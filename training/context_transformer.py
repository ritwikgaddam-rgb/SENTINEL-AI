"""Offline diagnostic of the previous MiniLM cutoff and a bounded fine-tuning trial."""

import json
from pathlib import Path
import re
import resource
from time import perf_counter

import numpy as np
from scipy.special import expit
from tokenizers import Tokenizer
import torch
from torch import nn
from transformers import AutoModel

from training import email_recall_study as study
from training.context_study import fit_cut_record, stats


def compare(args, rows, ix, y, capped, text, record, report):
    resources = Path(".runtime/handover")
    previous = resources / "fine-final"
    base = resources / "mini-train"
    original = json.loads((previous / "metrics.json").read_text())
    tokenizer = Tokenizer.from_file(str(resources / "mini/tokenizer.json"))
    torch.set_num_threads(4)
    torch.manual_seed(42)
    encoder = AutoModel.from_pretrained(base, local_files_only=True)
    head = nn.Linear(encoder.config.hidden_size, 1)
    saved = torch.load(previous / "last_block_and_head.pt", weights_only=True, map_location="cpu")
    encoder.encoder.layer[-1].load_state_dict(saved["last_block"])
    head.load_state_dict(saved["head"])
    legacy = [study.model_text(r.body, r.subject).encode("utf8", "replace").decode() for r in rows]
    indices = np.concatenate([v for k, v in ix.items() if k not in ("fit", "extra_fit", "stack")])

    def forward(batch, inputs):
        tokens = tokenizer.encode_batch([inputs[i] for i in batch])
        ids = torch.tensor([t.ids for t in tokens])
        mask = torch.tensor([t.attention_mask for t in tokens])
        hidden = encoder(input_ids=ids, attention_mask=mask).last_hidden_state
        return head((hidden * mask.unsqueeze(-1)).sum(1) / mask.sum(1, keepdim=True)).flatten()

    def score(inputs):
        encoder.eval()
        values = np.zeros(len(rows))
        with torch.inference_mode():
            for start in range(0, len(indices), 16):
                batch = indices[start : start + 16]
                values[batch] = forward(batch, inputs).numpy()
        return values

    tokenizer.enable_truncation(max_length=128)
    tokenizer.enable_padding()
    baseline = score(legacy)
    p = expit(baseline * original["calibration_slope"] + original["calibration_intercept"])
    old = ix["prior_tune"]
    guard = ix["guard"]
    original_cutoff = original["models"]["tuned_minilm"]["tune"]["threshold"]
    corrected_cutoff = study.choose_oof_threshold(y[old], p[old], p[guard], 0.025)
    guard_max = float(max(p[guard]))
    audit = report["semantic_audit"] = {
        "old_guard_max": guard_max,
        "old_tune_phish_max": float(max(p[old][y[old] == 1])),
        "replayed_old_threshold": original_cutoff,
        "corrected_old_validation_threshold": corrected_cutoff,
        "old_tune_at_guard_boundary": stats(y[old], p[old] > guard_max),
        "old_tune_raw_half": stats(y[old], p[old] > 0.5),
    }
    record("previous_minilm_original_cut", p > original_cutoff, p)
    record("previous_minilm_corrected_cut", p > corrected_cutoff, p)
    report["thresholds"].update(previous_minilm_original_cut=original_cutoff,
                                previous_minilm_corrected_cut=corrected_cutoff)
    fit_cut_record("previous_minilm_new_validation", baseline, ix, y, args.output, report, record)

    # Replace long split WordPiece placeholders with short ordinary words.
    # Preserve the role of numbers in code notifications, never their values.
    def context_text(s):
        s = re.sub(
            r"((?:verification|security|one.time) code (?:is )?)numberplaceholder",
            r"\1hidden code",
            s,
            flags=re.I,
        )
        return (
            s.replace("numberplaceholder", "number")
            .replace("urlplaceholder", "link")
            .replace("addressplaceholder", "email address")
        )

    compact = [context_text(s) for s in legacy]
    tokenizer.no_truncation()
    tokenizer.no_padding()
    for key, seq in (("original", legacy), ("compact", compact)):
        sizes = [len(tokenizer.encode(seq[i]).ids) for i in old]
        audit[key + "_tune_over_128"] = sum(n > 128 for n in sizes)
        audit[key + "_median_wordpieces"] = float(np.median(sizes))
    tokenizer.enable_truncation(max_length=128)
    tokenizer.enable_padding()
    fit_cut_record("previous_minilm_compact_mask", score(compact), ix, y, args.output, report, record)

    torch.manual_seed(42)
    encoder = AutoModel.from_pretrained(base, local_files_only=True)
    encoder.requires_grad_(False)
    upper = encoder.encoder.layer[-2:]
    upper.requires_grad_(True)
    head = nn.Linear(encoder.config.hidden_size, 1)
    tokenizer.enable_truncation(max_length=160)
    opt = torch.optim.AdamW(
        [{"params": upper.parameters(), "lr": 1e-5}, {"params": head.parameters(), "lr": 3e-4}]
    )
    rng = np.random.default_rng(42)
    fit = rng.choice(capped, min(1500, len(capped)), replace=False)
    pos_weight = torch.tensor(float(np.sum(y[fit] == 0) / np.sum(y[fit] == 1)))
    start = perf_counter()
    for _ in range(2):
        encoder.train()
        order = rng.permutation(fit)
        for i in range(0, len(order), 16):
            b = order[i : i + 16]
            opt.zero_grad()
            loss = nn.functional.binary_cross_entropy_with_logits(
                forward(b, compact), torch.tensor(y[b], dtype=torch.float32), pos_weight=pos_weight
            )
            loss.backward()
            opt.step()
    elapsed = perf_counter() - start
    start = perf_counter()
    scores = score(compact)
    latency = 1000 * (perf_counter() - start) / len(indices)
    fit_cut_record("two_block_minilm", scores, ix, y, args.output, report, record)
    artifact = args.output / "two_block_and_head.pt"
    torch.save({"upper": upper.state_dict(), "head": head.state_dict()}, artifact)
    audit.update(
        fit_rows=len(fit),
        positive_weight=float(pos_weight),
        epochs=2,
        fit_seconds=elapsed,
        batch_ms_per_mail=latency,
        peak_process_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        base_bytes=(base / "model.safetensors").stat().st_size,
        delta_bytes=artifact.stat().st_size,
    )
