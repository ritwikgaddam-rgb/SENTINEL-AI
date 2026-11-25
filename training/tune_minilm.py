"""Single offline CPU experiment. Called by handover_study with the same partitions."""
import json
import resource
from hashlib import sha256
from time import perf_counter

import numpy as np
from sklearn.linear_model import LogisticRegression
from tokenizers import Tokenizer
import torch
from torch import nn
from transformers import AutoModel

from training.email_recall_study import choose_oof_threshold
from training.handover_study import measure


def compare(args, texts, idx, y):
    torch.manual_seed(42)
    torch.set_num_threads(4)
    path = args.resources / "mini-train"
    encoder = AutoModel.from_pretrained(path, local_files_only=True)
    encoder.requires_grad_(False)
    encoder.encoder.layer[-1].requires_grad_(True)
    head = nn.Linear(encoder.config.hidden_size, 1)
    tokenizer = Tokenizer.from_file(str(args.resources / "mini/tokenizer.json"))
    tokenizer.enable_truncation(max_length=128)
    tokenizer.enable_padding()

    def predict(indices):
        batch = tokenizer.encode_batch([texts[i] for i in indices])
        ids = torch.tensor([t.ids for t in batch])
        mask = torch.tensor([t.attention_mask for t in batch])
        hidden = encoder(input_ids=ids, attention_mask=mask).last_hidden_state
        pooled = (hidden * mask.unsqueeze(-1)).sum(1) / mask.sum(1, keepdim=True)
        return head(pooled).flatten()

    opt = torch.optim.AdamW([{"params": encoder.encoder.layer[-1].parameters(), "lr": 2e-5},
                             {"params": head.parameters(), "lr": .001}])
    encoder.train()
    start = perf_counter()
    for batch in np.array_split(np.random.default_rng(42).permutation(idx["fit"]), (len(idx["fit"]) + 15) // 16):
        opt.zero_grad()
        nn.functional.binary_cross_entropy_with_logits(predict(batch), torch.tensor(y[batch], dtype=torch.float32)).backward()
        opt.step()
    fit_seconds = perf_counter() - start
    encoder.eval()
    values = {}
    start = perf_counter()
    with torch.inference_mode():
        for key in ("cal", "tune", "guard", "dev", "short", "fresh", "email_holdout"):
            ids = idx[key]
            values[key] = np.concatenate([predict(ids[i:i + 16]).numpy() for i in range(0, len(ids), 16)])
    latency = 1000 * (perf_counter() - start) / sum(len(v) for v in values.values())
    calibration = LogisticRegression(C=10).fit(values["cal"][:, None], y[idx["cal"]])
    p = {k: calibration.predict_proba(s[:, None])[:, 1] for k, s in values.items()}
    threshold = choose_oof_threshold(y[idx["tune"]], p["tune"], p["guard"], .025)
    artifact = args.output / "last_block_and_head.pt"
    torch.save({"last_block": encoder.encoder.layer[-1].state_dict(), "head": head.state_dict()}, artifact)
    report = {"models": {"tuned_minilm": {k: measure(y[idx[k]], p[k], threshold)
                                           for k in ("tune", "dev", "short", "fresh", "email_holdout")}},
              "base_sha256": sha256((path / "model.safetensors").read_bytes()).hexdigest(),
              "base_bytes": (path / "model.safetensors").stat().st_size,
              "delta_bytes": artifact.stat().st_size, "epoch_seconds": fit_seconds,
              "batch_ms_per_mail": latency, "process_peak_rss_native_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
              "calibration_slope": calibration.coef_.item(), "calibration_intercept": calibration.intercept_.item()}
    (args.output / "metrics.json").write_text(json.dumps(report, indent=2))
