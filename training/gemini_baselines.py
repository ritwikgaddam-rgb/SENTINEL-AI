"""Replay frozen email research baselines with their original feature contracts.

The caller owns the study partitions. Each result lists the cohorts eligible
for comparison and contains NaN scores elsewhere to expose accidental reuse.
Only load locally produced checkpoint files.
"""

import json
from pathlib import Path
import re
from time import perf_counter

import joblib
import numpy as np
from scipy.special import expit

from training import context_study
from training import email_recall_study as study
from training.handover_study import encoder

HANDOVER = Path(".runtime/handover")
CONTEXT = Path(".runtime/context-study/published")
CHECKPOINTS = Path(".runtime/context-study/cutoff-replay")

CONTEXT_EVAL = {
    "cal",
    "tune",
    "guard",
    "mixed_holdout",
    "auth_templates",
    "transaction_templates",
    "paired_templates",
    "archive_2021",
    "prior_tune",
    "prior_dev",
    "prior_short",
    "prior_fresh",
    "prior_email_holdout",
}
HISTORY_EVAL = {
    "guard",
    "prior_tune",
    "prior_dev",
    "prior_short",
    "prior_fresh",
    "prior_email_holdout",
}

CONTEXT_NOTE = (
    "Frozen November 26 artifacts. Current context fit/stack were separate from these held-out rows. "
    "The saved calibrator already used current cal and the saved cutoff already used current tune and guard. "
    "Historic cohorts have already been inspected."
)
HISTORY_NOTE = (
    "Frozen November 25 artifacts. The old mixed-source fit overlaps the current mixed split, "
    "so current cal, tune and mixed_holdout are excluded. The old cutoff already used prior_tune and guard. "
    "Historic development and archived evaluation cohorts have already been inspected."
)


def _pack(indices, size, scores, probabilities, threshold, allowed, notes):
    def expand(values):
        result = np.full(size, np.nan)
        result[indices] = values
        return result

    return {
        "scores": expand(scores),
        "probabilities": expand(probabilities),
        "threshold": float(threshold),
        "allowed_sets": set(allowed),
        "notes": notes,
    }


def _selection(ix, allowed):
    active = sorted(key for key in allowed if key in ix and len(ix[key]))
    if not active:
        raise ValueError("No replay cohorts match the frozen baseline data contract.")
    return active, np.unique(np.concatenate([ix[key] for key in active]))


def _legacy_text(rows):
    return [study.model_text(row.body, row.subject) for row in rows]


def replay_baselines(
    rows,
    ix,
    y,
    *,
    resources=HANDOVER,
    context_fit=CONTEXT,
    embeddings=None,
    historical_only=False,
    untouched_sets=(),
):
    """Return local frozen Logistic Regression and single-view baselines.

    If supplied, embeddings maps 'mini' and 'bge' to row-aligned arrays with the
    historical full masked subject/body and 128-token mean/CLS settings.
    Set untouched_sets only after checking each extra cohort against fit data.
    """
    if len(rows) != len(y):
        raise ValueError("Expected one label for every input row.")
    output = {}
    if not historical_only:
        output.update(_context_replay(rows, ix, context_fit, set(untouched_sets)))
    output.update(_archive_replay(rows, ix, resources, embeddings, set(untouched_sets)))
    return output


def _context_replay(rows, ix, directory, untouched):
    allowed, ids = _selection(ix, CONTEXT_EVAL | untouched)
    selected = [rows[i] for i in ids]
    text = [s[:4500].encode("utf8", "replace").decode() for s in _legacy_text(selected)]
    features = [context_study.row_features(row) for row in selected]
    output = {}
    decisions = {}
    for name in (
        "full_word",
        "full_char",
        "full_structure",
        "curated_char",
        "full_blend",
    ):
        bundle = joblib.load(directory / f"{name}.joblib")
        if name == "full_blend":
            matrix = np.column_stack(
                [decisions[f"full_{key}"] for key in ("word", "char", "structure")]
            )
            scores = bundle.decision_function(matrix)
        else:
            vec, model = bundle
            matrix = vec.transform(features if name == "full_structure" else text)
            scores = model.decision_function(matrix)
        decisions[name] = scores
        calibration, cutoff = joblib.load(directory / f"{name}_cut.joblib")
        probability = calibration.predict_proba(scores[:, None])[:, 1]
        output[name] = _pack(
            ids, len(rows), scores, probability, cutoff, allowed, CONTEXT_NOTE
        )
    return output


def _archive_features(rows, columns):
    values = []
    link_present = []
    for row in rows:
        _, anchors, _ = study.link_items(row.body, "", row.links)
        links = [
            {"url": link["url"], "label": link["display_text"]} for link in anchors
        ]
        features = study.extract_privacy_safe_features(
            row.body, row.sender, links, row.subject, row.reply_to
        )
        values.append([features[key] for key in columns])
        link_present.append(bool(features["has_links"]))
    return np.asarray(values), np.asarray(link_present, dtype=bool)


def _archive_replay(rows, ix, resources, embeddings, untouched):
    allowed, ids = _selection(ix, HISTORY_EVAL | untouched)
    selected = [rows[i] for i in ids]
    directory = resources / "single-mail"
    manifest = json.loads((directory / "metrics.json").read_text())
    text = [s.encode("utf-8", "replace").decode() for s in _legacy_text(selected)]
    structure, has_link = _archive_features(selected, manifest["structure_columns"])
    decisions = {}
    output = {}

    def record(name, scores):
        decisions[name] = scores
        calibration = joblib.load(directory / f"{name}_calibration.joblib")
        probability = calibration.predict_proba(scores[:, None])[:, 1]
        cutoff = manifest["models"][name]["tune"]["threshold"]
        output[f"nov25_{name}"] = _pack(
            ids, len(rows), scores, probability, cutoff, allowed, HISTORY_NOTE
        )

    for name in ("word", "char", "structure", "mini", "bge"):
        if name == "structure":
            matrix = structure
        elif name in ("mini", "bge"):
            if embeddings is not None and name in embeddings:
                matrix = embeddings[name][ids]
            else:
                matrix, _ = encoder(
                    resources / name, text, "mean" if name == "mini" else "cls"
                )
        else:
            vectorizer = joblib.load(directory / f"{name}_vectorizer.joblib")
            matrix = vectorizer.transform(text)
        record(
            name, joblib.load(directory / f"{name}.joblib").decision_function(matrix)
        )

    features = np.column_stack(
        [
            expit(decisions[name])
            for name in ("word", "char", "structure", "mini", "bge")
        ]
    )
    interaction = np.column_stack([features, features * has_link[:, None], has_link])
    record(
        "ensemble",
        joblib.load(directory / "ensemble.joblib").decision_function(features),
    )
    record(
        "regime_interaction",
        joblib.load(directory / "regime_interaction.joblib").decision_function(
            interaction
        ),
    )
    regimes = np.empty(len(ids))
    for regime in (False, True):
        mask = has_link == regime
        if np.any(mask):
            regimes[mask] = joblib.load(
                directory / f"separate_{int(regime)}.joblib"
            ).decision_function(features[mask])
    record("separate_regimes", regimes)
    return output


def _compact_text(text):
    # Same masking convention as the saved two-block run.
    text = re.sub(
        r"((?:verification|security|one.time) code (?:is )?)numberplaceholder",
        r"\1hidden code",
        text,
        flags=re.I,
    )
    return (
        text.replace("numberplaceholder", "number")
        .replace("urlplaceholder", "link")
        .replace("addressplaceholder", "email address")
    )


def replay_torch_checkpoints(
    rows, ix, y, *, resources=HANDOVER, checkpoint_fit=CHECKPOINTS, untouched_sets=()
):
    """Run both saved MiniLM checkpoints, including original guard probabilities."""
    from tokenizers import Tokenizer
    import torch
    from torch import nn
    from transformers import AutoModel

    if len(rows) != len(y):
        raise ValueError("Expected one label for every input row.")
    torch.set_num_threads(4)
    directory = resources / "fine-final"
    base = resources / "mini-train"
    legacy = json.loads((directory / "metrics.json").read_text())
    tokenizer = Tokenizer.from_file(str(resources / "mini/tokenizer.json"))
    tokenizer.enable_padding()
    output = {}
    untouched = set(untouched_sets)
    for name, allowed_sets in (
        ("nov25_minilm_checkpoint", HISTORY_EVAL),
        ("nov26_two_block_minilm", CONTEXT_EVAL),
    ):
        allowed, ids = _selection(ix, allowed_sets | untouched)
        masked = [
            s.encode("utf-8", "replace").decode()
            for s in _legacy_text([rows[i] for i in ids])
        ]
        model = AutoModel.from_pretrained(base, local_files_only=True)
        model.eval()
        head = nn.Linear(model.config.hidden_size, 1)
        if name == "nov25_minilm_checkpoint":
            saved = torch.load(
                directory / "last_block_and_head.pt",
                weights_only=True,
                map_location="cpu",
            )
            model.encoder.layer[-1].load_state_dict(saved["last_block"])
            tokenizer.enable_truncation(max_length=128)
        else:
            saved = torch.load(
                checkpoint_fit / "two_block_and_head.pt",
                weights_only=True,
                map_location="cpu",
            )
            model.encoder.layer[-2:].load_state_dict(saved["upper"])
            masked = [_compact_text(text) for text in masked]
            tokenizer.enable_truncation(max_length=160)
        head.load_state_dict(saved["head"])
        start = perf_counter()
        batches = []
        with torch.inference_mode():
            for first in range(0, len(ids), 16):
                batch = tokenizer.encode_batch(masked[first : first + 16])
                inputs = torch.tensor([item.ids for item in batch])
                mask = torch.tensor([item.attention_mask for item in batch])
                hidden = model(input_ids=inputs, attention_mask=mask).last_hidden_state
                pooled = (hidden * mask.unsqueeze(-1)).sum(1) / mask.sum(
                    1, keepdim=True
                )
                batches.append(head(pooled).flatten().numpy())
        scores = np.concatenate(batches).astype(float)
        if name == "nov25_minilm_checkpoint":
            probability = expit(
                scores * legacy["calibration_slope"] + legacy["calibration_intercept"]
            )
            cutoff = legacy["models"]["tuned_minilm"]["tune"]["threshold"]
            notes = HISTORY_NOTE
        else:
            calibration, cutoff = joblib.load(
                checkpoint_fit / "two_block_minilm_cut.joblib"
            )
            probability = calibration.predict_proba(scores[:, None])[:, 1]
            notes = CONTEXT_NOTE
        result = _pack(ids, len(rows), scores, probability, cutoff, allowed, notes)
        result["inference_ms_per_message"] = (perf_counter() - start) * 1000 / len(ids)
        output[name] = result
    return output
