"""Local evaluation of the documented Gemini phishing classifiers."""

import argparse
from collections import Counter, defaultdict
from hashlib import sha256
import json
import os
from pathlib import Path
from zipfile import ZipFile

import joblib
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold

from training import context_study as context
from training import email_recall_study as study
from training.handover_study import encoder

DEFAULT_OUTPUT = Path(".runtime/gemini-study")
RESOURCES = Path(".runtime/handover")


def make_study(args):
    if os.environ.get("PYTHONHASHSEED") != "42":
        raise ValueError("Set PYTHONHASHSEED=42 for reproducible grouping")
    sets, _ = context.build(args)
    seen = {key for rows in sets.values() for row in rows for key in context.signatures(row)}

    def distinct(rows):
        kept = []
        for row in rows:
            keys = context.signatures(row)
            if keys and not keys & seen:
                seen.update(keys)
                kept.append(row)
        return kept

    (groups, _), _, _ = study.dataset(args)
    archived, group_ids = zip(*groups["validation"])
    validation_labels = [r.label for r in archived]
    folds = StratifiedGroupKFold(4, shuffle=True, random_state=71)
    spare = tuple(folds.split(archived, validation_labels, group_ids))[-1][1]
    sets["spare_tune"] = distinct(archived[i] for i in spare)

    # This is a new lockbox relative to the earlier recorded replay. Its
    # positive and negative archives have different collection methods.
    additions = study.corpus(args.resources / "fresh/phishing-2025", 1, Counter())
    with ZipFile(args.resources / "fresh/sms.zip") as archive:
        additions += [
            context.Mail(line[4:], 0, "UCI unscored ham")
            for line in archive.read("SMSSpamCollection").decode().splitlines()
            if line.startswith("ham\t")
        ]
    candidates = sorted(additions, key=lambda r: sha256(context.study.normalized_key(r).encode()).digest())
    sampled = distinct(candidates)
    sets["unscored_archive_sms"] = [
        r for label in (0, 1) for r in [x for x in sampled if x.label == label][:200]
    ]

    # Category limits count every matching benign validation sample. A fixed
    # hash supplies a disjoint reserve for calibration and threshold decisions.
    # Topic tags are deliberately approximate and may overlap.
    for key in ("tune", "spare_tune"):
        retained = []
        for r in sets[key]:
            names = set(context.slices(r, {"has_links": bool(r.links)}))
            if r.label == 0 and sha256(context.study.normalized_key(r).encode()).digest()[0] < 170:
                category = next(
                    (
                        k
                        for k in (
                            "authentication",
                            "transactional",
                            "security_advice",
                            "professional_or_school",
                            "personal",
                        )
                        if k in names
                    ),
                    None,
                )
                if category:
                    sets.setdefault("category_" + category, []).append(r)
                    continue
            retained.append(r)
        sets[key] = retained

    rows = []
    ix = {}
    for key, values in sets.items():
        ix[key] = np.arange(len(rows), len(rows) + len(values), dtype=int)
        rows.extend(values)
    ix["expanded_tune"] = np.r_[ix["tune"], ix["spare_tune"]]
    y = np.array([r.label for r in rows])

    groups = defaultdict(list)
    for i in ix["fit"]:
        r = rows[i]
        groups[r.source, r.label].append(i)
    rng = np.random.default_rng(42)
    limited = [
        i
        for key in sorted(groups)
        for i in rng.choice(groups[key], min(300, len(groups[key])), replace=False)
    ]
    fit = np.array(sorted([*limited, *ix["extra_fit"]]), dtype=int)
    return rows, ix, y, fit


def embed(args, rows, ix, fit):
    from training.gemini_features import two_view_texts

    used = np.unique(np.r_[fit, np.concatenate([v for k, v in ix.items() if k not in ("fit", "extra_fit")])])
    views = [two_view_texts(rows[i], include_middle=True) for i in used]
    full = [study.model_text(rows[i].body, rows[i].subject).encode("utf8", "replace").decode() for i in used]
    sources = [
        ("mini", "front", [t[0] for t in views], "mean"),
        ("mini", "back", [t[1] for t in views], "mean"),
        ("mini", "middle", [t[2] for t in views], "mean"),
        ("mini", "single", full, "mean"),
        ("bge", "front", [t[0] for t in views], "cls"),
        ("bge", "back", [t[1] for t in views], "cls"),
    ]
    cache = args.output / "embeddings"
    cache.mkdir(exist_ok=True)
    arrays = {}
    metadata = {}
    for model, view, strings, pool in sources:
        path = cache / (model + "_" + view + ".joblib")
        directory = args.resources / model
        fingerprints = [
            sha256((directory / f).read_bytes()).hexdigest() for f in ("model.onnx", "tokenizer.json")
        ]
        digest = sha256()
        digest.update(json.dumps([used.tolist(), fingerprints, pool, len(rows)]).encode())
        for entry in strings:
            digest.update(sha256(entry.encode("utf8", "replace")).digest())
        key = digest.hexdigest()
        saved = joblib.load(path) if path.exists() else {}
        if saved.get("key") != key:
            vectors, profile = encoder(
                directory, [t.encode("utf8", "replace").decode() for t in strings], pool
            )
            saved = {"key": key, "embeddings": vectors.astype(np.float32), "profile": profile}
            joblib.dump(saved, path)
        matrix = np.zeros((len(rows), saved["embeddings"].shape[1]), dtype=np.float32)
        matrix[used] = saved["embeddings"]
        arrays[model, view] = matrix
        metadata[model + "_" + view] = saved["profile"] | {
            "encoded_messages": len(used),
            "sha256": fingerprints,
        }
        print("Encoded", model, view, len(used), flush=True)
    return arrays, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--resources", type=Path, default=RESOURCES)
    parser.add_argument("--source-dir", type=Path, default=Path(".runtime/email-model-study/sources"))
    parser.add_argument("--ham-dir", type=Path, default=Path(".runtime/email-sources"))
    parser.add_argument("--legacy-csv", type=Path, required=True)
    parser.add_argument("--public-seeds", action="store_true")
    parser.add_argument("--embed-only", action="store_true")
    parser.add_argument("--torch-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    os.environ.pop("SENTINELAI_LANGUAGETOOL_PORT", None)
    args.output.mkdir(parents=True, exist_ok=True)
    rows, ix, y, fit = make_study(args)
    print("Rows", {k: len(v) for k, v in ix.items()}, "research fit", len(fit), flush=True)
    if args.torch_only:
        from training.gemini_baselines import replay_torch_checkpoints

        joblib.dump(
            replay_torch_checkpoints(rows, ix, y, resources=args.resources),
            args.output / "checkpoints.joblib",
        )
        return
    vectors, encoder_profiles = embed(args, rows, ix, fit)
    if not args.embed_only:
        from training.gemini_candidates import run_candidates

        run_candidates(args, rows, ix, y, fit, vectors, encoder_profiles)


if __name__ == "__main__":
    main()
