"""Offline research only. Run from the repository root with python -m training.handover_study."""
import argparse
from collections import Counter
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path
from time import perf_counter
from zipfile import ZipFile

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

from training import email_recall_study as study
from training.train_reviewed_features import evaluate


def fingerprints(row):
    words = study.normalized_key(row).split()
    # Include interior shingles as well as both edges. A shared long boilerplate
    # passage can exclude otherwise distinct mail, a conservative sampling bias.
    yield " ".join(words)
    for i in range(len(words) - 11):
        phrase = " ".join(words[i:i + 12])
        if i == 0 or i == len(words) - 12 or hash(phrase) % 11 == 0:
            yield phrase


def fresh_rows(directory, prior, parquet=None):
    seen = {hash(s) for row in prior for s in fingerprints(row)}
    pos = study.corpus(directory / "phishing-2025", 1, Counter())
    neg = study.corpus(directory / "20021010_easy_ham.tar.bz2", 0, Counter())
    with ZipFile(directory / "sms.zip") as archive:
        lines = archive.read("SMSSpamCollection").decode().splitlines()
    sms = [study.Mail(line[4:], 0, "UCI ham SMS") for line in lines if line.startswith("ham\t")]
    rows = []
    derived = []
    if parquet:
        import pyarrow.parquet as pq
        table = pq.read_table(parquet, columns=["subject", "text", "sender"],
                              filters=[("dataset_name", "=", "TREC-07"), ("label", "=", 0)])
        for item in table.to_pylist():
            if item["text"]:
                derived.append(study.Mail(item["text"][:20000], 0, "TREC-07 derived label 0",
                                          (item["subject"] or "")[:500], (item["sender"] or "")[:500]))
    for cohort in (pos, neg, sms, derived):
        kept = 0
        for row in sorted(cohort, key=lambda r: sha256(r.body.encode()).digest()):
            keys = {hash(s) for s in fingerprints(row)}
            if not keys.isdisjoint(seen):
                continue
            rows.append(row)
            seen.update(keys)
            kept += 1
            if kept == 140:
                break
    return rows


def encoder(directory, texts, pooling):
    import onnxruntime as ort
    from tokenizers import Tokenizer

    options = ort.SessionOptions()
    options.intra_op_num_threads = 4
    options.inter_op_num_threads = 1
    ort.disable_telemetry_events()
    t = perf_counter()
    session = ort.InferenceSession(str(directory / "model.onnx"), options, providers=["CPUExecutionProvider"])
    load_ms = (perf_counter() - t) * 1000
    tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
    tokenizer.enable_truncation(max_length=128)
    tokenizer.enable_padding()
    t = perf_counter()
    embs = []
    # Dynamic int8 activation scales change with batch composition. Use the
    # same one-message inputs during fitting and inference as an installed scanner.
    for text in texts:
        batch = [tokenizer.encode(text)]
        ids = np.array([x.ids for x in batch], dtype=np.int64)
        mask = np.array([x.attention_mask for x in batch], dtype=np.int64)
        available = {"input_ids": ids, "attention_mask": mask, "token_type_ids": np.zeros_like(ids)}
        hidden = session.run(None, {i.name: available[i.name] for i in session.get_inputs()})[0]
        values = (hidden * mask[:, :, None]).sum(axis=1) / mask.sum(axis=1)[:, None] if pooling == "mean" else hidden[:, 0]
        embs.extend(values / np.maximum(np.linalg.norm(values, axis=1, keepdims=True), 1e-12))
    return np.array(embs), {"bytes": (directory / "model.onnx").stat().st_size,
                            "load_ms": load_ms, "batch_ms_per_mail": (perf_counter() - t) * 1000 / len(texts)}


def measure(y, prob, threshold):
    return evaluate(y, prob > threshold, prob) | {"threshold": float(threshold), "abstention_rate": 0.0}


def partitions(args):
    (groups, _), guards, _ = study.dataset(args)
    rng = np.random.default_rng(42)
    rows_fit = [x for x, _ in groups["fit"]]
    # Bound CPU cost before any evaluation. Retain both labels in each available source.
    fit = []
    for source, label in sorted({(r.source, r.label) for r in rows_fit}):
        pool = [r for r in rows_fit if (r.source, r.label) == (source, label)]
        fit.extend(pool[i] for i in rng.choice(len(pool), min(300, len(pool)), replace=False))
    val, vg = zip(*groups["validation"])
    folds = [test for _, test in StratifiedGroupKFold(4, shuffle=True, random_state=71).split(val, [r.label for r in val], vg)]
    sets = {"fit": fit, **{k: [val[i] for i in ids] for k, ids in zip(("stack", "cal", "tune", "spare"), folds)},
            "guard": guards, "dev": [r for r, _ in groups["manual"]], "short": [r for r, _ in groups["real"]]}
    prior = [r for group in groups.values() for r, _ in group] + guards
    if args.legacy_csv:
        prior.extend(study.Mail(r["Email Text"], 0, "") for r in study.csv_mail(args.legacy_csv) if r["Email Text"])
    # Keep the known development benchmark intact. Remove shared interior
    # shingles from lower-priority partitions before fitting or selecting cuts.
    seen = set()
    removed = {}
    for key in ("dev", "short", "guard", "tune", "cal", "stack", "fit"):
        fingerprints_here = set()
        keep = []
        for r in sets[key]:
            keys = {hash(s) for s in fingerprints(r)}
            if key in ("dev", "short", "guard") or keys.isdisjoint(seen):
                keep.append(r)
                fingerprints_here.update(keys)
        removed[key] = len(sets[key]) - len(keep)
        sets[key] = keep
        seen.update(fingerprints_here)
    fresh = fresh_rows(args.resources / "fresh", prior, args.parquet)
    sets["fresh"] = [r for r in fresh if r.source != "TREC-07 derived label 0"]
    sets["email_holdout"] = [r for r in fresh if r.source != "UCI ham SMS"]
    sets.pop("spare")
    return sets, removed


def run(args):
    os.umask(0o077)
    if os.environ.get("PYTHONHASHSEED") != "42":
        raise ValueError("Set PYTHONHASHSEED=42 before starting this reproducible study.")
    args.output.mkdir(exist_ok=False)
    sets, removed = partitions(args)
    rows, idx = [], {}
    for k, sub in sets.items():
        idx[k] = np.arange(len(rows), len(rows) + len(sub))
        rows.extend(sub)
    text = [study.model_text(r.body, r.subject).encode("utf-8", "replace").decode() for r in rows]
    y = np.array([r.label for r in rows])
    # Save private local inputs for identical JS/Python replays, outside Git.
    with (args.output / "replay.jsonl").open("w") as f:
        for k in ("tune", "dev", "short", "fresh", "email_holdout"):
            for r in sets[k]:
                f.write(json.dumps({"set": k, **asdict(r)}) + "\n")
    print("Cohorts", {k: len(v) for k, v in sets.items()}, flush=True)
    if args.fine_tune:
        from training.tune_minilm import compare
        compare(args, text, idx, y)
        return
    raw_struct = []
    for row in rows:
        _, links, _ = study.link_items(row.body, "", row.links)
        links = [{"url": link["url"], "label": link["display_text"]} for link in links]
        raw_struct.append(study.extract_privacy_safe_features(row.body, row.sender, links, row.subject, row.reply_to))
    names = sorted(set(raw_struct[0]) - {"is_esp_safelisted"})
    structural = np.array([[f[k] for k in names] for f in raw_struct])
    has_link = structural[:, names.index("has_links")].astype(bool)
    fit_idx, stack, cal, tune = (idx[k] for k in ("fit", "stack", "cal", "tune"))
    candidates, stats, pbase = {}, {}, {}
    for name in ("word", "char", "structure", "mini", "bge"):
        if name in ("mini", "bge"):
            X, stats[name] = encoder(args.resources / name, text, "mean" if name == "mini" else "cls")
        elif name == "structure":
            X = structural
        else:
            vectorizer = study.word_features() if name == "word" else TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=35000, sublinear_tf=True)
            vectorizer.fit([text[i] for i in fit_idx])
            X = vectorizer.transform(text)
            joblib.dump(vectorizer, args.output / (name + "_vectorizer.joblib"), compress=3)
        model = make_pipeline(StandardScaler(with_mean=False), LogisticRegression(C=.1, max_iter=500)) if name == "structure" else LogisticRegression(C=2, max_iter=500)
        model.fit(X[fit_idx], y[fit_idx])
        candidates[name] = model.decision_function(X)
        pbase[name] = model.predict_proba(X)[:, 1]
        joblib.dump(model, args.output / (name + ".joblib"), compress=3)
        print("Fitted", name, flush=True)
    features = np.column_stack(list(pbase.values()))
    # Every row used to train the stack is unseen by ALL base classifiers.
    # Calibration and threshold selection each get a separate template-group fold.
    interaction = np.column_stack([features, features * has_link[:, None], has_link])
    for name, matrix in (("ensemble", features), ("regime_interaction", interaction)):
        model = LogisticRegression(C=1).fit(matrix[stack], y[stack])
        candidates[name] = model.decision_function(matrix)
        joblib.dump(model, args.output / (name + ".joblib"))
    split_scores = np.empty(len(rows))
    for regime in (False, True):
        mask = has_link[stack] == regime
        model = LogisticRegression(C=1).fit(features[stack][mask], y[stack][mask])
        split_scores[has_link == regime] = model.decision_function(features[has_link == regime])
        joblib.dump(model, args.output / f"separate_{int(regime)}.joblib")
    candidates["separate_regimes"] = split_scores
    # Run the teammate's SVD + lexical stack under the repaired group protocol.
    # It is already a meta-estimator, so keep it outside the encoder ensemble.
    legacy_stack = study.CalibratedStackingClassifier(dense_text_pipeline=study.make_dense_semantic_pipeline(50))
    legacy_stack.fit_and_tune_oof(sets["fit"], y[fit_idx], sets["stack"], y[stack], sets["guard"], n_splits=3)
    stack_p = np.clip(legacy_stack.predict_proba(rows), 1e-12, 1 - 1e-12)
    candidates["lexical_svd_stack"] = np.log(stack_p / (1 - stack_p))
    joblib.dump(legacy_stack, args.output / "lexical_svd_stack.joblib", compress=3)
    report = {"near_duplicate_exclusions": removed, "encoder": stats, "structure_columns": names, "sources": {k: dict(Counter(r.source for r in v)) for k, v in sets.items()}, "models": {}}
    locked = {}
    for name, scores in candidates.items():
        calibrator = LogisticRegression(C=10).fit(scores[cal, None], y[cal])
        p = calibrator.predict_proba(scores[:, None])[:, 1]
        th = study.choose_oof_threshold(y[tune], p[tune], p[idx["guard"]], .025)
        locked[name] = (p, th)
        joblib.dump(calibrator, args.output / (name + "_calibration.joblib"))
    report["selected"] = max(locked, key=lambda k: measure(y[tune], locked[k][0][tune], locked[k][1])["recall"])
    for name, (p, threshold) in locked.items():
        report["models"][name] = {k: measure(y[idx[k]], p[idx[k]], threshold) for k in ("tune", "dev", "short", "fresh", "email_holdout")}
        for key, mask in (("linkless", ~has_link), ("linked", has_link)):
            ids = idx["dev"][mask[idx["dev"]]]
            report["models"][name][key] = measure(y[ids], p[ids], threshold)
    report["sha256"] = {str(f.relative_to(args.resources)): sha256(f.read_bytes()).hexdigest() for sub in ("mini", "bge", "fresh") for f in (args.resources / sub).iterdir()}
    (args.output / "metrics.json").write_text(json.dumps(report, indent=2, default=float))
    print("Locked candidate", report["selected"], flush=True)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("resources", type=Path)
    cli.add_argument("output", type=Path)
    cli.add_argument("--source-dir", type=Path, default=Path(".runtime/email-model-study/sources"))
    cli.add_argument("--ham-dir", type=Path, default=Path(".runtime/email-sources"))
    cli.add_argument("--legacy-csv", type=Path)
    cli.add_argument("--parquet", type=Path, help="Optional local TREC-07 derived ham stress test")
    cli.add_argument("--fine-tune", action="store_true", help="Only run the bounded MiniLM follow-up")
    cli.add_argument("--public-seeds", action="store_true")
    run(cli.parse_args())
