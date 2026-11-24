"""Compare a query-free URL candidate and the shipped forest on unseen domain groups."""

import argparse
from collections import Counter
from functools import lru_cache
import json
from pathlib import Path
from time import perf_counter
import zipfile

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit

from backend import server
from backend.assessments import registrable, split_url
from backend.url_advisory import new_features
from training.train_reviewed_features import evaluate


ROOT = Path(__file__).resolve().parents[1]
OLD_FEATURES = joblib.load(ROOT / "models/url_features_v2.joblib")
group_for_host = lru_cache(maxsize=65536)(registrable)


def parts_and_host(url):
    try:
        parts, host, _ = split_url(url)
        return parts, host, group_for_host(host)
    except (ValueError, UnicodeError):
        return None


def original_file(path):
    with zipfile.ZipFile(path) as archive:
        entry = next(name for name in archive.namelist() if name.lower().endswith(".csv"))
        with archive.open(entry) as csv:
            return pd.read_csv(csv, usecols=["URL", "label", *OLD_FEATURES])


def run(phresh, phiusiil, output):
    original = original_file(phiusiil)
    old_groups = set()
    valid = []
    for url in original.URL:
        parsed = parts_and_host(url)
        valid.append(parsed is not None)
        if parsed:
            old_groups.add(parsed[2])
    reference = original.loc[valid, OLD_FEATURES].reset_index(drop=True)
    recomputed = pd.DataFrame([server.extract_features_dict(url) for url in original.loc[valid, "URL"]])[OLD_FEATURES]

    sources = pd.read_csv(phresh, usecols=["url", "source_label"]).dropna()
    rows, seen = [], set()
    for url, label in sources.itertuples(index=False, name=None):
        parsed = parts_and_host(url)
        if not parsed or parsed[2] in old_groups or label not in {"benign", "phish"}:
            continue
        parts, host, group = parsed
        normalized = (parts.scheme, host, parts.path.rstrip("/"), parts.query)
        if normalized in seen:
            continue
        seen.add(normalized)
        rows.append((url, parts, host, group, int(label == "phish")))
    y = np.array([label for *_, label in rows])
    domains = np.array([group for _, _, _, group, _ in rows])
    fit, test = next(GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42).split(rows, groups=domains))
    baseline = joblib.load(ROOT / "models/url_phishing_model_v2.joblib")
    baseline.n_jobs = 1
    baseline_rows = pd.DataFrame([server.extract_features_dict(rows[i][0]) for i in test])[OLD_FEATURES]
    replacement = pd.DataFrame([new_features(parts, host) for _, parts, host, _, _ in rows])
    model = HistGradientBoostingClassifier(max_iter=150, max_leaf_nodes=15, random_state=42, class_weight="balanced")
    model.fit(replacement.iloc[fit], y[fit])

    def measure(model, inputs, positive, size):
        started = perf_counter()
        scores = model.predict_proba(inputs)[:, list(model.classes_).index(positive)]
        metrics = evaluate(y[test], scores > 0.5, scores)
        return {**metrics, "inference_ms_per_url": 1000 * (perf_counter() - started) / len(test), "model_bytes": size}

    output.mkdir(parents=True, exist_ok=False)
    artifact = output / "url_context_candidate.joblib"
    joblib.dump(model, artifact, compress=3)
    report = {
        "original_rows": len(original),
        "original_label_counts": dict(Counter(int(value) for value in original.label)),
        "published_feature_agreement": (reference == recomputed).mean().to_dict(),
        "fit": dict(Counter(int(value) for value in y[fit])),
        "holdout": dict(Counter(int(value) for value in y[test])),
        "shared_fit_and_holdout_domains": len(set(domains[fit]) & set(domains[test])),
        "legacy": measure(baseline, baseline_rows, 0, (ROOT / "models/url_phishing_model_v2.joblib").stat().st_size),
        "candidate": measure(model, replacement.iloc[test], 1, artifact.stat().st_size),
    }
    (output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phresh", type=Path, help="PhreshPhish URL-only test export")
    parser.add_argument("phiusiil", type=Path, help="Original PhiUSIIL ZIP")
    parser.add_argument("output", type=Path, help="New candidate directory")
    args = parser.parse_args()
    print(json.dumps(run(args.phresh, args.phiusiil, args.output), indent=2))
