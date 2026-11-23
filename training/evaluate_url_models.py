"""Train the v3 URL model and evaluate it against the saved v2 baseline."""

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import brier_score_loss, confusion_matrix, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

from url_features import url_feature_values
from url_reliability import LEGITIMATE_AT_MOST, PHISHING_AT_LEAST, PHISHING_LABEL, url_model_values


ROOT = Path(__file__).resolve().parents[1]


def domain_group(url):
    # Final two hostname labels overgroup public suffixes such as co.uk. This
    # errs toward excluding extra rows when preventing leakage across sources.
    hostname = (urlsplit(url).hostname or "").rstrip(".")
    return ".".join(hostname.split(".")[-2:])


def read_labelled(path, url_field, label_field, label_map):
    source = pd.read_csv(path, usecols=[url_field, label_field], dtype=str, keep_default_na=False)
    source.columns = source.columns.map({url_field: "url", label_field: "label"})
    source["label"] = source.label.map(label_map)
    source = source[source.label.notna()].copy()
    source["url"] = source.url.str.strip().str.replace(r"(?i)^https?://", lambda match: match[0].lower(), regex=True)
    usable = source.url.str.startswith(("http://", "https://"))
    usable &= ~source.url.str.contains(r"[\s\\]", regex=True) & source.url.str.len().between(1, 2083)
    source = source[usable].assign(canonical=source.url.str.removesuffix("/"))
    source = source.drop_duplicates("canonical", keep=False)

    records = []
    for row in source.itertuples(index=False):
        try:
            parsed = urlsplit(row.url)
            parsed.port  # Reject invalid ports.
            if parsed.hostname:
                records.append((row.url, int(row.label), domain_group(row.url)))
        except ValueError:
            continue
    return pd.DataFrame(records, columns=["url", "label", "group"])


def input_features(frame, extractor, columns):
    return pd.DataFrame([extractor(url) for url in frame.url], columns=columns)


def group_split(frame, seed):
    split = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed)
    train, test = next(split.split(frame, groups=frame.group))
    return frame.iloc[train], frame.iloc[test]


def evaluate(labels, scores, selective=False):
    actual = labels.to_numpy() == PHISHING_LABEL
    predicted = scores >= PHISHING_AT_LEAST if selective else scores >= 0.5
    covered = (predicted | (scores <= LEGITIMATE_AT_MOST)) if selective else np.ones_like(predicted)
    tn, fp, fn, tp = map(int, confusion_matrix(actual[covered], predicted[covered], labels=[False, True]).ravel())
    return {
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "abstained_legitimate": int(np.sum(~actual & ~covered)),
        "abstained_phishing": int(np.sum(actual & ~covered)),
        "coverage": float(covered.mean()),
        "accuracy_on_verdicts": (tn + tp) / max(tn + fp + fn + tp, 1),
        "precision": tp / max(tp + fp, 1),
        "recall_on_verdicts": tp / max(tp + fn, 1),
        "f1_on_verdicts": 2 * tp / max(2 * tp + fp + fn, 1),
        "false_positive_rate_on_verdicts": fp / max(tn + fp, 1),
        "false_negative_rate_on_verdicts": fn / max(tp + fn, 1),
        "false_alarm_rate_all_legitimate": fp / int(np.sum(~actual)),
        "detection_rate_all_phishing": tp / int(np.sum(actual)),
        "false_omission_rate": fn / max(tn + fn, 1),
        "brier_score_all_raw_scores": brier_score_loss(actual, scores),
        "auc_all_raw_scores": roc_auc_score(actual, scores),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phiusiil", type=Path, required=True)
    parser.add_argument("--phreshphish", type=Path, required=True)
    parser.add_argument("--legitphish", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New model output file")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Choose a new output path to preserve existing model artifacts.")

    original_domains = set()
    for url in pd.read_csv(args.phiusiil, usecols=["URL"]).URL:
        try:
            original_domains.add(domain_group(url))
        except ValueError:
            continue
    phresh = read_labelled(args.phreshphish, "url", "source_label", {"benign": 1, "phish": 0, "phishing": 0})
    phresh = phresh[~phresh.group.isin(original_domains)].reset_index(drop=True)
    train, held_out = group_split(phresh, seed=42)
    validation, test = group_split(held_out, seed=43)
    legit = read_labelled(args.legitphish, "URL", "ClassLabel", {"1": 1, "0": 0})
    legit = legit[~legit.group.isin(original_domains) & ~legit.group.isin(phresh.group)]

    columns = joblib.load(ROOT / "models/url_features_v2.joblib")
    v2 = joblib.load(ROOT / "models/url_phishing_model_v2.joblib")
    v2.n_jobs = 1
    v3 = HistGradientBoostingClassifier(max_iter=150, max_leaf_nodes=15, class_weight="balanced", random_state=42)
    v3.fit(input_features(train, url_model_values, columns), train.label)
    assert list(v2.classes_) == list(v3.classes_) == [0, 1]

    results = {"training": {"rows": len(train), "groups": train.group.nunique()}}
    for name, frame in (("validation", validation), ("test", test), ("external", legit)):
        scores_v2 = v2.predict_proba(input_features(frame, url_feature_values, columns))[:, 0]
        scores_v3 = v3.predict_proba(input_features(frame, url_model_values, columns))[:, 0]
        results[name] = {
            "rows": len(frame),
            "groups": frame.group.nunique(),
            "labelled_benign_with_path": sum(
                urlsplit(url).path not in ("", "/") for url in frame.loc[frame.label != PHISHING_LABEL, "url"]
            ),
            "labelled_benign_with_query": sum(
                bool(urlsplit(url).query) for url in frame.loc[frame.label != PHISHING_LABEL, "url"]
            ),
            "v2": evaluate(frame.label, scores_v2),
            "v3_class_at_0_5": evaluate(frame.label, scores_v3),
            "v3_production": evaluate(frame.label, scores_v3, selective=True),
        }

    print(json.dumps(results, indent=2))
    joblib.dump(v3, args.output, compress=3)


if __name__ == "__main__":
    main()
