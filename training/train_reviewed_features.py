"""Train a versioned, offline candidate from approved numeric or masked email samples."""

import argparse
from collections import Counter
import json
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, brier_score_loss, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import MaxAbsScaler


LABELS = {"legitimate": 0, "phishing": 1}


def read_features(path, kind, approved=False):
    document = json.loads(path.read_text())
    rows = document["samples"] if isinstance(document, dict) else document
    result = []
    for row in rows:
        if row["kind"] != kind:
            continue
        if approved and (row.get("version") != "features-v1" or row.get("status") != "approved"):
            raise ValueError("Use an approved feature export from SentinelAI.")
        if not approved and (not isinstance(row.get("group"), str) or not row["group"]):
            raise ValueError("Historical and independent evaluations require source/campaign groups.")
        features = row["features"]
        if not isinstance(features, dict) or not features or not all(
            isinstance(key, str) and type(value) is int and 0 <= value <= 100000 for key, value in features.items()
        ):
            raise ValueError("Feature rows require bounded non-negative integers.")
        result.append((features, LABELS[row["label"]], row.get("group", "")))
    return result


def read_masked_email(path, approved=False):
    from backend.threats import masked_terms, TEXT_VERSION, TRAINING_TERMS

    document = json.loads(path.read_text())
    rows = document["samples"] if isinstance(document, dict) else document
    result = []
    for row in rows:
        if row["kind"] != "email":
            continue
        body, subject = row["body"], row.get("subject", "")
        if not isinstance(body, str) or not isinstance(subject, str):
            raise ValueError("Email samples require text bodies and subjects.")
        group = row.get("group", "")
        if approved:
            if row.get("version") != TEXT_VERSION or row.get("status") != "approved":
                raise ValueError("Use the approved masked-text export from SentinelAI.")
            tokens = (subject + " " + body).split()
            if len(tokens) > 115 or not set(tokens) <= TRAINING_TERMS:
                raise ValueError("The export contains terms outside the masked-text feature set.")
        else:
            if not isinstance(group, str) or not group:
                raise ValueError("Historical and independent evaluations require source/campaign groups.")
            tokens = masked_terms(subject).split()[:15] + masked_terms(body).split()[:100]
        if len(set(tokens)) >= 3:
            result.append((" ".join(tokens), LABELS[row["label"]], group))
    return result


def deduplicate(rows, signatures=None):
    seen = {} if signatures is None else dict(signatures)
    distinct = []
    for features, label, group in rows:
        fingerprint = features if isinstance(features, str) else tuple(sorted(features.items()))
        if fingerprint in seen:
            if seen[fingerprint] != label:
                raise ValueError("Conflicting labels for the same feature vector. Review the source labels first.")
            continue
        seen[fingerprint] = label
        distinct.append((features, label, group))
    return distinct, seen


def evaluate(y, predictions, probabilities=None):
    tn, fp, fn, tp = (int(count) for count in confusion_matrix(y, predictions, labels=[0, 1]).ravel())
    precision, recall, f1, _ = precision_recall_fscore_support(y, predictions, average="binary", zero_division=0)
    metrics = {"accuracy": accuracy_score(y, predictions), "precision": precision, "recall": recall, "f1": f1,
               "fpr": fp / (tn + fp), "fnr": fn / (fn + tp), "confusion": [[tn, fp], [fn, tp]],
               "brier": None, "ece_10_bins": None}
    if probabilities is not None:
        observed, scores = np.asarray(y), np.asarray(probabilities)
        buckets = np.minimum((scores * 10).astype(int), 9)
        metrics["brier"] = brier_score_loss(observed, scores)
        metrics["ece_10_bins"] = sum(
            float(mask.mean() * abs(scores[mask].mean() - observed[mask].mean()))
            for bucket in range(10) if (mask := buckets == bucket).any()
        )
    return metrics


def train(kind, training, holdout, output, text=False):
    fit, signatures = deduplicate(training)
    groups = {group for _, _, group in training if group}
    if groups & {group for _, _, group in holdout}:
        raise ValueError("Independent holdout groups cannot occur in training.")
    test, _ = deduplicate(holdout, signatures)
    if set(label for _, label, _ in fit) != {0, 1} or set(label for _, label, _ in test) != {0, 1}:
        raise ValueError("Need both labels in training and independent holdout after overlap checks.")
    classifier = LogisticRegression(random_state=42, max_iter=1000, class_weight="balanced")
    if text:
        from backend.threats import TEXT_VERSION

        if kind != "email":
            raise ValueError("Masked text training is available for email.")
        version = TEXT_VERSION
        model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2)), classifier)
    else:
        version = "features-v1"
        columns = set(fit[0][0])
        if any(set(features) != columns for features, _, _ in fit + test):
            raise ValueError("Use the same versioned feature schema in both partitions.")
        model = make_pipeline(DictVectorizer(), MaxAbsScaler(), classifier)
    output.mkdir(parents=True, exist_ok=False)
    x_train, y_train, _ = zip(*fit)
    x_test, y_test, _ = zip(*test)
    model.fit(x_train, y_train)
    start = perf_counter()
    probabilities = model.predict_proba(x_test)[:, 1]
    inference_ms = 1000 * (perf_counter() - start) / len(test)
    artifact = output / f"{kind}_candidate.joblib"
    joblib.dump(model, artifact, compress=3)
    report = {
        "kind": kind, "feature_version": version, "training": dict(Counter(y_train)),
        "holdout": dict(Counter(y_test)), "overlap_exclusions": len(holdout) - len(test),
        "model_bytes": artifact.stat().st_size, "inference_ms_per_sample": inference_ms,
        "majority_baseline": evaluate(y_test, np.full(len(test), int(sum(y_train) / len(fit) > 0.5))),
        "candidate": evaluate(y_test, probabilities > 0.5, probabilities),
    }
    (output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=("email", "url", "webpage"), required=True)
    parser.add_argument("--approved", type=Path, required=True, help="Approved JSON exported by the review UI")
    parser.add_argument("--historical", type=Path, action="append", default=[], help="Verified feature rows with independent source/group labels")
    parser.add_argument("--holdout", type=Path, required=True, help="Independent labelled feature JSON excluded from collection and training")
    parser.add_argument("--output", type=Path, required=True, help="New directory for candidate and report")
    parser.add_argument("--text", action="store_true", help="Train on the email-only masked terms export")
    args = parser.parse_args()
    if args.text and args.kind != "email":
        parser.error("--text requires --kind email.")

    def read(path, approved=False):
        return read_masked_email(path, approved) if args.text else read_features(path, args.kind, approved)

    training = read(args.approved, approved=True)
    for path in args.historical:
        training.extend(read(path))
    report = train(args.kind, training, read(args.holdout), args.output, args.text)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
