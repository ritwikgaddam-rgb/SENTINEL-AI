"""Evaluate the saved email pipeline without following links or opening attachments."""

import argparse
from collections import Counter
from email import policy
from email.parser import BytesParser
from hashlib import sha256
from html.parser import HTMLParser
import itertools
import mailbox
from pathlib import Path
import re
import unicodedata

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import brier_score_loss, log_loss
from sklearn.model_selection import train_test_split

from email_reliability import effective_feature_count, email_scores


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "head"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "head"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def body_text(message):
    body = message.get_body(preferencelist=("plain", "html"))
    if body is None or body.get_content_disposition() == "attachment" or body.get_filename():
        return ""
    payload = body.get_payload(decode=True)
    if not payload:
        return ""
    try:
        text = payload.decode(body.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        text = payload.decode("utf-8", errors="replace")
    if body.get_content_subtype() == "html":
        parser = VisibleText()
        parser.feed(text)
        text = " ".join(parser.parts)
    return text.strip()


def phishing_bodies(path):
    messages = mailbox.mbox(path, factory=BytesParser(policy=policy.default).parse, create=False)
    try:
        for message in messages:
            yield body_text(message), 1
    finally:
        messages.close()


def digest(tokens):
    return sha256(" ".join(tokens).encode()).digest()


def fingerprint(text):
    """Track normalized bodies and common campaign/template variants."""
    canonical = unicodedata.normalize("NFKC", text).casefold()
    normalized = re.findall(r"\w+", canonical)
    if not normalized:
        return set()

    template = re.sub(r"\b(?:https?://|www\.)\S+", " urlplaceholder ", canonical)
    template = re.sub(r"\b[\w.+-]+@[\w.-]+\.\w+\b", " addressplaceholder ", template)
    template = re.sub(r"\d+", " numberplaceholder ", template)
    tokens = re.findall(r"\w+", template)
    signatures = {digest(normalized), digest(tokens)}
    if len(tokens) >= 40:
        signatures.update((digest(tokens[:40]), digest(tokens[-40:])))
    return signatures


def unique_rows(rows, known):
    selected = []
    counts = Counter()
    for text, label in rows:
        signatures = fingerprint(text)
        if not signatures:
            counts[label, "empty"] += 1
            continue
        if signatures & known:
            counts[label, "overlap"] += 1
            known.update(signatures)
            continue
        known.update(signatures)
        selected.append((text, label))
        counts[label, "included"] += 1
    print("Dataset screening by label and reason", dict(sorted(counts.items())))
    return selected


def report_training_overlap(data, model):
    print("Original class counts", data["Email Type"].value_counts().to_dict())
    clean = data.drop_duplicates(subset="Email Text")
    print("After dropping exact body duplicates", clean["Email Type"].value_counts().to_dict())
    train, test = train_test_split(clean, test_size=0.2, random_state=42, stratify=clean["Email Type"])
    known = set().union(*(fingerprint(text) for text in train["Email Text"]))
    overlaps = np.array([bool(known & fingerprint(text)) for text in test["Email Text"]])
    print(f"Historical test rows overlapping the fit after template normalization: {overlaps.sum()}/{len(test)}")
    labels = (test["Email Type"] == "Phishing Email").astype(int).to_numpy()
    predictions = model.predict(test["Email Text"])
    print("Historical test baseline", metrics(labels, predictions))
    print("Historical test baseline after overlap screening", metrics(labels[~overlaps], predictions[~overlaps]))
    return clean


def examples(rows, model):
    texts, labels = zip(*rows)
    features = model.named_steps["tfidf"].transform(texts)
    return np.array(labels), email_scores(model, features), np.array([
        effective_feature_count(row) for row in features
    ])


def metrics(labels, predictions):
    tn, fp, benign_abstained = [int(((labels == 0) & (predictions == value)).sum()) for value in (0, 1, -1)]
    fn, tp, phishing_abstained = [int(((labels == 1) & (predictions == value)).sum()) for value in (0, 1, -1)]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn + phishing_abstained)
    return {
        "confusion": [[tn, fp, benign_abstained], [fn, tp, phishing_abstained]],
        "fpr": fp / (tn + fp + benign_abstained),
        "scored_fpr": fp / (tn + fp) if tn + fp else 0.0,
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "coverage": (tn + fp + fn + tp) / len(labels),
    }


def predict(scores, features, support, safe, phishing):
    sufficient_evidence = features >= support
    return np.where(sufficient_evidence & (scores > phishing), 1,
                    np.where(sufficient_evidence & (scores <= safe), 0, -1))


def print_comparison(data, parameters):
    labels, scores, features = data
    baseline = metrics(labels, predict(scores, features, 0, 0.5, 0.5))
    updated = metrics(labels, predict(scores, features, *parameters))
    print("Baseline", baseline)
    print("Evidence policy", updated)
    print("Raw score calibration", {
        "brier": brier_score_loss(labels, scores),
        "log_loss": log_loss(labels, scores),
    })
    for lower in np.arange(5) / 5:
        mask = (scores >= lower) & (scores < lower + 0.2)
        if mask.any():
            print("Calibration band", round(lower, 1), int(mask.sum()),
                  round(scores[mask].mean(), 4), round(labels[mask].mean(), 4))


def select_parameters(data):
    labels, scores, features = data
    baseline = metrics(labels, predict(scores, features, 0, 0.5, 0.5))
    choices = []
    for parameters in itertools.product((0, 2, 3, 3.5, 4, 4.5, 5, 6, 7, 9), (0.5,), (0.5, 0.55, 0.6, 0.7, 0.8)):
        result = metrics(labels, predict(scores, features, *parameters))
        if result["recall"] >= baseline["recall"] * 0.94 and result["coverage"] >= 0.90:
            choices.append((-result["fpr"], result["f1"], result["coverage"], parameters))
    return max(choices)[-1]


def read_ham(path):
    return pd.read_parquet(path, columns=["text", "dataset_name"], filters=[("label", "==", 0)]).dropna()


def ham_bodies(ham, source):
    texts = ham.loc[ham["dataset_name"] == source, "text"].sample(n=3000, random_state=42)
    return ((text, 0) for text in texts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selection_phishing", type=Path, help="Nazario's phishing-2024 mailbox")
    parser.add_argument("test_phishing", type=Path, nargs="?", help="Nazario's phishing-2025 mailbox")
    parser.add_argument("--original", type=Path, default=Path("data/Phishing_Email.csv"))
    parser.add_argument("--ham", type=Path, default=Path("data/train.parquet"))
    parser.add_argument("--model", type=Path, default=Path("models/email_phishing_model.joblib"))
    args = parser.parse_args()

    model = joblib.load(args.model)
    train = report_training_overlap(pd.read_csv(args.original).dropna(subset=["Email Text", "Email Type"]), model)
    seen = set().union(*(fingerprint(text) for text in train["Email Text"]))
    ham = read_ham(args.ham)
    selection = unique_rows(itertools.chain(ham_bodies(ham, "CEAS-08"), phishing_bodies(args.selection_phishing)), seen)
    selection_data = examples(selection, model)
    parameters = select_parameters(selection_data)
    print("Selected effective feature count, legitimate cutoff, phishing cutoff", parameters)
    print_comparison(selection_data, parameters)
    if args.test_phishing is not None:
        test = unique_rows(itertools.chain(ham_bodies(ham, "TREC-07"), phishing_bodies(args.test_phishing)), seen)
        print("Holdout metrics")
        print_comparison(examples(test, model), parameters)


if __name__ == "__main__":
    main()
