"""Compare offline production-era and candidate email models on a grouped labelled cohort."""

import argparse
from collections import Counter, defaultdict
from email import message_from_binary_file, message_from_bytes, policy
from hashlib import file_digest
import json
import mailbox
from pathlib import Path
import re
import tarfile
from time import perf_counter

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import FeatureUnion, make_pipeline
from sklearn.svm import LinearSVC

from backend import server
from backend.assessments import link_items
from training.train_reviewed_features import evaluate


def normalized(text):
    return re.findall(r"[a-z]+", re.sub(r"https?://\S+|[\w.+-]+@[\w.-]+", " ", text.lower()))


def prepare(source):
    rows = []
    exact = defaultdict(set)
    for item in source:
        if item.get("Source") != "Manual" or item.get("Language") != "en" or item.get("Type") not in {"Valid", "Phishing"}:
            continue
        body, subject = str(item.get("Body") or "")[:20000], str(item.get("Subject") or "")[:500]
        key = " ".join(normalized(body))
        if not key:
            continue
        label = int(item["Type"] == "Phishing")
        exact[key].add(label)
        rows.append((body, subject, str(item.get("Sender") or "")[:500], label, key))
    result = []
    seen = set()
    for body, subject, sender, label, key in rows:
        if key not in seen and len(exact[key]) == 1:
            seen.add(key)
            result.append((body, subject, sender, label, key))
    return result


def template_groups(rows):
    owners = {}
    parent = list(range(len(rows)))

    def root(index):
        while parent[index] != index:
            index = parent[index]
        return index

    for i, (*_, key) in enumerate(rows):
        words = key.split()
        for signature in (tuple(words[:12]), tuple(words[-12:])):
            if signature in owners:
                parent[root(i)] = root(owners[signature])
            else:
                owners[signature] = i
    return [root(i) for i in range(len(rows))]


def candidate_results(name, model, holdout, labels, output=None):
    started = perf_counter()
    scores = model.predict_proba(holdout)[:, list(model.classes_).index(1)]
    duration = perf_counter() - started
    results = evaluate(labels, scores > .5, scores)
    results["inference_ms_per_sample"] = 1000 * duration / len(holdout)
    if output is not None:
        path = output / f"{name}.joblib"
        joblib.dump(model, path, compress=3)
        results["model_bytes"] = path.stat().st_size
    return results


def run(seed, output):
    rows = prepare(json.loads(seed.read_text()))
    groups = template_groups(rows)
    split = GroupShuffleSplit(n_splits=1, test_size=0.35, random_state=42)
    fit, test = next(split.split(rows, groups=groups))
    inputs = [f"{subject}\n{body}" for body, subject, _, _, _ in rows]
    y = np.array([label for _, _, _, label, _ in rows])
    if len(set(y[fit])) != 2 or len(set(y[test])) != 2:
        raise ValueError("Both labels are required in each grouped split.")
    evidence_start = perf_counter()
    evidence = [server.predict_email_risk(body, sender, subject=subject) for body, subject, sender, _, _ in rows]
    evidence_time = 1000 * (perf_counter() - evidence_start) / len(rows)
    numeric = [server.email_features(entry) for entry in evidence]
    reports = {"fit": dict(Counter(int(v) for v in y[fit])), "holdout": dict(Counter(int(v) for v in y[test])),
               "groups": {"fit": len({groups[i] for i in fit}), "holdout": len({groups[i] for i in test})}}
    original = Path("models/email_phishing_model.joblib")
    old = joblib.load(original)
    legacy = candidate_results("legacy", old, [rows[i][0] for i in test], y[test])
    legacy["model_bytes"] = original.stat().st_size
    reports["legacy_email"] = legacy
    output.mkdir(parents=True, exist_ok=False)
    for name, transformer, values in (
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2), inputs),
        ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2), inputs),
        ("context", DictVectorizer(), numeric),
    ):
        train_rows, test_rows = [values[i] for i in fit], [values[i] for i in test]
        pipeline = make_pipeline(transformer, LogisticRegression(max_iter=1000, random_state=42)).fit(train_rows, y[fit])
        reports[name] = candidate_results(name, pipeline, test_rows, y[test], output)
    outcomes = Counter((int(y[i]), evidence[i]["risk_level"]) for i in test)
    reports["local_evidence"] = {
        "legitimate_clear_suspicious_unrated": [outcomes[(0, status)] for status in ("neutral", "suspicious", "uncertain")],
        "phishing_clear_suspicious_unrated": [outcomes[(1, status)] for status in ("neutral", "suspicious", "uncertain")],
        "mean_ms_per_email": evidence_time,
    }
    (output / "evaluation.json").write_text(json.dumps(reports, indent=2) + "\n")
    return reports


def email_row(message, label):
    part = message.get_body(preferencelist=("plain", "html"))
    if part is None:
        return None
    try:
        content = part.get_content()
    except (LookupError, UnicodeError, ValueError):
        return None
    if not isinstance(content, str):
        return None
    content = content[:20000]
    body = link_items("", content, ())[0] if part.get_content_subtype() == "html" else content
    key = " ".join(normalized(body))
    if len(key.split()) < 4:
        return None
    return body, str(message.get("Subject") or "")[:500], str(message.get("From") or "")[:500], label, key


def load_mail(ham_paths, phishing_paths):
    """Read publisher-labelled mail bodies locally without opening links or attachments."""
    rows = []
    for path in ham_paths:
        with tarfile.open(path, "r:bz2") as archive:
            for entry in archive:
                if not entry.isfile() or not 0 < entry.size < 1_000_000 or Path(entry.name).name == "cmds":
                    continue
                with archive.extractfile(entry) as message:
                    row = email_row(message_from_bytes(message.read(), policy=policy.default), 0)
                    if row is not None:
                        rows.append(row)
    for path in phishing_paths:
        messages = mailbox.mbox(path, create=False)
        try:
            for key in messages.iterkeys():
                with messages.get_file(key) as file:
                    row = email_row(message_from_binary_file(file, policy=policy.default), 1)
                    if row is not None:
                        rows.append(row)
        finally:
            messages.close()
    return rows


def exclusive_cohorts(fit, validation, final):
    """Keep the final source intact and remove its related templates upstream."""
    all_rows = final + validation + fit
    partitions = [0] * len(final) + [1] * len(validation) + [2] * len(fit)
    known_partition = {}
    exact_labels = defaultdict(set)
    for *_, label, key in all_rows:
        exact_labels[key].add(label)
    exact = set()
    cohorts = ([], [], [])
    for row, group, partition in zip(all_rows, template_groups(all_rows), partitions):
        key = row[-1]
        if len(exact_labels[key]) > 1 or key in exact or known_partition.setdefault(group, partition) != partition:
            continue
        exact.add(key)
        cohorts[partition].append(row)
    final, validation, fit = cohorts
    return fit, validation, final


def model_text(body, subject):
    text = re.sub(r"(?m)^>[^\n]*$", "", subject + "\n" + body)
    text = re.sub(r"https?://[^\s<>]+", " urlplaceholder ", text, flags=re.I)
    text = re.sub(r"[\w.+%-]+@[\w.-]+\.[a-z]{2,}", " addressplaceholder ", text, flags=re.I)
    text = re.sub(r"\d+", " numberplaceholder ", text)
    return " ".join(text.split())


def word_features():
    return TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True, max_features=25000)


def mixed_features():
    return FeatureUnion([
        ("words", word_features()),
        ("characters", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                       sublinear_tf=True, max_features=50000)),
    ])


def run_source_holdout(seed, output, fit_ham, fit_phishing, validation_ham, validation_phishing):
    archives = [seed, *fit_ham, *fit_phishing, *validation_ham, *validation_phishing]
    hashes = {}
    for path in archives:
        with path.open("rb") as file:
            hashes[path.name] = file_digest(file, "sha256").hexdigest()
    if len(set(hashes.values())) != len(archives):
        raise ValueError("Use distinct input archives in each cohort.")
    raw = (load_mail(fit_ham, fit_phishing), load_mail(validation_ham, validation_phishing),
           prepare(json.loads(seed.read_text())))
    cohorts = exclusive_cohorts(*raw)
    labels = [[row[3] for row in cohort] for cohort in cohorts]
    if any(set(group) != {0, 1} for group in labels):
        raise ValueError("All three cohorts need both labels after duplicate removal.")
    inputs = [[model_text(body, subject) for body, subject, *_ in cohort] for cohort in cohorts]
    x_fit, x_validation, x_final = inputs
    y_fit, y_validation, y_final = labels
    output.mkdir(parents=True, exist_ok=False)
    report = {"benchmark": "email-source-holdout-v1", "input_sha256": hashes,
              "preprocessing": "model_text v1", "decision_threshold": .5,
              "cohorts": {name: {"loaded": len(before), "counts": dict(Counter(y))}
                          for name, before, y in zip(("fit", "validation", "final"), raw, labels)}}
    original = Path("models/email_phishing_model.joblib")
    old = joblib.load(original)
    report["legacy_email"] = candidate_results("legacy", old, [row[0] for row in cohorts[-1]], y_final)
    report["legacy_email"]["model_bytes"] = original.stat().st_size
    svm = make_pipeline(mixed_features(), LinearSVC(class_weight="balanced", random_state=42)).fit(x_fit, y_fit)
    calibrated = CalibratedClassifierCV(FrozenEstimator(svm), method="sigmoid").fit(x_validation, y_validation)
    candidates = {
        "word_lr": make_pipeline(word_features(), LogisticRegression(max_iter=1000, random_state=42)).fit(x_fit, y_fit),
        "word_char_lr": make_pipeline(mixed_features(), LogisticRegression(
            class_weight="balanced", max_iter=1000, random_state=42)).fit(x_fit, y_fit),
        "word_char_svm_calibrated": calibrated,
    }
    for name, model in candidates.items():
        report[name] = candidate_results(name, model, x_final, y_final, output)
    started = perf_counter()
    outcomes = Counter((label, server.predict_email_risk(body, sender, subject=subject)["risk_level"])
                       for body, subject, sender, label, _ in cohorts[-1])
    report["local_evidence"] = {"mean_ms_per_email": 1000 * (perf_counter() - started) / len(y_final),
                                **{name: {state: outcomes[label, state] for state in ("neutral", "suspicious", "uncertain")}
                                   for label, name in ((0, "legitimate"), (1, "phishing"))}}
    (output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seed", type=Path, help="PhishFuzzer original seed JSON")
    parser.add_argument("output", type=Path, help="New candidate output directory")
    parser.add_argument("--fit-ham", action="append", type=Path, help="Apache SpamAssassin ham archive")
    parser.add_argument("--fit-phishing", action="append", type=Path, help="Nazario phishing mbox")
    parser.add_argument("--validation-ham", action="append", type=Path, help="Separate ham archive")
    parser.add_argument("--validation-phishing", action="append", type=Path, help="Separate phishing mbox")
    args = parser.parse_args()
    sources = (args.fit_ham, args.fit_phishing, args.validation_ham, args.validation_phishing)
    if any(sources) and not all(sources):
        parser.error("The independent benchmark requires all four fit and validation source arguments.")
    report = run_source_holdout(args.seed, args.output, *sources) if all(sources) else run(args.seed, args.output)
    print(json.dumps(report, indent=2))
