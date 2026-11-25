"""Offline source-held-out email evaluation. Artifacts and reports stay under .runtime."""
import argparse
from collections import Counter, defaultdict
from contextlib import closing
import csv
from dataclasses import dataclass
from email import message_from_bytes, message_from_binary_file, policy
from hashlib import file_digest
import json
import mailbox
import os
from pathlib import Path
import tarfile
from time import perf_counter

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.frozen import FrozenEstimator
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import MaxAbsScaler
from sklearn.svm import LinearSVC

from backend import server
from backend.assessments import email_evidence, link_items
from training.compare_email_models import mixed_features, model_text, normalized, prepare, template_groups, word_features
from training.train_reviewed_features import evaluate

ROOT = Path(__file__).resolve().parents[1]
LABELS = {"Safe Email": 0, "Phishing Email": 1}
FALSE_POSITIVE_BUDGET = .05


@dataclass(frozen=True)
class Mail:
    body: str
    label: int
    source: str
    subject: str = ""
    sender: str = ""
    reply_to: str = ""
    links: tuple = ()


def corpus_mail(message, label, source):
    part = message.get_body(preferencelist=("plain", "html"))
    if part is None:
        return None
    try:
        body = part.get_content()[:20000]
        links = ()
        if part.get_content_subtype() == "html":
            body, anchors, _ = link_items("", body, ())
            links = tuple({"url": item["url"], "label": item["display_text"]} for item in anchors)
        return Mail(body, label, source, str(message.get("Subject") or "")[:500],
                    str(message.get("From") or "")[:500], str(message.get("Reply-To") or "")[:500], links)
    except (AttributeError, LookupError, UnicodeError, ValueError):
        return None


def corpus(path, label, counts):
    output = []

    def read(message):
        counts["parsed"] += 1
        row = corpus_mail(message, label, path.name)
        if row is not None and len(normalized(row.body)) >= 4:
            output.append(row)
        else:
            counts["missing_or_unusable"] += 1

    if path.suffix == ".bz2":
        with tarfile.open(path, "r:bz2") as archive:
            for entry in archive:
                if entry.isfile() and Path(entry.name).name != "cmds":
                    if not 0 < entry.size < 1_000_000:
                        counts["size_excluded"] += 1
                        continue
                    with archive.extractfile(entry) as message:
                        read(message_from_bytes(message.read(), policy=policy.default))
    else:
        with closing(mailbox.mbox(path, create=False)) as messages:
            for key in messages.iterkeys():
                with messages.get_file(key) as message:
                    read(message_from_binary_file(message, policy=policy.default))
    return output


def csv_mail(path):
    csv.field_size_limit(50_000_000)
    with path.open(newline="") as source:
        return list(csv.DictReader(source))


def normalized_key(row):
    # Suppress formatting, URL values, e-mail domains and digit changes in group keys.
    return " ".join(normalized(row.body))


def make_partitions(partitions):
    """Remove exact label conflicts and keep related templates in one partition."""
    order = ("manual", "real", "validation", "fit")
    rows = [(name, row, normalized_key(row)) for name in order for row in partitions[name]]
    groups = template_groups([(key,) for _, _, key in rows])
    labels = defaultdict(set)
    for _, row, key in rows:
        labels[key].add(row.label)
    report = {name: Counter(input=len(partitions[name])) for name in order}
    result = {name: [] for name in order}
    seen, group_owner = set(), {}
    for (name, row, key), group in zip(rows, groups):
        if not key:
            report[name]["missing"] += 1
        elif len(labels[key]) > 1:
            report[name]["conflicting"] += 1
        elif key in seen:
            report[name]["exact_duplicate"] += 1
        elif group_owner.setdefault(group, name) != name:
            report[name]["cross_partition_template"] += 1
        else:
            seen.add(key)
            result[name].append((row, group))
    for name in order:
        report[name]["retained"] = len(result[name])
        report[name].update({f"label_{k}": v for k, v in Counter(row.label for row, _ in result[name]).items()})
        report[name]["groups"] = len({group for _, group in result[name]})
    return result, report


# Benign examples authored for this study. The acceptance strings in tests
# remain separate. Augmentation supplies modern/short benign text to old mail.
FIT_HAM = (
    "Hi there!", "Morning!", "Got a minute?", "Thanks for your help.", "See you on Saturday.",
    "Can you bring the notebook?", "We have a lab session after lunch.", "The essay draft is attached.",
    "Practice is at four on the east field.", "The library books are due Friday.",
    "No class on Monday. The lesson moves to Wednesday.", "I've put the team notes in the shared folder.",
    "That time works for me.", "Sorry I missed the meeting.", "Let's review the homework together.",
    "Please bring your signed permission slip to the office.", "Can we move our call to the afternoon?",
    "I finished the draft and left comments in the margin.", "Please send the slides when you get a chance.",
    "Security reminder: use the official app to review recent sign-ins.",
    "Keep your recovery codes somewhere private. Our staff will never ask for them.",
    "If you suspect an email is fake, report it to the support team.",
    "A password manager can help you use a unique password for everything.",
    "The security workshop covers how to spot a fake login screen.",
    "The invoice is ready for the regular accounting review.",
    "Your class project has been approved. Plan to present next week.",
    "The test results are ready in the school portal you normally use.",
    "I will pick up the tickets at the door.",
    "How did the rehearsal go?", "Looks good to me.", "Can you confirm our appointment for Tuesday?",
)
DEV_HAM = (
    "Hey, good evening.", "Are you free for a quick chat?", "Talk later.", "That was really helpful.",
    "I'll meet you outside the gym.", "The teacher has moved the quiz to Thursday.",
    "Please return the science worksheet tomorrow.", "My homework was done but I forget to attach it.",
    "Can you check whether I uploaded the right assignment?",
    "Never give a caller the recovery code for your account.",
    "Someone asked me about a password reset. I told them to contact support.",
    "Turn on two-step verification using the settings menu.",
    "Please confirm you received the meeting notes.",
    "The department calendar has the updated room number and time.",
    "The order arrived today. Could you check the receipt?", "Please let me know if you have questions.",
    "I have sent the report to our usual reviewer.", "Their documentation is at https://example.org/help.",
)


def dataset(args):
    audits = {}
    sources = sorted(args.source_dir.glob("phishing-*"))
    ham_paths = sorted(args.ham_dir.glob("*.tar.bz2"))
    fit, validation = [], []
    for paths, label, validation_suffix in ((ham_paths, 0, "easy_ham_2.tar.bz2"), (sources, 1, "2024")):
        for path in paths:
            audit = audits[path.name] = Counter()
            extracted = corpus(path, label, audit)
            audit["retained_before_dedup"] = len(extracted)
            (validation if path.name.endswith(validation_suffix) else fit).extend(extracted)
    fit.extend(Mail(body, 0, "authored_fit") for body in FIT_HAM)
    dev_ham = [Mail(body, 0, "authored_validation") for body in DEV_HAM]
    raw = json.loads((args.source_dir / "seed.json").read_text())
    entries = prepare(raw)
    # Recover author-provided visible URLs without inventing anchor labels.
    refs = {}
    for item in raw:
        if item.get("Source") == "Manual" and item.get("Language") == "en":
            key = " ".join(normalized(str(item.get("Body") or "")[:20000]))
            urls = item.get("URL")
            refs.setdefault(key, tuple(url for url in urls if isinstance(url, str)) if isinstance(urls, list) else ())
    manual = [Mail(body, label, "PhishFuzzer manual", subject, sender, links=refs.get(key, ()))
              for body, subject, sender, label, key in entries]
    zen = csv_mail(args.source_dir / "validation-v3.csv")
    meta = csv_mail(args.source_dir / "validation-v3-meta.csv")
    if len(zen) != len(meta) or any(row["Email Type"] != m["email_type"] for row, m in zip(zen, meta)):
        raise ValueError("Short-message benchmark and source metadata do not align.")
    real = [Mail(row["Email Text"], LABELS[row["Email Type"]], "Zenodo real")
            for row, m in zip(zen, meta) if m["source_category"] == "original_v1"]
    if len(real) != 100:
        raise ValueError(f"Expected 100 real Zenodo records. Found {len(real)}.")
    audits["PhishFuzzer"] = {"total": len(raw), "selected_manual_english_after_screen": len(manual)}
    if args.public_seeds:
        public = [
            row for row in raw
            if row.get("Source") != "Manual" and row.get("Language") == "en"
            and row.get("Type") in {"Valid", "Phishing"} and str(row.get("Body") or "").strip()
        ]
        audits["PhishFuzzer"]["public_fit_before_screen"] = len(public)
        fit.extend(Mail(str(row["Body"])[:20000], int(row["Type"] == "Phishing"), "PhishFuzzer public",
                        str(row.get("Subject") or "")[:500], str(row.get("Sender") or "")[:500]) for row in public)
    audits["Zenodo"] = {"total": len(zen), "real": len(real), "excluded_template_generated": len(zen) - len(real)}
    if args.legacy_csv is not None:
        rows = csv_mail(args.legacy_csv)
        valid = [row for row in rows if row["Email Type"] in LABELS and (row["Email Text"] or "").strip()]
        audits["local_legacy_csv"] = {"rows": len(rows), "labels": dict(Counter(x["Email Type"] for x in rows)),
                                      "missing_or_invalid": len(rows) - len(valid)}
        fit.extend(Mail(row["Email Text"][:20000], LABELS[row["Email Type"]], "local legacy CSV") for row in valid)
    return make_partitions({"fit": fit, "validation": validation, "manual": manual, "real": real}), dev_ham, audits


def frame(rows, context=False):
    data = pd.DataFrame({"text": [model_text(row.body, row.subject) for row in rows]})
    if context:
        features = []
        for row in rows:
            details = email_evidence(row.body, row.sender, row.links, row.subject, row.reply_to)
            numeric = server.email_features(details)
            # No corpus/source identifier, raw header strings or grammar in the learned signal.
            numeric.update(subject_present=int(bool(row.subject)), sender_present=int(bool(row.sender)),
                           reply_to_present=int(bool(row.reply_to)),
                           weak_links=sum(any(m["severity"] == "medium" for m in link["markers"])
                                          for link in details["links"]))
            features.append(numeric)
        data = pd.concat([data, pd.DataFrame(features)], axis=1)
    return data


def choose_threshold(labels, probability, ham_probability):
    # Select strictly on validation. Report the realized rate at the locked cut.
    thresholds = np.r_[0., np.unique(probability), 1.]
    def at(threshold):
        alerts = probability > threshold
        return (np.mean(alerts[labels == 0]), np.mean(alerts[labels == 1]), np.mean(ham_probability > threshold))
    viable = [(recall, -fpr, -short_fpr, float(t)) for t in thresholds
              for fpr, recall, short_fpr in (at(t),) if fpr <= FALSE_POSITIVE_BUDGET and short_fpr == 0]
    return max(viable)[-1]


def score_set(labels, probabilities, threshold, *, raw=False):
    result = evaluate(labels, probabilities > threshold, probabilities if raw else None)
    result.update(threshold=threshold, coverage=1., abstention_rate=0.)
    if raw:
        p, r, t = precision_recall_curve(labels, probabilities)
        result.update(average_precision=float(average_precision_score(labels, probabilities)),
                      curve={"precision": p.tolist(), "recall": r.tolist(), "threshold": t.tolist()})
    return result


def main(args):
    os.environ.pop("SENTINELAI_LANGUAGETOOL_PORT", None)
    os.umask(0o077)  # A candidate vocabulary can contain terms from the source corpus.
    (partitions, counts), authored_ham, audits = dataset(args)
    args.output.mkdir(parents=True, exist_ok=False)
    print("Partitions", counts, flush=True)
    fit = [row for row, _ in partitions["fit"]]
    validation, groups = zip(*partitions["validation"])
    yv = np.array([row.label for row in validation])
    calibration, tune = next(StratifiedGroupKFold(n_splits=2, shuffle=True, random_state=27)
                             .split(validation, yv, groups))
    assert set(np.array(groups)[calibration]).isdisjoint(set(np.array(groups)[tune]))
    known = {"fit": fit, "calibration": [validation[i] for i in calibration], "tune": [validation[i] for i in tune],
             "manual": [row for row, _ in partitions["manual"]], "real": [row for row, _ in partitions["real"]]}
    y = {key: np.array([row.label for row in rows]) for key, rows in known.items()}
    old = server.email_model()
    raw = lambda rows: old.predict_proba([row.body for row in rows])[:, list(old.classes_).index(1)]
    legacy_th = choose_threshold(y["tune"], raw(known["tune"]), raw(authored_ham))
    models = {}
    report = {"audit": usual_dict(audits), "partitions": usual_dict(counts),
              "calibration_counts": dict(Counter(int(n) for n in y["calibration"])),
              "threshold_counts": dict(Counter(int(n) for n in y["tune"])),
              "selection_budget": FALSE_POSITIVE_BUDGET, "models": {}, "current_policy": {}}

    fit_frames = {key: frame(known[key], context=True) for key in ("fit", "calibration", "tune")}
    short = frame(authored_ham, context=True)
    models["legacy"] = (old, raw, legacy_th)
    char = lambda: TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                                  sublinear_tf=True, max_features=35000)
    trials = [
        ("word_lr", word_features, LogisticRegression(C=1, max_iter=700)),
        ("word_lr_balanced", word_features, LogisticRegression(C=2, class_weight="balanced", max_iter=700)),
        ("char_lr", char, LogisticRegression(C=2, class_weight="balanced", max_iter=700)),
        ("word_char_lr", mixed_features, LogisticRegression(C=2, class_weight="balanced", max_iter=700)),
        ("word_char_svm", mixed_features, LinearSVC(C=.5, class_weight="balanced", random_state=27)),
        ("hybrid_lr", mixed_features, LogisticRegression(C=.8, class_weight="balanced", max_iter=700)),
    ]
    cols = [c for c in fit_frames["fit"] if c != "text"]
    for name, vectorizer, estimator in trials:
        transforms = [("text", vectorizer(), "text")]
        if name == "hybrid_lr":
            transforms.append(("evidence", MaxAbsScaler(), cols))
        model = make_pipeline(ColumnTransformer(transforms), estimator).fit(fit_frames["fit"], y["fit"])
        model = CalibratedClassifierCV(FrozenEstimator(model), method="sigmoid").fit(fit_frames["calibration"], y["calibration"])
        probability = lambda table, m=model: m.predict_proba(table)[:, list(m.classes_).index(1)]
        cutoff = choose_threshold(y["tune"], probability(fit_frames["tune"]), probability(short))
        models[name] = (model, probability, cutoff)
        joblib.dump(model, args.output / f"{name}.joblib", compress=3)
        print(name, "locked threshold", round(cutoff, 7), flush=True)

    def inputs(name, cohort):
        if name == "legacy":
            return known[cohort]
        if cohort not in fit_frames:
            fit_frames[cohort] = frame(known[cohort], context=True)
        return fit_frames[cohort]
    selection = {}
    for name, (_, predict, threshold) in models.items():
        probability = predict(inputs(name, "tune"))
        selection[name] = score_set(y["tune"], probability, threshold)
    selected = max(selection, key=lambda name: (selection[name]["recall"], selection[name]["f1"], -selection[name]["fpr"]))
    report["selected_on_validation"] = selected
    print("Locked selection", selected, flush=True)

    for name, (_, predict, threshold) in models.items():
        model_path = ROOT / "models/email_phishing_model.joblib" if name == "legacy" else args.output / f"{name}.joblib"
        metrics = {"model_bytes": model_path.stat().st_size}
        for cohort in ("tune", "manual", "real"):
            rows = inputs(name, cohort)
            start = perf_counter()
            probability = predict(rows)
            latency = (perf_counter() - start) * 1000 / len(rows)
            result = score_set(y[cohort], probability, threshold, raw=True)
            result["fixed_half"] = score_set(y[cohort], probability, .5)
            result["batch_ms_per_message"] = latency
            if cohort == "tune":
                result["sweep"] = {str(t): score_set(y[cohort], probability, t) for t in (.25, .5, .6, .7, .8, .9, .95, .98)}
            metrics[cohort] = result
        inputs_short = authored_ham if name == "legacy" else short
        metrics["authored_tune_ham"] = {"count": len(authored_ham), "alerts": int(np.sum(predict(inputs_short) > threshold))}
        report["models"][name] = metrics

    for cohort in ("tune", "manual", "real"):
        rows = known[cohort]
        start = perf_counter()
        outputs = [server.predict_email_risk(row.body, row.sender, row.links, row.subject, row.reply_to) for row in rows]
        elapsed = (perf_counter() - start) * 1000 / len(rows)
        wanted = [output["risk_level"] == "suspicious" for output in outputs]
        summary = evaluate(y[cohort], wanted)
        summary["verdicts"] = {f"{label}_{status}": count for (label, status), count in
                               Counter((row.label, out["display_level"]) for row, out in zip(rows, outputs)).items()}
        summary["coverage"] = np.mean([o["display_level"] != "unknown" for o in outputs])
        summary["abstention_rate"] = 1 - summary["coverage"]
        summary["mean_ms_per_message"] = elapsed
        summary["unavailable"] = sum(not o["ml_evaluated"] for o in outputs)
        report["current_policy"][cohort] = summary
        # Also measure a policy that preserves evidence-based alerts and adds the
        # validation-selected learned alerts. Never tune this using final labels.
        prediction = models[selected][1](inputs(selected, cohort))
        promoted = [old_alert or p > models[selected][2] for old_alert, p in zip(wanted, prediction)]
        report.setdefault("alert_union", {})[cohort] = evaluate(y[cohort], promoted) | {
            "additional_alerts": sum(new and not before for new, before in zip(promoted, wanted)),
            "abstention_rate": np.mean([out["display_level"] == "unknown" and not alert
                                        for out, alert in zip(outputs, promoted)])}
    if args.archived_candidates:
        paths = args.archived_candidates
        report["archived_candidates"] = {}
        keys = {"sentinel-v2-email-63287d9": ("word_lr", "word_char_lr", "word_char_svm_calibrated"),
                "sentinel-main-email-final": ("word", "char", "context")}
        for folder, names in keys.items():
            for name in names:
                path = paths / folder / f"{name}.joblib"
                if not path.is_file():
                    continue
                # Read only known artifacts previously produced in this workspace.
                model = joblib.load(path)
                result = {"model_bytes": path.stat().st_size}
                for cohort in ("manual", "real"):
                    rows = known[cohort]
                    values = frame(rows)["text"] if folder.startswith("sentinel-v2") else [f"{r.subject}\n{r.body}" for r in rows]
                    if name == "context":
                        values = [server.email_features(email_evidence(r.body, r.sender, r.links, r.subject, r.reply_to)) for r in rows]
                    start = perf_counter()
                    p = model.predict_proba(values)[:, list(model.classes_).index(1)]
                    result[cohort] = score_set(y[cohort], p, .5, raw=True) | {"batch_ms_per_message": (perf_counter()-start)*1000/len(rows)}
                report["archived_candidates"][folder + "/" + name] = result
    paths = sorted(args.source_dir.iterdir()) + sorted(args.ham_dir.glob("*.tar.bz2"))
    if args.legacy_csv:
        paths.append(args.legacy_csv)
    report["input_sha256"] = {}
    for path in paths:
        with path.open("rb") as source:
            report["input_sha256"][path.name] = file_digest(source, "sha256").hexdigest()
    (args.output / "evaluation.json").write_text(json.dumps(report, indent=2, default=float) + "\n")


def usual_dict(counters):
    return {name: dict(counts) for name, counts in counters.items()}


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("source_dir", type=Path)
    cli.add_argument("ham_dir", type=Path)
    cli.add_argument("output", type=Path)
    cli.add_argument("--legacy-csv", type=Path)
    cli.add_argument("--public-seeds", action="store_true",
                     help="Use English non-Manual PhishFuzzer seeds in fit after cross-partition deduplication.")
    cli.add_argument("--archived-candidates", type=Path)
    main(cli.parse_args())
