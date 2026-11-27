"""Local context and source-shift study. Writes aggregates and private research artifacts separately."""

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
from hashlib import sha256
import json
import math
import os
from pathlib import Path
from time import perf_counter
import re
from zipfile import ZipFile

import joblib
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import MaxAbsScaler

from training import email_recall_study as study
from training.handover_study import fingerprints
from backend.assessments import credential_context, link_items
from backend import server

Mail = study.Mail
ROOT = Path(".runtime/context-study")
PRIOR = Path(".runtime/handover/single-mail/replay.jsonl")


def new_cohorts(inputs, sources):
    import yaml

    with ZipFile(inputs / "allauth.zip") as z:
        auth = []
        for path in sorted(z.namelist()):
            if "/templates/" not in path or not path.endswith("_message.txt") or "/base_message" in path:
                continue
            text = re.sub(r"{%.*?%}", "", z.read(path).decode(), flags=re.S)
            text = re.sub(r"{{.*?}}", "[value]", text, flags=re.S).strip()
            if len(text.split()) >= 4:
                auth.append(Mail(text, 0, "allauth template"))
    with ZipFile(inputs / "solidus.zip") as z:
        (locale,) = [s for s in z.namelist() if s.endswith("/core/config/locales/en.yml")]
        strings = yaml.safe_load(z.read(locale))["en"]["spree"]
        orders = []
        for key in ("order_mailer", "shipment_mailer", "reimbursement_mailer"):
            for msg in strings[key].values():
                text = " ".join(x for k, x in msg.items() if k != "subject" and isinstance(x, str))
                orders.append(
                    Mail(
                        re.sub(r"%{[^}]+}", "[value]", text),
                        0,
                        "Solidus strings",
                        re.sub(r"%{[^}]+}", "[value]", msg.get("subject", "")),
                    )
                )
    by_template = {}
    for r, meta in zip(
        study.csv_mail(sources / "validation-v3.csv"),
        study.csv_mail(sources / "validation-v3-meta.csv"),
        strict=True,
    ):
        if meta["source_category"] == "generated_v3":
            by_template.setdefault(
                meta["template_id"], Mail(r["Email Text"], study.LABELS[r["Email Type"]], "Zenodo template")
            )
    return {
        "auth_templates": auth,
        "transaction_templates": orders,
        "paired_templates": list(by_template.values()),
        "archive_2021": study.corpus(inputs / "phishing-2021", 1, Counter()),
    }


def extra_training(inputs):
    # These publisher templates describe intended messages. No actual codes or
    # delivered headers are available. Keep each template in training only.
    pairs = dict(
        line.split("=", 1)
        for line in (inputs / "keycloak.properties").read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    rows = [
        Mail(
            re.sub(r"\{\d+}", "[value]", value.replace(r"\n", " ").replace("''", "'")),
            0,
            "Keycloak templates",
            pairs.get(key[:-4] + "Subject", ""),
        )
        for key, value in pairs.items()
        if key.endswith("Body") and key != "emailTestBody"
    ]
    with ZipFile(".runtime/handover/fresh/sms.zip") as archive:
        ham = sorted(
            (
                line[4:]
                for line in archive.read("SMSSpamCollection").decode().splitlines()
                if line.startswith("ham\t")
            ),
            key=lambda s: sha256(s.encode()).digest(),
        )
        rows.extend(Mail(s, 0, "UCI training ham") for s in ham[:750])
    rows.extend(study.corpus(inputs / "phishing-2020", 1, Counter()))
    return rows


def signatures(row):
    return {hash(key) for key in fingerprints(row)}


def build(args):
    (groups, counts), guards, audit = study.dataset(args)
    sets = defaultdict(list)
    for line in PRIOR.read_text().splitlines():
        obj = json.loads(line)
        sets["prior_" + obj.pop("set")].append(Mail(**obj))
    protected = {sig for rows in sets.values() for r in rows for sig in signatures(r)}
    for name, rows in new_cohorts(ROOT / "inputs", args.source_dir).items():
        for row in rows:
            sigs = signatures(row)
            if not protected.intersection(sigs):
                sets[name].append(row)
                protected.update(sigs)
    sets["guard"] = guards
    protected.update(sig for row in guards for sig in signatures(row))
    # Keep template groups intact. Sample calibration, stack and tuning from
    # both labels of the same legacy collection, plus the other named sources.
    allocated = defaultdict(list)
    for row, group in groups["fit"]:
        bucket = int.from_bytes(sha256(str(group).encode()).digest()[:4], "big") % 20
        name = {0: "stack", 1: "cal", 2: "tune", 3: "mixed_holdout"}.get(bucket, "fit")
        allocated[name].append(row)
    for name in ("mixed_holdout", "tune", "cal", "stack", "fit"):
        here = set()
        for row in allocated[name]:
            sig = signatures(row)
            if not sig.intersection(protected):
                here.update(sig)
                sets[name].append(row)
        protected.update(here)
    for row in extra_training(ROOT / "inputs"):
        sig = signatures(row)
        if not protected.intersection(sig):
            sets["extra_fit"].append(row)
            protected.update(sig)
    return dict(sets), {"dataset": audit, "old_partition_counts": counts}


def stats(y, prediction, probability=None):
    y = np.array(y)
    prediction = np.array(prediction, dtype=bool)
    tn, fp, fn, tp = (
        int(np.sum((y == v) & (prediction == p))) for v, p in ((0, False), (0, True), (1, False), (1, True))
    )

    def interval(k, n):
        if not n:
            return None
        f = k / n
        center = (f + 1.96**2 / (2 * n)) / (1 + 1.96**2 / n)
        half = 1.96 * math.sqrt(f * (1 - f) / n + 1.96**2 / (4 * n * n)) / (1 + 1.96**2 / n)
        return [max(0, center - half), min(1, center + half)]

    return {
        "n": len(y),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": tp / (tp + fn) if tp + fn else None,
        "precision": tp / (tp + fp) if tp + fp else None,
        "fpr": fp / (fp + tn) if fp + tn else None,
        "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        "recall_ci95": interval(tp, tp + fn),
        "fpr_ci95": interval(fp, tn + fp),
        "brier": float(np.mean((y - probability) ** 2)) if probability is not None else None,
    }


def cut(y, p, guard):
    # Both observed score lists are valid boundaries under the strict > comparison.
    cuts = np.unique(np.r_[0.0, p, guard, 1.0])
    feasible = [
        (np.sum((p > c) & (y == 1)), -np.sum((p > c) & (y == 0)), c)
        for c in cuts
        if np.mean(p[y == 0] > c) < 0.05 and not np.any(guard > c)
    ]
    return float(max(feasible)[2])


def row_features(r):
    _, anchors, _ = link_items(r.body, "", r.links)
    links = [{"url": a["url"], "label": a["display_text"]} for a in anchors]
    features = study.extract_privacy_safe_features(r.body, r.sender, links, r.subject, r.reply_to)
    features.pop("is_esp_safelisted", None)
    for part in (r.body, r.subject):
        code, _ = credential_context(part)
        if code:
            features[code] = 1
    return features


def slices(row, features):
    s = row.subject + " " + row.body
    names = [
        "short" if len(s.split()) <= 30 else "long",
        "linked" if features["has_links"] else "linkless",
        "missing_headers" if not row.sender or not row.reply_to else "has_sender_reply",
    ]
    for name, pattern in {
        "authentication": r"verification code|one.time code|two.factor|new device|sign.in",
        "security_advice": r"never share|do not share|protect your|security (?:tip|advice)",
        "transactional": r"receipt|invoice|shipment|order confirmation",
        "professional_or_school": r"meeting|homework|colleague|schedule|deadline",
        "personal": r"catch up|how are you|see you|dinner|weekend|your day",
    }.items():
        if re.search(pattern, s, re.I):
            names.append(name)
    return names


def run(args):
    if os.getenv("PYTHONHASHSEED") != "42":
        raise ValueError("Set PYTHONHASHSEED=42")
    os.umask(0o077)
    out = args.output
    out.mkdir(exist_ok=False, parents=True)
    sets, audit = build(args)
    rows = []
    ix = {}
    for k, group in sets.items():
        ix[k] = np.arange(len(rows), len(rows) + len(group))
        rows.extend(group)
    y = np.array([r.label for r in rows])
    report = {"audit": audit, "cohorts": {}, "methods": {}, "thresholds": {}, "timing": {}}
    report["input_sha256"] = {
        p.name: sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT / "inputs").iterdir())
    }
    for key, rs in sets.items():
        report["cohorts"][key] = {
            s: dict(Counter(r.label for r in rs if r.source == s)) for s in sorted({r.source for r in rs})
        }
    evaluation = {k: v for k, v in ix.items() if k not in ("fit", "extra_fit", "guard", "cal", "stack")}
    print("Dataset", {k: len(v) for k, v in ix.items()}, flush=True)
    # Same bounded input and features in both cap conditions. Do not assess links remotely.
    text = np.array(
        [study.model_text(r.body, r.subject)[:4500].encode("utf8", "replace").decode() for r in rows],
        dtype=object,
    )
    f = [row_features(r) for r in rows]
    tags = [slices(r, v) for r, v in zip(rows, f)]
    train = ix["fit"]
    by = defaultdict(list)
    for i in train:
        by[(rows[i].source, y[i])].append(i)
    capped = np.array(
        [
            i
            for key in sorted(by)
            for i in np.random.default_rng(42).choice(by[key], min(300, len(by[key])), replace=False)
        ]
    )
    # A second control excludes weak aggregate labels. Validation and tests
    # stay identical so a better score cannot come from changing the test.
    curated = [i for i in train if rows[i].source not in {"local legacy CSV", "PhishFuzzer public"}]
    caps = {"cap300": capped, "full": train, "curated": np.r_[curated, ix["extra_fit"]]}
    for tag, ids in caps.items():
        report.setdefault("fit_counts", {})[tag] = len(ids)

    def record(name, alerts, p=None):
        report["methods"][name] = {}
        for k, idx in evaluation.items():
            report["methods"][name][k] = stats(y[idx], alerts[idx], None if p is None else p[idx])
        # Prior cohorts share positives. Use only the mixed held-out split for slices.
        idx = ix["mixed_holdout"]
        groups = {}
        for tag in sorted({t for i in idx for t in tags[i]}):
            subset = np.array([i for i in idx if tag in tags[i]])
            groups[tag] = stats(y[subset], alerts[subset])
        report.setdefault("mixed_slices", {})[name] = groups

    report["extra_fit_profiles"] = {
        s: dict(Counter(t for i in ids for t in tags[i]))
        for s, ids in by_source(rows, ix["extra_fit"]).items()
    }
    if args.semantic:
        from training.context_transformer import compare

        compare(args, rows, ix, y, capped, text, record, report)
    else:
        for tag, ids in caps.items():
            components = []
            for kind in ("word", "char", "structure"):
                start = perf_counter()
                if kind == "structure":
                    vec = make_pipeline(DictVectorizer(), MaxAbsScaler()).fit([f[i] for i in ids])
                    X = vec.transform(f)
                else:
                    vec = (
                        study.word_features()
                        if kind == "word"
                        else TfidfVectorizer(
                            analyzer="char_wb",
                            ngram_range=(3, 5),
                            min_df=3,
                            sublinear_tf=True,
                            max_features=35000,
                        )
                    ).fit(text[ids])
                    X = vec.transform(text)
                model = LogisticRegression(C=1, max_iter=500).fit(X[ids], y[ids])
                scores = model.decision_function(X)
                joblib.dump((vec, model), out / f"{tag}_{kind}.joblib", compress=3)
                components.append(scores)
                fit_cut_record(f"{tag}_{kind}", scores, ix, y, out, report, record)
                report["timing"][tag + "_" + kind] = {
                    "fit_transform_evaluate_seconds": perf_counter() - start,
                    "model_bytes": (out / f"{tag}_{kind}.joblib").stat().st_size,
                }
                del X
            matrix = np.stack(components, axis=1)
            meta = LogisticRegression().fit(matrix[ix["stack"]], y[ix["stack"]])
            joblib.dump(meta, out / f"{tag}_blend.joblib")
            fit_cut_record(f"{tag}_blend", meta.decision_function(matrix), ix, y, out, report, record)
            print("Fitted", tag, flush=True)
        alerts = np.zeros(len(y), dtype=bool)
        unknown = np.zeros(len(y), dtype=bool)
        raw = np.zeros(len(y))
        report["policy_trace"] = {}
        for key, ids in evaluation.items():
            trace = Counter()
            for i in ids:
                r = rows[i]
                result = server.predict_email_risk(r.body, r.sender, r.links, r.subject, r.reply_to)
                alerts[i] = result["risk_level"] == "suspicious"
                unknown[i] = result["display_level"] == "unknown"
                raw[i] = result["model_observation"]["phishing_probability"]
                if raw[i] > 0.5 and not alerts[i]:
                    label = "phish" if y[i] else "ham"
                    trace["raw_only_" + label] += 1
                    if not any(m["severity"] in {"medium", "high", "danger"} for m in result["markers"]):
                        trace["raw_only_" + label + "_without_medium_or_high_evidence"] += 1
            report["policy_trace"][key] = dict(trace)
        record("raw_production_model", raw > 0.5, raw)
        record("production", alerts)
        report["abstentions"] = {k: int(unknown[ids].sum()) for k, ids in evaluation.items()}
        report["fit_audit"] = {}
        for s, ids in by_source(rows, np.r_[train, ix["extra_fit"]]).items():
            local = [rows[i] for i in ids]
            freq = Counter(w for i in ids for w in set(re.findall(r"[a-z]{3,}", text[i].lower())))
            # Report counts for previously implicated terms, never print unreviewed vocabulary.
            report["fit_audit"][s] = {
                "missing_sender": sum(not r.sender for r in local),
                "missing_reply": sum(not r.reply_to for r in local),
                "with_links": sum(bool(f[i]["has_links"]) for i in ids),
                "document_frequency": {
                    k: freq[k]
                    for k in ("enron", "vince", "linguistics", "your", "password", "code", "meeting")
                },
            }
        with (out / "replay.jsonl").open("w") as stream:
            for k, ids in evaluation.items():
                for i in ids:
                    stream.write(json.dumps({"set": k, **asdict(rows[i])}) + "\n")
    (out / "metrics.json").write_text(json.dumps(report, default=float, indent=2))


def by_source(rows, ids):
    d = defaultdict(list)
    for i in ids:
        d[rows[i].source].append(i)
    return d


def fit_cut_record(name, scores, ix, y, out, report, record):
    cal = ix["cal"]
    tune = ix["tune"]
    calibration = LogisticRegression(C=10).fit(scores[cal, None], y[cal])
    p = calibration.predict_proba(scores[:, None])[:, 1]
    threshold = cut(y[tune], p[tune], p[ix["guard"]])
    report["thresholds"][name] = threshold
    joblib.dump((calibration, threshold), out / (name + "_cut.joblib"))
    record(name, p > threshold, p)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("output", type=Path)
    cli.add_argument("--source-dir", type=Path, default=Path(".runtime/email-model-study/sources"))
    cli.add_argument("--ham-dir", type=Path, default=Path(".runtime/email-sources"))
    cli.add_argument("--legacy-csv", type=Path, required=True)
    cli.add_argument("--public-seeds", action="store_true")
    cli.add_argument("--semantic", action="store_true")
    run(cli.parse_args())
