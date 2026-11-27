"""Bounded lexical and structural phishing evaluation using local screened data."""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
from scipy.special import expit
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import MaxAbsScaler, StandardScaler

from backend import server
from training import context_study as context
from training import email_recall_study as study
from training.gemini_candidates import feature_groups, structure
from training.gemini_features import compute_deconfounded_sample_weights
from training.gemini_study import make_study
from training.gemini_thresholds import FPR_TARGETS, evaluate_operating_points


# A fixed factorial subset. Each pair retains the same fit groups.
LEXICAL_SETTINGS = {
    "word_reference": (dict(ngram_range=(1, 2), max_features=25000, min_df=2), 1.0, None),
    "word_compact": (dict(ngram_range=(1, 1), max_features=9000, min_df=3), 0.5, "balanced"),
    "char_reference": (dict(analyzer="char_wb", ngram_range=(3, 5), max_features=35000, min_df=3), 1.0, None),
    "char_compact": (
        dict(analyzer="char", ngram_range=(3, 4), max_features=16000, min_df=3),
        0.5,
        "balanced",
    ),
}
COMPARISON_COHORTS = (
    "prior_dev",
    "prior_short",
    "mixed_holdout",
    "auth_templates",
    "transaction_templates",
    "prior_email_holdout",
    "unscored_archive_sms",
)
FROZEN_MODELS = ("nov25_structure", "full_word", "full_char", "curated_char", "full_structure", "full_blend")


def measures(y, alerts, scores=None, unknown=None):
    report = context.stats(y, alerts)
    unknown = np.zeros(len(y), dtype=bool) if unknown is None else unknown
    report.update(
        abstentions=int(unknown.sum()),
        abstention_rate=float(unknown.mean()),
        unscored_phishing=int((unknown & (y == 1)).sum()),
    )
    if scores is not None:
        finite = np.isfinite(scores)
        both_labels = len(np.unique(y[finite])) == 2
        report.update(
            n_ranked=int(finite.sum()),
            auroc=float(roc_auc_score(y[finite], scores[finite])) if both_labels else None,
            average_precision=float(average_precision_score(y[finite], scores[finite]))
            if both_labels
            else None,
        )
    return report


def compact_comparison(scores, y, ix, categories):
    evaluated = evaluate_operating_points(
        scores,
        y,
        ix,
        tune="expanded_tune",
        old_validation="tune",
        category_sets=categories,
        sweep_cohorts=COMPARISON_COHORTS,
    )
    cuts = evaluated["selected"]["thresholds"]
    cal = evaluated["calibration"]["global"]
    probability = expit(scores * cal["slope"] + cal["intercept"])
    out = {
        "thresholds": cuts,
        "validation": evaluated["selected"]["cohorts"]["expanded_tune"]["alerts"],
        "operating_points": evaluated["sweeps"]["expanded_tune"],
        "cohorts": {
            key: {
                "alerts": measures(y[ix[key]], probability[ix[key]] > cuts["caution"], probability[ix[key]]),
                "high_risk": values["high_risk"],
                "outcomes_by_label": values["display_by_label"],
            }
            for key, values in evaluated["selected"]["cohorts"].items()
        },
        "calibration": evaluated["calibration"],
    }
    return out, probability


def evaluate_production(rows, y, ix):
    active = np.unique(np.concatenate([ix[k] for k in (*COMPARISON_COHORTS, "expanded_tune", "guard")]))
    levels = np.full(len(y), "unknown", dtype="<U14")
    observations = {key: np.full(len(y), np.nan) for key in ("risk_index", "raw_probability")}
    important = np.zeros(len(y), dtype=bool)
    for i in active:
        row = rows[i]
        result = server.predict_email_risk(row.body, row.sender, row.links, row.subject, row.reply_to)
        levels[i] = result["display_level"]
        if result["risk_score"] is not None:
            observations["risk_index"][i] = result["risk_score"] / 100
        probability = result["model_observation"].get("phishing_probability")
        if probability is not None:
            observations["raw_probability"][i] = probability
        important[i] = any(marker["severity"] in {"medium", "high", "danger"} for marker in result["markers"])

    alerts = np.isin(levels, ("suspicious", "danger"))
    unknown = levels == "unknown"
    report = {}
    for key in (*COMPARISON_COHORTS, "expanded_tune", "guard"):
        ids = ix[key]
        raw = observations["raw_probability"][ids]
        suppressed = (raw > 0.5) & ~alerts[ids]
        report[key] = {
            "policy": measures(y[ids], alerts[ids], observations["risk_index"][ids], unknown[ids]),
            "raw_at_half": measures(y[ids], raw > 0.5, raw, ~np.isfinite(raw)),
            "raw_alert_without_policy_alert": {
                label: {
                    "count": int((suppressed & (y[ids] == value)).sum()),
                    "no_medium_or_high_marker": int((suppressed & ~important[ids] & (y[ids] == value)).sum()),
                }
                for label, value in (("legitimate", 0), ("phishing", 1))
            },
        }
    return report, levels, important


def cautious_overlay(name, y, ix, probability, levels, eligible):
    """Try a model-assisted caution while preserving existing warnings and abstentions."""
    fixed_alert = np.isin(levels, ("suspicious", "danger"))
    unknown = levels == "unknown"
    evaluable = eligible & ~unknown & ~fixed_alert
    tune = ix["expanded_tune"]
    positives = y[tune] == 1
    negatives = ~positives

    def alert_at(cut):
        return fixed_alert | (evaluable & (probability > cut))

    # Keep cutoff selection to the preregistered tuning pool. The actual
    # false-positive limit includes existing alerts, even if it is infeasible.
    boundaries = np.r_[0.0, np.unique(probability[tune][evaluable[tune]]), 1.0]
    out = {"base_candidate": name, "operating_points": {}}
    for limit in FPR_TARGETS:
        feasible = []
        for threshold in boundaries:
            alerts = alert_at(threshold)[tune]
            fpr = alerts[negatives].mean()
            if fpr <= limit:
                feasible.append((int(alerts[positives].sum()), -fpr, float(threshold)))
        if not feasible:
            out["operating_points"][str(limit)] = {
                "status": "infeasible_with_existing_alerts",
                "existing_validation_fpr": float(fixed_alert[tune][negatives].mean()),
            }
            continue
        _, _, chosen = max(feasible)
        alerts = alert_at(chosen)
        out["operating_points"][str(limit)] = {
            "threshold": chosen,
            "validation": measures(y[tune], alerts[tune], unknown=unknown[tune]),
            "cohorts": {
                key: measures(y[ids], alerts[ids], unknown=unknown[ids])
                for key in COMPARISON_COHORTS
                if len(ids := ix[key])
            },
        }
    return out


def run(args):
    started = perf_counter()
    # The study only consumes the grouped corpus reader. No embedding path is invoked.
    os.environ.pop("SENTINELAI_LANGUAGETOOL_PORT", None)
    rows, ix, y, capped = make_study(args)
    ix.pop("spare_tune")
    categories = {k.removeprefix("category_"): ids for k, ids in ix.items() if k.startswith("category_")}
    curated = np.r_[
        np.array(
            [i for i in ix["fit"] if rows[i].source not in {"local legacy CSV", "PhishFuzzer public"}],
            dtype=int,
        ),
        ix["extra_fit"],
    ]
    # Drop noncandidate fit rows from feature transformation. Calibration and all
    # held-out messages retain their original positions.
    used = np.unique(np.r_[capped, curated, np.concatenate([ids for key, ids in ix.items() if key != "fit"])])
    text = [""] * len(rows)
    groups = [({}, {}, {}, {}) for _ in rows]
    for i in used:
        row = rows[i]
        text[i] = study.model_text(row.body, row.subject)[:4500].encode("utf8", "replace").decode()
        groups[i] = feature_groups(row)
    text = np.array(text, dtype=object)
    expanded = structure(groups, interact=True)
    simple = [group[0] for group in groups]

    report = {
        "protocol": {
            "split": "November 26 Gemini grouped splits, screened for normalized bodies and sampled shingles",
            "fresh_independent_source_evaluation": False,
            "held_out_archive_sms": "Disjoint within this run. Previously evaluated and class-confounded by source.",
            "fit_selection": "Rank candidate variants by recall at 2.5% FPR on expanded validation, subject to category constraint. Tie-break on fewer false positives and candidate name.",
            "evaluation": "Caution and high risk are alerts. Scoreless phishing counts as a miss. Rank metrics use the scored subset and are undefined on single-class cohorts.",
            "scope": "Research only. No model conversion or deployment.",
            "lexical_variant_note": "Compact configurations change vocabulary, n-grams, C and class weighting together. The separate source weighting and structural scaling tests are controlled comparisons.",
        },
        "counts": {key: dict(Counter(y[ids].tolist())) for key, ids in ix.items()},
        "training": {},
        "candidates": {},
        "frozen_baselines": {},
    }
    probabilities = {}

    def record(name, values, params):
        report["candidates"][name], probabilities[name] = compact_comparison(values, y, ix, categories)
        report["candidates"][name]["configuration"] = params
        v = report["candidates"][name]["validation"]
        print(name, v["tp"], v["fp"], flush=True)

    for pool, fit in (("capped", capped), ("curated", curated)):
        score = {}
        fit_rows = [rows[i] for i in fit]
        source_weights = compute_deconfounded_sample_weights(fit_rows)
        report["training"][pool] = {
            "n": len(fit),
            "classes": dict(Counter(y[fit].tolist())),
            "source_counts": dict(Counter(row.source for row in fit_rows)),
            "source_weight_ess": float(source_weights.sum() ** 2 / np.dot(source_weights, source_weights)),
        }
        for name, (settings, c, balanced) in LEXICAL_SETTINGS.items():
            vec = TfidfVectorizer(**settings, sublinear_tf=True)
            vec.fit(text[fit])
            matrix = vec.transform(text)
            clf = LogisticRegression(C=c, class_weight=balanced, max_iter=500).fit(matrix[fit], y[fit])
            score[name] = clf.decision_function(matrix)
            record(
                pool + "_" + name,
                score[name],
                settings
                | {
                    "C": c,
                    "class_weight": balanced,
                    "sublinear_tf": True,
                    "norm": "l2",
                    "features": len(vec.vocabulary_),
                },
            )
            if pool == "capped" and name == "char_reference":
                weighted = LogisticRegression(C=c, max_iter=500).fit(
                    matrix[fit], y[fit], sample_weight=source_weights
                )
                record(
                    "capped_char_source_weighted",
                    weighted.decision_function(matrix),
                    settings | {"C": c, "norm": "l2", "legacy_ham_weight": 0.6, "modern_ham_weight": 3.0},
                )
        for name, features, scaler in (
            ("structure", simple, MaxAbsScaler()),
            ("structure_context", expanded, MaxAbsScaler()),
            ("structure_context_scaled", expanded, StandardScaler(with_mean=False)),
        ):
            vec = make_pipeline(DictVectorizer(), scaler).fit([features[i] for i in fit])
            matrix = vec.transform(features)
            classifier = LogisticRegression(max_iter=500).fit(matrix[fit], y[fit])
            score[name] = classifier.decision_function(matrix)
            record(pool + "_" + name, score[name], {"C": 1, "scaler": type(scaler).__name__})
        train_stack = ix["stack"]
        for name, inputs in (
            ("text_stack", ("word_reference", "char_reference")),
            ("context_stack", ("word_reference", "char_reference", "structure_context")),
        ):
            matrix = np.column_stack([score[i] for i in inputs])
            fusion = make_pipeline(MaxAbsScaler(), LogisticRegression(C=1, max_iter=500))
            fusion.fit(matrix[train_stack], y[train_stack])
            record(
                pool + "_" + name,
                fusion.decision_function(matrix),
                {"inputs": inputs, "stack_rows": len(train_stack), "C": 1},
            )

    def rank(name):
        tune = report["candidates"][name]["validation"]
        return (tune["tp"], -tune["fp"], name)

    selected = max(probabilities, key=rank)
    report["validation_selected"] = selected
    production, levels, important = evaluate_production(rows, y, ix)
    report["production"] = production
    report["policy_comparisons"] = {
        "add_caution": cautious_overlay(
            selected, y, ix, probabilities[selected], levels, np.ones(len(y), dtype=bool)
        ),
        "add_caution_with_corroboration": cautious_overlay(
            selected, y, ix, probabilities[selected], levels, important
        ),
    }

    # Read the previous non-transformer checkpoints' saved scores only. The
    # archived index contract is tied to make_study() and its pinned splits.
    previous = joblib.load(args.frozen_scores)
    for key in FROZEN_MODELS:
        baseline = previous[key]
        ranking = baseline["probabilities"]
        if len(ranking) != len(y):
            raise ValueError("Frozen checkpoints must use the same grouped study row order.")
        measurements = {
            cohort: measures(y[ids], ranking[ids] > baseline["threshold"], ranking[ids])
            for cohort in COMPARISON_COHORTS
            if cohort in baseline["allowed_sets"] and len(ids := ix[cohort])
        }
        report["frozen_baselines"][key] = {
            "cutoff": baseline["threshold"],
            "cohorts": measurements,
            "notes": baseline["notes"],
        }

    report["elapsed_seconds"] = perf_counter() - started
    args.output.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    print("Validation selected", selected, "in", round(report["elapsed_seconds"], 1), "seconds")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--legacy-csv", type=Path, required=True)
    parser.add_argument("--resources", type=Path, default=Path(".runtime/handover"))
    parser.add_argument("--source-dir", type=Path, default=Path(".runtime/email-model-study/sources"))
    parser.add_argument("--ham-dir", type=Path, default=Path(".runtime/email-sources"))
    parser.add_argument("--public-seeds", action="store_true")
    parser.add_argument(
        "--frozen-scores", type=Path, default=Path(".runtime/gemini-study/final/baselines.joblib")
    )
    run(parser.parse_args())
