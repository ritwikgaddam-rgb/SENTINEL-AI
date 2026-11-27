"""Fit research classifiers and compare their validation-locked operating points."""

from collections import Counter
import json
import resource
from time import perf_counter

import joblib
import numpy as np
from scipy.special import expit
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import MaxAbsScaler

from backend import server
from backend.assessments import link_items
from training import context_study as context
from training import email_recall_study as study
from training.gemini_baselines import replay_baselines
from training.gemini_features import (
    compute_deconfounded_sample_weights,
    compute_prototype_margin,
    extract_benign_suppressor_features,
    extract_lots_and_url_lure_features,
    extract_sparse_header_short_features,
)
from training.gemini_thresholds import evaluate_operating_points, sweep_frozen_probabilities


def feature_groups(row):
    _, links, _ = link_items(row.body, "", row.links)
    anchors = [{"url": a["url"], "label": a["display_text"]} for a in links]
    return (
        context.row_features(row),
        extract_lots_and_url_lure_features(row, anchors),
        extract_benign_suppressor_features(row, anchors),
        extract_sparse_header_short_features(row, anchors),
    )


def structure(groups, include_benign=True, interact=False):
    matrix = []
    for base, links, benign, sparse in groups:
        row = base | links | (benign if include_benign else {})
        if interact:
            row.update(sparse)
            row.update(
                {
                    "sparse_" + name: value * sparse["is_sparse_header_or_short"]
                    for name, value in row.items()
                    if name
                    in {
                        "has_links",
                        "credential_request",
                        "callback_phishing_signal",
                        "wire_urgency_signal",
                        "short_callback_refund_scam",
                        "short_sms_delivery_account_lure",
                    }
                }
            )
        matrix.append(row)
    return matrix


def fit_structure(features, labels, fit, weights):
    vec = make_pipeline(DictVectorizer(), MaxAbsScaler()).fit([features[i] for i in fit])
    X = vec.transform(features)
    clf = LogisticRegression(max_iter=500).fit(X[fit], labels[fit], sample_weight=weights)
    return clf.decision_function(X), (vec, clf)


def fit_lexical(text, labels, fit, weights, kind):
    vec = (
        study.word_features()
        if kind == "word"
        else TfidfVectorizer(
            analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=35000, sublinear_tf=True
        )
    )
    vec.fit(text[fit])
    X = vec.transform(text)
    clf = LogisticRegression(max_iter=500).fit(X[fit], labels[fit], sample_weight=weights)
    return clf.decision_function(X), (vec, clf)


def fit_stack(columns, labels, indices, weights):
    X = np.column_stack(columns)
    model = make_pipeline(MaxAbsScaler(), LogisticRegression(max_iter=500))
    model.fit(X[indices], labels[indices], logisticregression__sample_weight=weights)
    return model.decision_function(X), model


def scoring_slices(rows, groups, ix):
    slices = {}
    for cohort in ("mixed_holdout", "prior_short", "prior_dev", "unscored_archive_sms"):
        for idx in ix[cohort]:
            tags = context.slices(rows[idx], groups[idx][0])
            tags.append("sparse" if groups[idx][3]["is_sparse_header_or_short"] else "dense")
            if len(rows[idx].body.split()) > 160:
                tags.append("over_160_words")
            for name in tags:
                slices.setdefault(cohort + ":" + name, []).append(idx)
    return {name: np.asarray(values, dtype=int) for name, values in slices.items()}


def ablation_summary(report):
    """Retain each constraint setting at the 1.5% validation budget."""
    return {
        "at_1_5": {
            pool: {mode: points["0.015"] for mode, points in settings.items()}
            for pool, settings in report["sweeps"].items()
        },
        "selected": report["selected"],
        "calibration": report["calibration"],
    }


def run_candidates(args, rows, ix, y, fit, embeddings, encoder_profiles):
    started = perf_counter()
    groups = [feature_groups(row) for row in rows]
    sparse = np.array([x[3]["is_sparse_header_or_short"] for x in groups])
    text = np.array([study.model_text(r.body, r.subject)[:4500] for r in rows], dtype=object)
    evaluation_ix = {k: v for k, v in ix.items() if k != "spare_tune"}
    category_sets = {k.removeprefix("category_"): v for k, v in ix.items() if k.startswith("category_")}
    slices = scoring_slices(rows, groups, ix)
    fit_rows = [rows[i] for i in fit]
    stack = ix["stack"]
    report = {
        "partition_counts": {k: dict(Counter(y[v].tolist())) for k, v in ix.items()},
        "fit_by_source": dict(Counter(r.source for r in fit_rows)),
        "encoder_profiles": encoder_profiles,
        "candidates": {},
        "ablations": {},
        "baselines": {},
        "weighting": {},
        "error_slices": {},
    }
    artifacts = args.output / "models"
    artifacts.mkdir(exist_ok=True)

    def evaluate(scores, regimes=False, calibration_weights=None):
        return evaluate_operating_points(
            scores,
            y,
            evaluation_ix,
            tune="expanded_tune",
            old_validation="tune",
            category_sets=category_sets,
            slices=slices,
            sparse_regime=sparse if regimes else None,
            sweep_cohorts=(
                "prior_dev",
                "prior_short",
                "prior_email_holdout",
                "auth_templates",
                "mixed_holdout",
                "unscored_archive_sms",
            ),
            calibration_weights=calibration_weights,
        )

    def record(name, scores, primary=False):
        value = evaluate(scores, regimes=primary)
        if primary:
            report["candidates"][name] = value
            calibration = value["calibration"]["global"]
            probability = expit(scores * calibration["slope"] + calibration["intercept"])
            cutoff = value["selected"]["thresholds"]["caution"]
            report["error_slices"][name] = {
                cohort: error_slices(y, probability > cutoff, ix[cohort], groups)
                for cohort in (
                    "prior_dev",
                    "prior_short",
                    "prior_email_holdout",
                    "mixed_holdout",
                    "auth_templates",
                    "transaction_templates",
                    "unscored_archive_sms",
                )
            }
        else:
            report["ablations"][name] = ablation_summary(value)

    def weighted(rows, ratio):
        if ratio == 1:
            return np.ones(len(rows))
        return compute_deconfounded_sample_weights(rows, legacy_ham_weight=0.6, modern_ham_weight=0.6 * ratio)

    # Standard weight policy uses the handover's 0.6 / 3.0. Train the other
    # ratios against the same rows and tune without inspecting the tests.
    base_weights = weighted(fit_rows, 5)
    stack_weights = weighted([rows[i] for i in stack], 5)
    word, word_bundle = fit_lexical(text, y, fit, base_weights, "word")
    char, char_bundle = fit_lexical(text, y, fit, base_weights, "char")
    basic = structure(groups)
    regime = structure(groups, interact=True)
    plus, plus_bundle = fit_structure(basic, y, fit, base_weights)
    sparse_score, sparse_bundle = fit_structure(regime, y, fit, base_weights)
    record("structure_plus", plus, primary=True)
    record("regime_aware_sparse", sparse_score, primary=True)

    # Embedding classifiers and prototypes both fit on the first split only.
    # Meta LR consumes predictions on a separate labelled split.
    def multiview(keys, weights, prototypes=True):
        X = np.column_stack([embeddings[k] for k in keys])
        clf = LogisticRegression(C=1, max_iter=500).fit(X[fit], y[fit], sample_weight=weights)
        result = [clf.decision_function(X)]
        centers = None
        if prototypes:
            margin, centers = compute_prototype_margin(X, fit, y[fit], sample_weight=weights)
            result.append(margin)
        return result, (clf, centers)

    primary_keys = [("mini", "front"), ("mini", "back"), ("bge", "front"), ("bge", "back")]
    sem, sem_bundle = multiview(primary_keys, base_weights)
    gemini, stack_model = fit_stack([plus, word, *sem, sparse], y, stack, stack_weights)
    record("deconfounded_multiview_stack", gemini, primary=True)
    joblib.dump(
        {
            "structure": plus_bundle,
            "sparse": sparse_bundle,
            "word": word_bundle,
            "char": char_bundle,
            "semantic": sem_bundle,
            "stack": stack_model,
            "views": primary_keys,
        },
        artifacts / "gemini.joblib",
        compress=3,
    )
    # Isolate each component while retaining the original train/stack/cal/tune.
    no_benign, _ = fit_structure(structure(groups, include_benign=False), y, fit, base_weights)
    basic_only, _ = fit_structure([g[0] for g in groups], y, fit, base_weights)
    variants = {
        "no_benign_context": [no_benign, word, *sem, sparse],
        "previous_structural_features": [basic_only, word, *sem, sparse],
        "no_structural_branch": [word, *sem, sparse],
        "no_sparse_flag": [plus, word, *sem],
        "no_prototypes": [plus, word, sem[0], sparse],
        "no_semantics": [plus, word, sparse],
        "add_character": [plus, word, char, *sem, sparse],
        "structural_character_semantic": [sparse_score, char, *sem],
        "single_view_minilm": [plus, word, *multiview([("mini", "single")], base_weights)[0], sparse],
        "minilm_two_views": [plus, word, *multiview(primary_keys[:2], base_weights)[0], sparse],
        "bge_two_views": [plus, word, *multiview(primary_keys[2:], base_weights)[0], sparse],
        "include_middle": [
            plus,
            word,
            *multiview(primary_keys + [("mini", "middle")], base_weights)[0],
            sparse,
        ],
    }
    for name, columns in variants.items():
        scores, _ = fit_stack(columns, y, stack, stack_weights)
        record(name, scores)
    print("Trained three candidates and", len(variants), "component ablations", flush=True)
    for ratio in (1, 2, 3, 5):
        fit_weights = weighted(fit_rows, ratio)
        fusion_weights = weighted([rows[i] for i in stack], ratio)
        report["weighting"][str(ratio)] = {"fit_ess": ess(fit_weights), "stack_ess": ess(fusion_weights)}
        if ratio != 5:
            ratio_structure, _ = fit_structure(basic, y, fit, fit_weights)
            ratio_word, _ = fit_lexical(text, y, fit, fit_weights, "word")
            ratio_sem, _ = multiview(primary_keys, fit_weights)
            scores, _ = fit_stack([ratio_structure, ratio_word, *ratio_sem, sparse], y, stack, fusion_weights)
            record("weight_ratio_" + str(ratio), scores)
    calibration_weights = np.ones(len(rows))
    calibration_weights[ix["cal"]] = weighted([rows[i] for i in ix["cal"]], 5)
    report["ablations"]["weighted_calibration"] = ablation_summary(
        evaluate(gemini, calibration_weights=calibration_weights)
    )
    print("Completed source weighting and calibration comparisons", flush=True)

    baseline_file = args.output / "baselines.joblib"
    if baseline_file.exists():
        frozen = joblib.load(baseline_file)
    else:
        frozen = replay_baselines(rows, ix, y, resources=args.resources)
        joblib.dump(frozen, baseline_file)
    checkpoints = args.output / "checkpoints.joblib"
    if not checkpoints.exists():
        raise FileNotFoundError("Run the same study with --torch-only to evaluate both MiniLM checkpoints")
    frozen.update(joblib.load(checkpoints))
    for name, model in frozen.items():
        probability, cutoff = model["probabilities"], model["threshold"]
        report["baselines"][name] = {
            "historical_cutoff": cutoff,
            "cohorts": {
                k: context.stats(y[ix[k]], probability[ix[k]] > cutoff, probability[ix[k]])
                for k in sorted(model["allowed_sets"])
                if k not in {"guard", "cal"}
            },
            "notes": model["notes"],
        }
    orig = frozen["nov25_minilm_checkpoint"]["probabilities"]
    report["previous_minilm_threshold_sensitivity"] = sweep_frozen_probabilities(
        y[ix["prior_tune"]], orig[ix["prior_tune"]], orig[ix["guard"]]
    )

    fixed = {}
    for key in evaluation_ix:
        if key in {"fit", "extra_fit", "stack", "cal", "guard", "expanded_tune", "tune"} or key.startswith(
            "category_"
        ):
            continue
        indices = ix[key]
        levels = []
        for i in indices:
            r = rows[i]
            levels.append(
                server.predict_email_risk(r.body, r.sender, r.links, r.subject, r.reply_to)["display_level"]
            )
        counts = context.stats(y[indices], [v in {"danger", "suspicious"} for v in levels])
        fixed[key] = counts | {"abstentions": levels.count("unknown")}
    report["baselines"]["corrected_production"] = {"cohorts": fixed}
    report["research_runtime"] = {
        "after_embedding_seconds": perf_counter() - started,
        "process_peak_rss_native_units": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "saved_primary_python_bytes": (artifacts / "gemini.joblib").stat().st_size,
    }
    (args.output / "metrics.json").write_text(
        json.dumps(report, indent=2, default=float, allow_nan=False) + "\n"
    )
    print("Wrote research metrics", flush=True)


def ess(weights):
    return float(weights.sum() ** 2 / np.dot(weights, weights))


def error_slices(y, alerted, indices, features):
    """Count overlapping evidence types for errors without exporting messages."""
    out = {}
    indicator_names = (
        "abused_cloud_host_with_cta",
        "nested_link_lure",
        "credential_path_lure",
        "attachment_lure_signal",
        "newsletter_bulk_markers",
        "transactional_receipt_markers",
        "conversational_reply_markers",
        "is_sparse_header_or_short",
        "short_callback_refund_scam",
        "short_linkless_bec_urgency",
    )
    for expected, name in ((0, "false_positives"), (1, "false_negatives")):
        errors = [i for i in indices if y[i] == expected and alerted[i] != bool(expected)]
        observations = [features[i][0] | features[i][1] | features[i][2] | features[i][3] for i in errors]
        out[name] = {
            "n": len(errors),
            "indicator_counts": {
                key: sum(bool(row.get(key)) for row in observations) for key in indicator_names
            },
        }
    return out
