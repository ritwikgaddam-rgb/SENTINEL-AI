"""Offline calibration and alert selection using disjoint validation partitions."""

from collections import Counter
from math import floor

import numpy as np
from scipy.special import expit, logit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

from training.context_study import stats


FPR_TARGETS = (0.01, 0.015, 0.025, 0.05)
CURVE_GRID = np.unique(np.r_[np.linspace(0, 1, 41), 0.001, 0.01, 0.99, 0.999, 0.9999])


def _operating_point(y, probability, target, categories):
    """Maximize validation recall subject to empirical false-positive budgets."""
    # With strict >, a category's own score may be the best cutoff.
    boundaries = np.unique(np.concatenate(([0.0, 1.0], probability, *(p for p, _ in categories))))
    negatives = np.sort(probability[y == 0])
    positives = np.sort(probability[y == 1])
    fp = len(negatives) - np.searchsorted(negatives, boundaries, side="right")
    tp = len(positives) - np.searchsorted(positives, boundaries, side="right")
    feasible = fp <= floor(target * len(negatives) + 1e-10)
    for values, limit in categories:
        values = np.sort(values)
        count = len(values) - np.searchsorted(values, boundaries, side="right")
        feasible &= count <= floor(limit * len(values) + 1e-10)
    candidates = np.flatnonzero(feasible)
    best = min(candidates, key=lambda i: (-tp[i], fp[i], -i))
    return float(boundaries[best])


def _counts(y, probability, cutoff):
    result = stats(y, probability > cutoff)
    result["abstentions"] = int(np.isnan(probability).sum())
    return result


def _calibration_stats(y, probability):
    finite = np.isfinite(probability)
    y, probability = y[finite], probability[finite]
    if not len(y):
        return {"n": 0, "brier": None, "ece_10": None, "above_0_999": 0, "below_0_001": 0}
    buckets = np.minimum((probability * 10).astype(int), 9)
    ece = 0.0
    for bucket in np.unique(buckets):
        rows = buckets == bucket
        ece += rows.mean() * abs(y[rows].mean() - probability[rows].mean())
    return {
        "n": len(y),
        "brier": float(np.mean((y - probability) ** 2)),
        "ece_10": float(ece),
        "above_0_999": int((probability > 0.999).sum()),
        "below_0_001": int((probability < 0.001).sum()),
        "max_legitimate": float(max(probability[y == 0])) if (y == 0).any() else None,
        "min_phishing": float(min(probability[y == 1])) if (y == 1).any() else None,
    }


def _curve(y, probability, thresholds):
    """Aggregate curve points on fixed and validation-selected score boundaries."""
    valid = np.isfinite(probability)
    both = len(np.unique(y[valid])) == 2
    # A genuinely unknown score stays a missed detection across all plotted cutoffs.
    pos = np.sort(probability[(y == 1) & valid])
    neg = np.sort(probability[(y == 0) & valid])
    cuts = np.unique(np.r_[CURVE_GRID, thresholds])
    fpr, recall, precision = [], [], []
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    for cutoff in cuts:
        tp = int(len(pos) - np.searchsorted(pos, cutoff, side="right"))
        fp = int(len(neg) - np.searchsorted(neg, cutoff, side="right"))
        fpr.append(fp / n_neg if n_neg else None)
        recall.append(tp / n_pos if n_pos else None)
        precision.append(tp / (tp + fp) if tp + fp else None)
    return {
        "threshold": cuts.tolist(),
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "auroc_scored": float(roc_auc_score(y[valid], probability[valid])) if both else None,
        "average_precision_scored": float(average_precision_score(y[valid], probability[valid]))
        if both
        else None,
        "n_scored": int(valid.sum()),
        "n": len(y),
    }


def _fit_sigmoid(logits, y, calibration, weights):
    weights = None if weights is None else weights[calibration]
    if weights is not None:
        weights = weights / weights.mean()
    model = LogisticRegression(C=10)
    model.fit(logits[calibration, None], y[calibration], sample_weight=weights)
    slope = float(model.coef_[0, 0])
    intercept = float(model.intercept_[0])
    return expit(logits * slope + intercept), {
        "slope": slope,
        "intercept": intercept,
        "n": len(calibration),
        "effective_n": float(weights.sum() ** 2 / np.dot(weights, weights))
        if weights is not None
        else len(calibration),
    }


def sweep_frozen_probabilities(y, probability, guard_probabilities=()):
    """Reproduce validation policy on a saved checkpoint's original scale."""
    y, probability, guard = map(np.asarray, (y, probability, guard_probabilities))
    if y.ndim != 1 or y.shape != probability.shape or set(y) != {0, 1} or guard.ndim != 1:
        raise ValueError("Expected aligned binary validation labels and one-dimensional probabilities")
    values = np.r_[probability, guard]
    if not np.isfinite(values).all() or ((values < 0) | (values > 1)).any():
        raise ValueError("Frozen probabilities must be finite and in [0, 1]")
    constraints = {"unconstrained": []}
    if len(guard):
        constraints["zero_guard"] = [(guard, 0.0)]
    benign = np.zeros(len(guard), dtype=int)
    report = {
        "at_half": {"validation": _counts(y, probability, 0.5), "guard": _counts(benign, guard, 0.5)},
        "calibration_diagnostics": {
            "validation": _calibration_stats(y, probability),
            "guard": _calibration_stats(benign, guard),
        },
        "sweeps": {},
    }
    thresholds = []
    for kind, bounds in constraints.items():
        report["sweeps"][kind] = points = {}
        for target in FPR_TARGETS:
            cutoff = _operating_point(y, probability, target, bounds)
            thresholds.append(cutoff)
            points[str(target)] = {
                "threshold": cutoff,
                "validation": _counts(y, probability, cutoff),
                "guard": _counts(benign, guard, cutoff),
            }
    report["curves"] = _curve(y, probability, thresholds)
    return report


def evaluate_operating_points(
    scores,
    y,
    ix,
    *,
    old_validation="prior_tune",
    category_sets=None,
    slices=None,
    tune="tune",
    cal="cal",
    sparse_regime=None,
    probability_input=False,
    sweep_cohorts=None,
    min_category_rows=20,
    calibration_weights=None,
):
    """Compare locked operating points without consulting evaluation labels.

    Score rows must align with y. By default scores are logits, and NaN represents
    an unscored evaluation row. Each category is a benign-only group reserved for
    threshold selection. Its empirical false-positive cap matches the global cap.
    Small categories are measured separately in the all-category sensitivity run.
    """
    y, scores = np.asarray(y), np.asarray(scores, dtype=float)
    if y.ndim != 1 or y.shape != scores.shape or not np.isin(y, (0, 1)).all():
        raise ValueError("Aligned one-dimensional binary labels and scores are required")
    finite = np.isfinite(scores)
    if np.isinf(scores).any() or (probability_input and ((scores[finite] < 0) | (scores[finite] > 1)).any()):
        raise ValueError("Expected finite logits or probabilities in [0, 1], with NaN for unavailable scores")
    raw = scores if probability_input else expit(scores)
    logits = logit(np.clip(scores, 1e-12, 1 - 1e-12)) if probability_input else scores
    if min_category_rows < 1:
        raise ValueError("Minimum category size must be positive")

    def check_indices(indices):
        indices = np.asarray(indices)
        if (
            indices.ndim != 1
            or (
                len(indices)
                and (indices.dtype.kind not in "ui" or indices.min() < 0 or indices.max() >= len(y))
            )
            or len(np.unique(indices)) != len(indices)
        ):
            raise ValueError("Partitions must contain distinct in-range integer indices")
        return indices.astype(int)

    ix = {name: check_indices(indices) for name, indices in ix.items()}
    categories = {name: check_indices(indices) for name, indices in (category_sets or {}).items()}
    pools = {tune: ix[tune]}
    if old_validation and old_validation in ix and old_validation != tune:
        pools[old_validation] = ix[old_validation]
    calibration = ix[cal]
    guard = ix.get("guard", np.array([], dtype=int))
    if calibration_weights is not None:
        calibration_weights = np.asarray(calibration_weights, dtype=float)
        if (
            calibration_weights.shape != y.shape
            or not (
                (calibration_weights[calibration] > 0) & np.isfinite(calibration_weights[calibration])
            ).all()
        ):
            raise ValueError(
                "Calibration weights must align with labels and be positive and finite on calibration rows"
            )
    for indices in [calibration, *pools.values()]:
        if len(np.unique(y[indices])) != 2:
            raise ValueError("Calibration and threshold pools each need both labels")
    tune_union = set(np.concatenate(list(pools.values())))
    disjoint = set(calibration) | tune_union | set(guard)
    if len(disjoint) != len(calibration) + len(tune_union) + len(guard):
        raise ValueError("Calibration, threshold pools and prior guard must be disjoint")
    category_union = set(np.concatenate(list(categories.values()))) if categories else set()
    if category_union & disjoint:
        raise ValueError(
            "Category validation must be separate from calibration, threshold pools and prior guard"
        )
    for indices in [guard, *categories.values()]:
        if (y[indices] != 0).any():
            raise ValueError("Guard and category constraints require legitimate labels")
    if not finite[list(disjoint | category_union)].all():
        raise ValueError("Calibration and threshold-selection rows require finite scores")

    reserved = {"fit", "extra_fit", "stack", "guard", "cal", cal, *pools}
    used = disjoint | category_union
    cohorts = {}
    for name, indices in ix.items():
        if name in reserved or not len(indices) or set(indices).issubset(category_union):
            continue
        if set(indices) & used:
            raise ValueError(f"Evaluation cohort {name} overlaps calibration or threshold selection")
        cohorts[name] = indices
    slices = {name: check_indices(indices) for name, indices in (slices or {}).items()}
    for name, indices in slices.items():
        if set(indices) & used:
            raise ValueError(f"Evaluation slice {name} overlaps calibration or threshold selection")
    requested_cohorts = {name: cohorts[name] for name in (sweep_cohorts or ())}

    probability, fitted = _fit_sigmoid(logits, y, calibration, calibration_weights)
    measurements = {cal: calibration, **pools, **cohorts}
    if len(guard):
        measurements["guard"] = guard
    measurements.update({f"category:{name}": indices for name, indices in categories.items()})
    report = {
        "calibration": {
            "global": fitted,
            "cohorts": {
                name: {
                    "raw": _calibration_stats(y[indices], raw[indices]),
                    "calibrated": _calibration_stats(y[indices], probability[indices]),
                }
                for name, indices in measurements.items()
            },
        }
    }

    def select(p, pool, constraints, target):
        constrained = [(p[indices], limit) for indices, limit in constraints]
        return _operating_point(y[pool], p[pool], target, constrained)

    def selected_results(p, thresholds, groups):
        caution, high = thresholds["caution"], thresholds["high_risk"]
        result = {}
        for name, idx in groups.items():
            values = p[idx]
            display = np.full(len(idx), "below_caution", dtype="<U15")
            display[values > caution] = "caution"
            display[values > high] = "high_risk"
            display[np.isnan(values)] = "unknown"
            result[name] = {
                "alerts": _counts(y[idx], values, caution),
                "high_risk": _counts(y[idx], values, high),
                "display_by_label": {
                    label: dict(Counter(display[y[idx] == value]))
                    for value, label in ((0, "legitimate"), (1, "phishing"))
                },
            }
        return result

    eligible = {name: idx for name, idx in categories.items() if len(idx) >= min_category_rows}
    nonempty = {name: idx for name, idx in categories.items() if len(idx)}
    report["category_constraints"] = {
        "minimum_n_for_selected_constraint": min_category_rows,
        "eligible": list(eligible),
        "exploratory_only": [name for name in categories if name not in eligible],
    }
    report["sweeps"] = sweeps = {}
    for name, pool in pools.items():
        sweeps[name] = {"unconstrained": {}}
        if len(guard):
            sweeps[name]["zero_guard"] = {}
        if eligible:
            sweeps[name]["category"] = {}
        if nonempty.keys() != eligible.keys():
            sweeps[name]["category_all"] = {}
        for target in FPR_TARGETS:
            for kind, points in sweeps[name].items():
                selected_categories = {"category": eligible, "category_all": nonempty}.get(kind, {})
                constraints = [(idx, target) for idx in selected_categories.values()]
                if kind == "zero_guard":
                    constraints = [(guard, 0.0)]
                cutoff = select(probability, pool, constraints, target)
                point = {
                    "threshold": cutoff,
                    "validation": _counts(y[pool], probability[pool], cutoff),
                    "guard": _counts(y[guard], probability[guard], cutoff),
                    "categories": {
                        label: _counts(y[idx], probability[idx], cutoff)
                        | {"allowed_false_positives_at_category_cap": floor(target * len(idx) + 1e-10)}
                        for label, idx in categories.items()
                    },
                }
                if requested_cohorts:
                    point["cohorts"] = {
                        label: _counts(y[idx], probability[idx], cutoff)
                        for label, idx in requested_cohorts.items()
                    }
                points[str(target)] = point
    constraint = "category" if eligible else "unconstrained"
    selected = {
        "caution": sweeps[tune][constraint]["0.025"]["threshold"],
        "high_risk": sweeps[tune][constraint]["0.01"]["threshold"],
    }
    selected["high_risk"] = max(selected["caution"], selected["high_risk"])
    groups = {**pools, **cohorts}
    report["selected"] = {
        "thresholds": selected,
        "validation_pool": tune,
        "constraint": constraint,
        "distinct_levels": selected["caution"] < selected["high_risk"],
        "cohorts": selected_results(probability, selected, groups),
        "slices": selected_results(probability, selected, slices),
    }
    run_thresholds = [
        point["threshold"]
        for variants in sweeps.values()
        for sweep in variants.values()
        for point in sweep.values()
    ]
    report["curves"] = {
        name: _curve(y[idx], probability[idx], run_thresholds) for name, idx in groups.items()
    }
    if sparse_regime is not None:
        sparse = np.asarray(sparse_regime, dtype=bool)
        if sparse.shape != y.shape:
            raise ValueError("Sparse regime must be aligned with the score array")
        regimes = {
            name: calibration[sparse[calibration] == value]
            for name, value in (("sparse", True), ("dense", False))
        }
        if all(np.bincount(y[idx].astype(int), minlength=2).min() >= 20 for idx in regimes.values()):
            split = np.empty(len(y))
            fits = {}
            for name, idx in regimes.items():
                p, fits[name] = _fit_sigmoid(logits, y, idx, calibration_weights)
                mask = sparse if name == "sparse" else ~sparse
                split[mask] = p[mask]
            cutoffs = {
                label: select(split, pools[tune], [(idx, target) for idx in eligible.values()], target)
                for label, target in (("caution", 0.025), ("high_risk", 0.01))
            }
            cutoffs["high_risk"] = max(cutoffs["caution"], cutoffs["high_risk"])
            report["calibration"]["regime"] = {
                "fits": fits,
                "thresholds": cutoffs,
                "cohorts": selected_results(split, cutoffs, groups),
                "brier_ece_saturation": {
                    name: _calibration_stats(y[idx], split[idx]) for name, idx in measurements.items()
                },
            }
        else:
            report["calibration"]["regime"] = {
                "status": "insufficient_calibration_rows",
                "class_counts": {
                    name: np.bincount(y[idx].astype(int), minlength=2).tolist()
                    for name, idx in regimes.items()
                },
            }
    return report
