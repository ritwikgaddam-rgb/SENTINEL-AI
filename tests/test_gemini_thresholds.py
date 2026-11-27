"""Synthetic checks for validation-only calibration and operating points."""

import json
import unittest

import numpy as np

from training.gemini_thresholds import _operating_point, evaluate_operating_points, sweep_frozen_probabilities


class GeminiThresholdsTests(unittest.TestCase):
    def setUp(self):
        self.labels = np.array([0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1])
        self.logits = np.array([-2, -1, 1, 2, -2, -1, 0, 2, 1.5, -0.5, -1, 0.8, np.nan])
        self.ix = {
            "cal": np.arange(4),
            "tune": np.arange(4, 8),
            "guard": [8],
            "validation_auth": [9],
            "manual": [10, 11, 12],
        }

    def test_inclusive_empirical_budget_with_exact_guard_boundary(self):
        labels = np.array([0] * 100 + [1, 1])
        values = np.array([0.1] * 99 + [0.91, 0.86, 0.94])
        threshold = _operating_point(labels, values, 0.01, [(np.array([0.85]), 0.0)])
        self.assertEqual(threshold, 0.85)
        self.assertEqual(np.sum(values[labels == 0] > threshold), 1)
        self.assertEqual(np.sum(values[labels == 1] > threshold), 2)

    def test_category_and_old_guard_are_distinct_constraints(self):
        report = evaluate_operating_points(
            self.logits,
            self.labels,
            self.ix,
            category_sets={"authentication": [9]},
            sweep_cohorts=["manual"],
            min_category_rows=1,
        )
        points = report["sweeps"]["tune"]
        self.assertLess(points["category"]["0.025"]["threshold"], points["zero_guard"]["0.025"]["threshold"])
        self.assertEqual(points["category"]["0.025"]["categories"]["authentication"]["fp"], 0)
        self.assertEqual(
            points["category"]["0.025"]["categories"]["authentication"][
                "allowed_false_positives_at_category_cap"
            ],
            0,
        )
        self.assertGreater(points["category"]["0.025"]["categories"]["authentication"]["fpr_ci95"][1], 0.5)
        self.assertEqual(points["category"]["0.025"]["cohorts"]["manual"]["abstentions"], 1)
        selected = report["selected"]
        self.assertGreaterEqual(selected["thresholds"]["high_risk"], selected["thresholds"]["caution"])
        self.assertEqual(selected["cohorts"]["manual"]["display_by_label"]["phishing"]["unknown"], 1)
        self.assertGreaterEqual(selected["cohorts"]["manual"]["alerts"]["fn"], 1)
        self.assertNotIn("validation_auth", selected["cohorts"])
        json.dumps(report, allow_nan=False)

    def test_tiny_category_remains_in_strict_sensitivity_comparison(self):
        report = evaluate_operating_points(self.logits, self.labels, self.ix, category_sets={"auth": [9]})
        self.assertEqual(report["category_constraints"]["exploratory_only"], ["auth"])
        self.assertEqual(report["selected"]["constraint"], "unconstrained")
        point = report["sweeps"]["tune"]["category_all"]["0.025"]
        self.assertEqual(point["categories"]["auth"]["fp"], 0)

    def test_held_out_labels_do_not_affect_thresholds_or_calibrators(self):
        report = evaluate_operating_points(self.logits, self.labels, self.ix)
        altered = self.labels.copy()
        altered[self.ix["manual"]] = 1 - altered[self.ix["manual"]]
        replay = evaluate_operating_points(self.logits, altered, self.ix)
        self.assertEqual(report["selected"]["thresholds"], replay["selected"]["thresholds"])
        self.assertEqual(report["calibration"]["global"], replay["calibration"]["global"])
        self.assertNotEqual(report["selected"]["cohorts"]["manual"], replay["selected"]["cohorts"]["manual"])

    def test_category_constraint_rejects_evaluation_overlap(self):
        with self.assertRaisesRegex(ValueError, "overlaps calibration or threshold selection"):
            evaluate_operating_points(
                self.logits, self.labels, self.ix, category_sets={"authentication": [10]}
            )

    def test_use_original_probabilities_and_two_validation_pools(self):
        probability = np.array([0.1, 0.2, 0.8, 0.9, 0.1, 0.3, 0.6, 0.95, 1, 0, 0.9, 0.99999, np.nan])
        ix = dict(self.ix, expanded_tune=[4, 5, 6, 7, 10, 11], prior_tune=[10, 11], manual=[12])
        ix.pop("tune")
        report = evaluate_operating_points(
            probability,
            self.labels,
            ix,
            tune="expanded_tune",
            old_validation="prior_tune",
            probability_input=True,
            calibration_weights=np.arange(len(probability)) + 1,
        )
        self.assertIn("prior_tune", report["sweeps"])
        self.assertLess(report["calibration"]["global"]["effective_n"], 4)
        self.assertEqual(report["calibration"]["cohorts"]["prior_tune"]["raw"]["above_0_999"], 1)
        self.assertAlmostEqual(report["calibration"]["cohorts"]["guard"]["raw"]["brier"], 1)
        self.assertEqual(report["calibration"]["cohorts"]["manual"]["calibrated"]["n"], 0)

    def test_frozen_checkpoint_keeps_checkpoint_probabilities(self):
        report = sweep_frozen_probabilities([0, 0, 1, 1], [0.12, 0.26, 0.46, 0.93], [0.25, 0.81])
        self.assertEqual(report["at_half"]["guard"]["fp"], 1)
        guarded = report["sweeps"]["zero_guard"]["0.025"]
        self.assertEqual(guarded["threshold"], 0.81)
        self.assertEqual(guarded["validation"]["tp"], 1)
        self.assertEqual(guarded["guard"]["fp"], 0)
        self.assertEqual(report["curves"]["auroc_scored"], 1)

    def test_split_calibration_uses_only_regimes_with_both_classes(self):
        labels = np.tile([0, 1], 90)
        sparse = np.r_[np.ones(80), np.zeros(80), np.ones(20)].astype(bool)
        scores = np.where(sparse, 1.5, -1.5) + labels * 2
        ix = {"cal": np.arange(160), "tune": np.arange(160, 170), "manual": np.arange(170, 180)}
        report = evaluate_operating_points(scores, labels, ix, sparse_regime=sparse)
        self.assertEqual(report["calibration"]["regime"]["fits"]["sparse"]["n"], 80)
        self.assertEqual(report["calibration"]["regime"]["fits"]["dense"]["n"], 80)
        insufficient = evaluate_operating_points(scores, labels, ix, sparse_regime=labels.astype(bool))
        self.assertEqual(insufficient["calibration"]["regime"]["status"], "insufficient_calibration_rows")
