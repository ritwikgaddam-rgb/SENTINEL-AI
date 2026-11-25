"""Regression fixtures for the deployed email alert contract."""
import unittest

import numpy as np

from backend import server
from training.email_recall_study import Mail, choose_threshold, make_partitions

BENIGN = (
    "Hello.",
    "How are you doing today?",
    "Hey how are you what are you doing.",
    "Please send me the homework when you finish.",
    "Never share your password or OTP with anyone.",
    "I has completed my homework yesterday.",
    "Here is the Python documentation: https://docs.python.org/3/",
    "The science club meets in the library after school. Bring a notebook.",
    "The draft budget is ready. Could you check the totals before our meeting?",
    "For your safety, don't give anyone your verification code. Open your usual app to review the alert.",
)


class EmailAlertRegressionTests(unittest.TestCase):
    def test_benign_messages_remain_free_of_alerts(self):
        for body in BENIGN:
            with self.subTest(body=body):
                result = server.predict_email_risk(body)
                self.assertTrue(result["ml_evaluated"])
                self.assertIn(result["display_level"], {"safe", "unknown"})
                if result["display_level"] == "unknown":
                    self.assertIsNone(result["safety_score"])

    def test_original_model_and_structural_evidence_have_separate_outputs(self):
        result = server.predict_email_risk(
            "Please reply with your password to confirm the account.",
            "Example Support <notices@example.org>",
            [{"url": "https://example.net/review", "label": "https://example.org/review"}],
            subject="Final notice to verify your account", reply_to="audit@example.net",
        )
        self.assertEqual(result["display_level"], "danger")
        self.assertTrue(result["ml_evaluated"])
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertAlmostEqual(result["risk_score"] + result["safety_score"], 100)
        self.assertTrue({"credential_request", "reply_domain_mismatch", "link_deception"}
                        <= {m["id"] for m in result["markers"]})
        self.assertEqual(result["links"][0]["assessment"], "Suspicious")
        self.assertEqual(server.legacy_scan_response(result)["risk_level"], result["display_level"])


class EmailEvaluationTests(unittest.TestCase):
    def test_threshold_respects_false_positive_budget_and_short_mail(self):
        labels = np.array([0] * 20 + [1, 1, 1])
        scores = np.array([0.1] * 18 + [0.5, 0.8, 0.4, 0.9, 0.95])
        self.assertEqual(choose_threshold(labels, scores, np.array([0.55])), 0.8)

    def test_related_holdout_template_is_removed_from_training(self):
        template = "We have reserved the small meeting room for our training event"
        holdout = Mail(template + " on Monday morning.", 0, "held out")
        relative = Mail(template + " on Wednesday afternoon.", 0, "fit")
        unique = Mail("Your student council vote was counted.", 0, "fit")
        rows, counts = make_partitions({"fit": [relative, unique], "validation": [],
                                        "manual": [holdout], "real": []})
        self.assertEqual([mail for mail, _ in rows["fit"]], [unique])
        self.assertEqual([mail for mail, _ in rows["manual"]], [holdout])
        self.assertEqual(counts["fit"]["cross_partition_template"], 1)
