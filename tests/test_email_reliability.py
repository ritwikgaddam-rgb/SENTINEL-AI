import unittest
from pathlib import Path

import joblib

from email_reliability import assess_email


class EmailReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.model = joblib.load(root / "models/email_phishing_model.joblib")

    def test_greetings_abstain_even_when_raw_phishing_score_is_high(self):
        for greeting in ("How are you", "Hello", "Hey", "How are you today?"):
            with self.subTest(greeting=greeting):
                probabilities = self.model.predict_proba([greeting])[0]
                self.assertGreater(probabilities[list(self.model.classes_).index(1)], 0.5)
                result = assess_email(self.model, greeting)
                self.assertEqual(result["prediction"], "Insufficient information")
                self.assertEqual(result["risk_level"], "Unrated")
                self.assertIsNone(result["phishing_probability"])
                self.assertIn("reason", result)

    def test_unrecognized_text_does_not_inherit_intercept_as_a_prediction(self):
        result = assess_email(self.model, "🤷 !?! 𝝅")
        self.assertEqual(result["prediction"], "Insufficient information")
        self.assertEqual(result["evidence_policy"]["effective_features"], 0.0)

    def test_repeating_the_same_term_leaves_evidence_sparse(self):
        result = assess_email(self.model, "hello " * 100)
        self.assertEqual(result["prediction"], "Insufficient information")

    def test_full_text_preserves_the_saved_score(self):
        examples = {
            "The school garden meeting is on Friday at noon. Thanks for sending the notes.": "Legitimate",
            "Your account has been suspended. Verify your password immediately to claim your free prize.": "Phishing",
        }
        for text, prediction in examples.items():
            with self.subTest(prediction=prediction):
                row = self.model.named_steps["tfidf"].transform([text])
                result = assess_email(self.model, text, feature_row=row)
                self.assertEqual(result["prediction"], prediction)
                self.assertAlmostEqual(result["phishing_probability"], self.model.predict_proba([text])[0, 1])
