"""Regression fixtures contain placeholder codes and reserved example hosts only."""

import json
from pathlib import Path
import unittest

from backend.server import predict_email_risk

CASES = json.loads((Path(__file__).parent / "fixtures/credential_context.json").read_text())


class CredentialContextTests(unittest.TestCase):
    def test_context_screening(self):
        for case in CASES:
            with self.subTest(case=case["case"]):
                result = predict_email_risk(
                    **{k: case[k] for k in ("text", "subject", "sender", "reply_to", "links") if k in case}
                )
                self.assertEqual(result["display_level"], case["expected"])
                self.assertEqual(result["score_kind"], "screening_index")
                self.assertEqual(result["sender"]["authentication"], "unavailable")
                ids = {m["id"] for m in result["markers"]}
                if "marker" in case:
                    self.assertIn(case["marker"], ids)
                if case["expected"] != "danger":
                    self.assertNotIn("credential_request", ids)
                if case["expected"] == "unknown":
                    self.assertIsNone(result["safety_score"])
        self.assertAlmostEqual(
            predict_email_risk(CASES[0]["text"])["model_observation"]["phishing_probability"],
            0.44303772369383343,
        )
