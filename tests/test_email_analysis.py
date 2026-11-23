import json
import math
import os
import unittest
from pathlib import Path
from unittest.mock import patch

import joblib
import requests

from email_analysis import analyze_email, check_grammar, explain_email_model, warning_signs


MODELS = Path(__file__).resolve().parents[1] / "models"


class EmailAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.model = joblib.load(MODELS / "email_phishing_model.joblib")

    def test_contributions_reproduce_pipeline_probability_and_polarity(self):
        text = "How are you"
        evidence, contributions = explain_email_model(text, self.model)
        classifier = self.model.named_steps["classifier"]
        vectorizer = self.model.named_steps["tfidf"]
        row = vectorizer.transform([text])
        expected = self.model.predict_proba([text])[0, list(classifier.classes_).index(1)]
        self.assertEqual(list(classifier.classes_), [0, 1])
        self.assertEqual(evidence["feature_count"], 5)
        self.assertAlmostEqual(evidence["intercept_log_odds"], classifier.intercept_[0])
        self.assertAlmostEqual(sum(item["contribution_log_odds"] for item in contributions), evidence["feature_log_odds"])
        self.assertAlmostEqual(1 / (1 + math.exp(-evidence["total_log_odds"])), expected)
        self.assertEqual(contributions[0]["feature"], "you")
        self.assertEqual({item["toward"] for item in contributions}, {"phishing", "legitimate"})
        for item in contributions:
            index = vectorizer.vocabulary_[item["feature"]]
            self.assertAlmostEqual(item["tfidf"], row[0, index])
            self.assertAlmostEqual(item["coefficient"], classifier.coef_[0, index])
            self.assertAlmostEqual(item["contribution_log_odds"], row[0, index] * classifier.coef_[0, index])

    def test_unrecognized_text_has_only_intercept(self):
        evidence, contributions = explain_email_model("zzqvxzzz", self.model)
        self.assertEqual(evidence["feature_count"], 0)
        self.assertEqual(contributions, [])
        self.assertEqual(evidence["total_log_odds"], evidence["intercept_log_odds"])

    def test_warning_indicators_are_observations_without_raw_link_or_dns(self):
        # The cues are isolated to test recognition, without following any links.
        example = "Cue examples: respond immediately. Enter your password. Transfer funds immediately. http://192.0.2.1/path"
        with patch("socket.getaddrinfo", side_effect=AssertionError("unexpected DNS lookup")):
            warnings = warning_signs(example)
        self.assertEqual({item["category"] for item in warnings}, {
            "urgency", "sensitive_information", "financial_pressure", "link_structure",
        })
        self.assertNotIn("192.0.2.1", json.dumps(warnings))
        self.assertTrue(all(example[item["offset"]:item["offset"] + item["length"]] for item in warnings))

    def test_ordinary_mentions_and_negated_requests_are_not_indicators(self):
        text = "Account notes and payment receipt. Please do not provide your password. Never share your OTP."
        self.assertEqual(warning_signs(text), [])

    @patch.dict(os.environ, {}, clear=True)
    def test_builtin_grammar_spelling_repetition_and_punctuation_are_local(self):
        text = "Your account have been suspended. We recieve the the notes !"
        with patch("email_analysis.requests.Session", side_effect=AssertionError("unexpected HTTP client")):
            result = analyze_email(text, self.model)
        grammar = result["grammar"]
        self.assertEqual(grammar["status"], "limited")
        self.assertEqual(grammar["total_issues"], 4)
        self.assertEqual([grammar[f"{kind}_issues"] for kind in ("grammar", "spelling", "repeated_word", "punctuation")], [1, 1, 1, 1])
        spans = [(text[issue["offset"]:issue["offset"] + issue["length"]], issue["suggestions"]) for issue in grammar["issues"]]
        self.assertEqual(spans, [("have", ["has"]), ("recieve", ["receive"]), ("the", []), (" ", [""])])
        self.assertEqual(result["warning_signs"], [])

    @patch.dict(os.environ, {}, clear=True)
    def test_standard_prose_addresses_and_links_are_not_marked(self):
        text = "We received the notes. The reference is https://example.org/recieve. Contact recieve@example.org."
        self.assertEqual(check_grammar(text)["issues"], [])

    @patch.dict(os.environ, {"SENTINELAI_LANGUAGETOOL_PORT": "8081"}, clear=True)
    def test_optional_grammar_service_is_loopback_only_and_deduplicated(self):
        text = "😀 recieve at person@example.org"
        match = {
            "offset": 3,
            "length": 7,
            "message": "Possible spelling error.",
            "rule": {"id": "SPELLING", "issueType": "misspelling"},
            "replacements": [{"value": "receive"}],
        }
        with patch("email_analysis.requests.Session") as session:
            client = session.return_value.__enter__.return_value
            response = client.post.return_value.__enter__.return_value
            response.status_code = 200
            address_match = {**match, "offset": 15, "length": 4}
            response.iter_content.return_value = [json.dumps({"matches": [match, match, address_match]}).encode()]
            result = check_grammar(text)
        self.assertFalse(client.trust_env)
        self.assertEqual(client.post.call_args.args[0], "http://127.0.0.1:8081/v2/check")
        self.assertFalse(client.post.call_args.kwargs["allow_redirects"])
        self.assertNotIn("person@example.org", client.post.call_args.kwargs["data"]["text"])
        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["spelling_issues"], 1)
        self.assertEqual(result["issues"][0]["offset"], 2)
        self.assertEqual(result["issues"][0]["suggestions"], ["receive"])

    @patch.dict(os.environ, {"SENTINELAI_LANGUAGETOOL_PORT": "8081"}, clear=True)
    def test_optional_service_cannot_return_an_oversized_grammar_payload(self):
        text = "A string with several words and lots of positions for synthetic findings."
        match = {
            "length": 1,
            "message": "😀" * 1000,
            "rule": {"id": "X" * 1000, "issueType": "grammar"},
            "replacements": [{"value": "😀" * 1000}, {"value": "😀" * 1000}],
        }
        matches = [{**match, "offset": index} for index in range(12)]
        with patch("email_analysis.requests.Session") as session:
            response = session.return_value.__enter__.return_value.post.return_value.__enter__.return_value
            response.status_code = 200
            response.iter_content.return_value = [json.dumps({"matches": matches}).encode()]
            result = check_grammar(text)
        self.assertEqual(result["total_issues"], 12)
        self.assertTrue(result["issues_truncated"])
        self.assertGreater(len(result["issues"]), 0)
        self.assertLessEqual(len(json.dumps(result, ensure_ascii=True)), 7500)

    @patch.dict(os.environ, {"SENTINELAI_LANGUAGETOOL_PORT": "8081"}, clear=True)
    def test_service_failure_and_unsupported_language_report_status(self):
        with patch("email_analysis.requests.Session", side_effect=requests.ConnectionError("local test")):
            result = check_grammar("We recieve the notes.")
        self.assertTrue(result["available"])
        self.assertEqual(result["status"], "limited")
        self.assertIn("unavailable", result["reason"])
        self.assertEqual(result["spelling_issues"], 1)
        with patch("email_analysis.requests.Session", side_effect=AssertionError("unexpected grammar request")):
            unknown = check_grammar("Hola, buenos días.", "es")
        self.assertEqual(unknown["status"], "unsupported_language")
        self.assertIsNone(unknown["total_issues"])

    @patch.dict(os.environ, {"SENTINELAI_LANGUAGETOOL_PORT": "https://example.org"}, clear=True)
    def test_non_loopback_configuration_never_connects(self):
        with patch("email_analysis.requests.Session", side_effect=AssertionError("unexpected HTTP client")):
            result = check_grammar("Please recieve the notes.")
        self.assertEqual(result["status"], "limited")
        self.assertEqual(result["spelling_issues"], 1)


if __name__ == "__main__":
    unittest.main()
