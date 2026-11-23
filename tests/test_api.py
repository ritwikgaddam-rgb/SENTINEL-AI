"""Run from the project root with python -m unittest discover -s tests -v."""

import os
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack, closing
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import joblib
from fastapi.testclient import TestClient
import pandas as pd

from main import app
from url_features import extract_url_features
from url_reliability import url_model_values


MODELS = Path(__file__).resolve().parents[1] / "models"


class SentinelAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.url_model = joblib.load(MODELS / "url_phishing_model_v3.joblib")
        cls.original_url_model = joblib.load(MODELS / "url_phishing_model_v2.joblib")
        cls.original_url_model.n_jobs = 1
        cls.columns = joblib.load(MODELS / "url_features_v2.joblib")
        cls.email_model = joblib.load(MODELS / "email_phishing_model.joblib")

    def setUp(self):
        contexts = ExitStack()
        self.addCleanup(contexts.close)
        directory = contexts.enter_context(tempfile.TemporaryDirectory())
        self.db_path = Path(directory) / "history.sqlite3"
        contexts.enter_context(patch.dict(os.environ, SENTINELAI_DB_PATH=str(self.db_path)))
        self.client = contexts.enter_context(TestClient(app))

    def post_scan(self, path, data):
        response = self.client.post(path, json=data)
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_startup_health_and_empty_history(self):
        self.assertEqual(self.client.get("/health").json()["status"], "ok")
        history = self.client.get("/history").json()
        self.assertEqual(history["items"], [])
        for key in ("total", "total_scans", "phishing_detections", "privacy_matches"):
            self.assertEqual(history[key], 0)

    def test_local_frontend_origin_can_post(self):
        origin = "http://127.0.0.1:5173"
        preflight = self.client.options("/scan/email", headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type",
        })
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight.headers["access-control-allow-origin"], origin)

    def test_url_preserves_feature_order_and_uses_class_zero_for_phishing(self):
        self.assertEqual(list(self.url_model.feature_names_in_), list(self.columns))
        self.assertIn("NoOfDegitsInURL", self.columns)
        for url, expected in (
            ("https://en.wikipedia.org/wiki/Internet?oldid=123&view=single", "Legitimate"),
            ("https://www.flipkart.com.example.invalid/s?k=headphones", "Phishing"),
            ("http://192.168.1.1/login", "Phishing"),
        ):
            with self.subTest(url=url):
                features = extract_url_features(url)[self.columns]
                # A prediction must work offline, even for a hostname.
                with patch("socket.getaddrinfo", side_effect=AssertionError("unexpected DNS lookup")):
                    result = self.post_scan("/scan/url", {"url": url})
                model_input = pd.DataFrame([url_model_values(url)], columns=self.columns)
                index = list(self.url_model.classes_).index(0)
                self.assertEqual(result["prediction"], expected)
                self.assertAlmostEqual(result["phishing_probability"], self.url_model.predict_proba(model_input)[0, index])
                self.assertEqual(result["features"], features.iloc[0].to_dict())

        wiki = self.post_scan("/scan/url", {"url": "https://ext.en.wikipedia.org/wiki/Internet?a=1&b=2"})
        observed = wiki["url_analysis"]["observations"]
        self.assertEqual(observed["query_field_count"], 2)
        self.assertEqual(observed["subdomain_count_estimate"], 2)
        self.assertTrue(observed["uses_https"])

    def test_legitimate_url_variants_no_longer_generate_certain_alerts(self):
        examples = (
            "https://www.flipkart.com/",
            "https://www.flipkart.com/search?q=notebooks",
            "https://www.amazon.in/s?k=notebooks",
            "https://www.amazon.com/dp/B0C5R9BYTK?th=1&psc=1",
            "https://www.youtube.com/results?search_query=interview",
        )
        index = list(self.original_url_model.classes_).index(0)
        for url in examples:
            with self.subTest(url=url):
                original = extract_url_features(url)[self.columns]
                self.assertAlmostEqual(self.original_url_model.predict_proba(original)[0, index], 1.0)
                result = self.post_scan("/scan/url", {"url": url})
                self.assertEqual(result["prediction"], "Insufficient information")
                self.assertIsNone(result["phishing_probability"])
                self.assertEqual(result["risk_level"], "Unrated")
                self.assertTrue(result["reason"])
        self.assertEqual(self.client.get("/history").json()["total"], 0)

        base = self.post_scan("/scan/url", {"url": "https://www.flipkart.com"})
        slash = self.post_scan("/scan/url", {"url": "https://www.flipkart.com/"})
        self.assertEqual(base["prediction"], slash["prediction"])
        self.assertEqual(base["phishing_probability"], slash["phishing_probability"])

    def test_email_matches_saved_pipeline_with_class_one_for_phishing(self):
        messages = [
            "The school garden meeting is on Friday at noon. Thanks for sending the notes.",
            "Your account has been suspended. Verify your password immediately to claim your free prize.",
        ]
        for message, expected in zip(messages, ("Legitimate", "Phishing")):
            with self.subTest(prediction=expected):
                result = self.post_scan("/scan/email", {"text": message})
                label = self.email_model.predict([message])[0]
                index = list(self.email_model.classes_).index(1)
                self.assertEqual(result["prediction"], expected)
                self.assertEqual(result["prediction"], "Phishing" if label == 1 else "Legitimate")
                self.assertAlmostEqual(result["phishing_probability"], self.email_model.predict_proba([message])[0, index], places=4)

    def test_email_abstains_on_sparse_model_evidence(self):
        index = list(self.email_model.classes_).index(1)
        self.assertAlmostEqual(self.email_model.predict_proba(["How are you"])[0, index], 0.7557129359)
        for text in ("How are you", "Hello", "😀 ?"):
            with self.subTest(text=text):
                result = self.post_scan("/scan/email", {"text": text})
                self.assertEqual(result["prediction"], "Insufficient information")
                self.assertEqual(result["risk_level"], "Unrated")
                self.assertIsNone(result["phishing_probability"])
                self.assertTrue(result["reason"])
        self.assertEqual(self.client.get("/history").json()["total"], 0)

    def test_email_analysis_counts_and_contributions_are_separate_from_the_score(self):
        message = "Your account have been suspended. Verify immediately and enter your password. Check teh page."
        result = self.post_scan("/scan/email", {"text": message})
        analysis = result["analysis"]
        self.assertGreaterEqual(analysis["grammar"]["grammar_issues"], 1)
        self.assertGreaterEqual(analysis["grammar"]["spelling_issues"], 1)
        self.assertIn("sensitive_request", {finding["code"] for finding in analysis["warning_signs"]})
        self.assertAlmostEqual(
            analysis["model_evidence"]["total_log_odds"],
            float(self.email_model.decision_function([message])[0]),
        )
        self.assertTrue(analysis["model_contributions"])
        unsupported = self.post_scan("/scan/email", {"text": message, "language": "fr"})
        self.assertEqual(unsupported["analysis"]["grammar"]["status"], "unsupported_language")
        self.assertIsNone(unsupported["analysis"]["grammar"]["total_issues"])
        self.assertEqual(unsupported["phishing_probability"], result["phishing_probability"])
        self.assertNotIn("model_contributions", self.client.get("/history").text)

    def test_native_messages_classification_is_local_and_does_not_write_history(self):
        sample = {"text": "The school garden meeting is on Friday at noon. Thanks for sending the notes."}
        remote = self.client.post("/classify/message", json=sample)
        self.assertEqual(remote.status_code, 403)
        # Reuse the running app lifespan and give this request a loopback client address.
        local = TestClient(app, client=("127.0.0.1", 49152))
        response = local.post("/classify/message", json=sample)
        self.assertEqual(response.status_code, 200, response.text)
        index = list(self.email_model.classes_).index(1)
        self.assertAlmostEqual(
            response.json()["phishing_probability"],
            self.email_model.predict_proba([sample["text"]])[0, index],
        )
        self.assertNotIn("analysis", response.json())
        insufficient = local.post("/classify/message", json={"text": "How are you"}).json()
        self.assertEqual(insufficient["prediction"], "Insufficient information")
        self.assertIsNone(insufficient["phishing_probability"])
        self.assertEqual(self.client.get("/history").json()["total_scans"], 0)

    def test_redaction_counts_repeated_matches_and_preserves_other_text(self):
        source = "a@example.org, ba@example.org, a@example.org. Call +91 9876543210. ID 2345-6789-0123."
        result = self.post_scan("/privacy/redact", {"text": source})
        self.assertEqual(result["redacted_text"], "[EMAIL], [EMAIL], [EMAIL]. Call [PHONE]. ID [AADHAAR].")
        self.assertEqual(result["counts"], {"emails": 3, "phone_numbers": 1, "aadhaar_numbers": 1})
        clean = "The meeting starts at noon."
        unchanged = self.post_scan("/privacy/redact", {"text": clean})
        self.assertEqual(unchanged["redacted_text"], clean)
        self.assertEqual(sum(unchanged["counts"].values()), 0)

    def test_history_pagination_filters_and_persistent_metadata(self):
        marker = "unique-scan-text"
        token = "synthetic-auth-token-34562"
        url = self.post_scan("/scan/url", {"url": f"https://en.wikipedia.org/wiki/Internet?token={token}"})
        email = self.post_scan("/scan/email", {"text": f"The school garden meeting is on Friday at noon. Thanks for sending the notes. {marker} {token}"})
        self.post_scan("/privacy/redact", {"text": f"{marker} test@example.org 9876543210"})
        page = self.client.get("/history", params={"limit": 1, "offset": 1}).json()
        self.assertEqual(page["total"], 3)
        self.assertEqual([row["scan_type"] for row in page["items"]], ["email"])
        history = self.client.get("/history", params={"scan_type": "privacy"}).json()
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["total_scans"], 3)
        self.assertEqual(history["phishing_detections"], sum(r["prediction"] == "Phishing" for r in (url, email)))
        self.assertEqual(history["privacy_matches"], 2)
        self.assertEqual(len(history["items"]), 1)
        item = history["items"][0]
        self.assertEqual(item["scan_type"], "privacy")
        self.assertGreater(item["id"], 0)
        self.assertTrue(item["risk_level"])
        self.assertTrue(item["findings"])
        self.assertIsNotNone(datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00")).tzinfo)
        # Open an independent connection so the check includes committed storage.
        self.assertTrue(self.db_path.is_file())
        with closing(sqlite3.connect(self.db_path)) as db:
            dump = "\n".join(db.iterdump())
            confidences = dict(db.execute("SELECT scan_type, confidence FROM scans"))
        for scan_type, result in (("URL", url), ("Email", email)):
            probability = result["phishing_probability"]
            predicted_probability = probability if result["prediction"] == "Phishing" else 1 - probability
            self.assertAlmostEqual(confidences[scan_type], 100 * predicted_probability)
        self.assertIsNone(confidences["Privacy"])
        self.assertIn(item["prediction"], dump)
        for raw in (marker, token, "example.org", "en.wikipedia.org", "9876543210"):
            self.assertNotIn(raw, dump)
            self.assertNotIn(raw, self.client.get("/history").text)

    def test_activity_window_is_seven_utc_dates(self):
        for day in ("-7 days", "-6 days", "now"):
            self.post_scan("/privacy/redact", {"text": "Class notes"})
            if day != "now":
                with closing(sqlite3.connect(self.db_path)) as db, db:
                    db.execute(
                        "UPDATE scans SET created_at = datetime('now', ?) WHERE id = (SELECT MAX(id) FROM scans)",
                        (day,),
                    )
        history = self.client.get("/history?scan_type=url").json()
        self.assertEqual(history["total"], 0)
        self.assertEqual(history["total_scans"], 3)
        self.assertEqual([day["count"] for day in history["daily_activity"]], [1, 1])

    def test_rejected_inputs_leave_history_empty(self):
        requests = [
            ("/scan/url", {"url": "ftp://example.org"}),
            ("/scan/url", {"url": "https://"}),
            ("/scan/url", {"url": "http://example.org:invalid"}),
            ("/scan/email", {"text": "\t "}),
            ("/privacy/redact", {}),
            ("/privacy/redact", {"text": "x" * 100001}),
        ]
        for path, body in requests:
            with self.subTest(path=path):
                self.assertEqual(self.client.post(path, json=body).status_code, 422)
        self.assertEqual(self.client.get("/history?scan_type=invalid").status_code, 422)
        self.assertEqual(self.client.get("/history").json()["total"], 0)

    def test_validation_messages_do_not_echo_submitted_text(self):
        text = "private@example.org " * 1100
        response = self.client.post("/privacy/redact", json={"text": text})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("private@example.org", response.text)

    def test_failed_history_write_returns_an_error(self):
        with patch("main.save_scan", side_effect=sqlite3.OperationalError("disk full")):
            response = self.client.post("/privacy/redact", json={"text": "Call 9876543210"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("9876543210", response.text)
        self.assertEqual(self.client.get("/history").json()["total"], 0)


if __name__ == "__main__":
    unittest.main()
