"""Storage outages must not erase successful inference or expose private inputs."""
import json
import sqlite3
import unittest
from unittest.mock import patch

from backend import server


class OptionalStorageTests(unittest.TestCase):
    def test_history_and_collection_fail_independently(self):
        handler = object.__new__(server.SentinelAPIHandler)
        handler.headers = {}
        private = "fixture-only-private-value"
        for history, collection in ((True, False), (False, True), (True, True)):
            with self.subTest(history=history, collection=collection), patch.object(
                server, "log_scan", side_effect=sqlite3.OperationalError(private) if history else None
            ), patch.object(server.threats, "collect", return_value=7,
                            side_effect=OSError(private) if collection else None):
                result = handler.handle_post("/api/scan-email", {"text": "Please send your password.",
                                                                 "collect_sample": True})
                self.assertTrue(result["ml_evaluated"])
                self.assertEqual(result["risk_level"], "danger")
                self.assertEqual(result["persistence"], {"history": "unavailable" if history else "saved",
                                                         "collection": "unavailable" if collection else "saved"})
                self.assertNotIn(private, json.dumps(result))

    def test_inference_failure_is_separate(self):
        with patch.object(server, "email_model", return_value=None):
            result = server.predict_email_risk("The library opens tomorrow. Class is at noon.")
        self.assertFalse(result["ml_evaluated"])
        self.assertIsNone(result["risk_score"])
        self.assertEqual(result["assessment"], "Analysis unavailable")

    def test_privacy_audit_failure_still_returns_selected_edits(self):
        handler = object.__new__(server.SentinelAPIHandler)
        handler.headers = {}
        with patch.object(server, "log_privacy_audit", side_effect=sqlite3.OperationalError()):
            result = handler.handle_post("/api/privacy-redact", {"text": "Email: fixture@example.org"})
        self.assertIn("[EMAIL]", result["redacted_text"])
        self.assertEqual(result["persistence"]["history"], "unavailable")
