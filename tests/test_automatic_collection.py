"""Automatic threat collection against disposable SQLite databases."""
from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import server
from backend.assessments import PAGE_FEATURES


class AutomaticCollectionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        self.history = self.path / "history.db"
        self.threats = self.path / "threats.db"
        env = patch.dict("os.environ", SENTINELAI_DB_PATH=str(self.history), SENTINELAI_THREATS_PATH=str(self.threats))
        env.start()
        self.addCleanup(env.stop)
        handler = object.__new__(server.SentinelAPIHandler)
        handler.headers = {}
        self.handler = handler
        self.post = handler.handle_post
        server.init_db()

    def test_backwards_migration_preserves_reviews_and_requires_new_opt_in(self):
        with closing(sqlite3.connect(self.threats)) as db, db:
            db.executescript(server.threats.SCHEMA)
            db.execute("UPDATE collection SET enabled = 1, retention_days = 30")
            db.execute("""INSERT INTO samples(kind,fingerprint,features,assessment,version,status,label)
                          VALUES ('email','fixture-fingerprint','{}','suspicious','features-v1','approved','legitimate')""")
        server.threats.init_db()
        self.assertEqual(server.threats.settings(), {
            "enabled": False, "retention_days": 30, "sanitized_text_enabled": False,
        })
        self.assertEqual(server.threats.list_samples(approved_only=True)[0]["label"], "legitimate")
        self.assertIsNone(server.threats.list_samples()["samples"][0]["risk_index"])
        server.threats.settings(True)
        server.threats.init_db()
        self.assertTrue(server.threats.settings()["enabled"])

    def test_only_eligible_scans_are_collected_and_metadata_is_bounded(self):
        server.threats.init_db()
        self.assertTrue(self.history.is_file() and self.threats.is_file())
        email = {"subject": "Private-canary-subject", "text": "Please reply with your password. Fixture: mail-canary@example.org"}
        self.assertIsNone(self.post("/api/scan-email", email)["sample_id"])
        server.threats.settings(True)
        self.assertNotIn("sample_id", self.post("/api/scan-email", email | {"preview": True}))
        self.assertIsNone(self.post("/api/scan-email", {"text": "Class meets tomorrow near the school library at noon."})["sample_id"])
        self.assertIsInstance(self.post("/api/scan-email", email)["sample_id"], int)
        self.assertIsNone(self.post("/api/v2/scan-email", email)["sample_id"])
        self.assertIsInstance(self.post("/api/scan-email", email | {"text": email["text"] + " Different message."})["sample_id"], int)
        url = "https://account.example@elsewhere.example/private-canary-path?token=first-canary"
        self.assertIsInstance(self.post("/api/scan-url", {"url": url})["sample_id"], int)
        self.assertIsNone(self.post("/api/v2/scan-url", {"url": url.replace("first-canary", "second-canary")})["sample_id"])
        page = dict.fromkeys(PAGE_FEATURES, 0) | {"infection_claim": 1, "support_request": 1, "blocking_overlay": 1}
        self.assertIsInstance(self.post("/api/scan-page", {"url": url, "observations": page})["sample_id"], int)
        server.threats.settings(False)
        self.assertIsNone(self.post("/api/scan-email", email | {"subject": "Another canary subject"})["sample_id"])
        data = server.threats.list_samples()
        self.assertEqual(data["counts"], {"pending": 4})
        self.assertEqual(data["label_counts"], {})
        self.assertEqual({r["kind"] for r in data["samples"]}, {"url", "email", "webpage"})
        for row in data["samples"]:
            self.assertIsNone(row["label"])
            self.assertIsNone(row["sanitized_body"])
            self.assertGreater(row["risk_index"], 0)
            self.assertTrue(row["indicators"])
            self.assertTrue(row["model_version"])
        for path in (self.history, self.threats):
            with closing(sqlite3.connect(path)) as db:
                dump = "\n".join(db.iterdump())
            for secret in ("Private-canary-subject", "mail-canary@example.org", "canary-path", "first-canary", "second-canary"):
                self.assertNotIn(secret, dump)

    def test_gmail_never_adds_masked_text_even_with_text_setting(self):
        server.threats.settings(True, sanitized_text_enabled=True)
        self.handler.headers = {"Origin": "https://mail.google.com"}
        text = "Please reply with your password to confirm the security review for the account."
        result = self.post("/api/scan-email", {"text": text, "collect_sample": True, "collect_text": True})
        self.assertEqual(result["persistence"]["collection"], "saved")
        self.assertNotIn("text_sample_id", result)
        sample, = server.threats.list_samples()["samples"]
        self.assertIsNone(sample["sanitized_body"])

    def test_store_paths_cannot_point_to_the_same_database(self):
        with patch.dict("os.environ", SENTINELAI_THREATS_PATH=str(self.history)):
            result = self.post("/api/scan-email", {"text": "Please reply with the verification code."})
            self.assertEqual(result["risk_level"], "danger")
            self.assertEqual(result["persistence"], {"history": "saved", "collection": "unavailable"})
        with closing(sqlite3.connect(self.history)) as db:
            self.assertNotIn("CREATE TABLE samples", "\n".join(db.iterdump()))

    def test_writer_lock_does_not_erase_inference_and_next_scan_can_collect(self):
        server.threats.settings(True)
        payload = {"text": "Please send your password for the fictional rehearsal."}
        with closing(sqlite3.connect(self.threats)) as lock:
            lock.execute("BEGIN IMMEDIATE")
            result = self.post("/api/scan-email", payload)
            self.assertTrue(result["ml_evaluated"])
            self.assertEqual(result["persistence"]["collection"], "unavailable")
        self.assertEqual(self.post("/api/scan-email", payload)["persistence"]["collection"], "saved")
