"""Tests for SentinelAI's SQLite helpers. Every test uses a temporary file."""

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime
from pathlib import Path

from database import (
    clear_history,
    delete_scan,
    get_scan_by_id,
    get_scan_count,
    get_scan_history,
    init_db,
    save_scan,
)


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SCANS = [
    {"created_at": "2026-11-17T09:00:00Z", "scan_type": "Email", "prediction": "phishing", "confidence": 94.0},
    {"created_at": "2026-11-17T10:15:00Z", "scan_type": "URL", "prediction": "Safe", "confidence": 98.0},
    {"created_at": "2026-11-17T11:30:00Z", "scan_type": "URL", "prediction": "phishing", "confidence": 89.0},
    {"created_at": "2026-11-17T12:45:00Z", "scan_type": "Email", "prediction": "Safe", "confidence": 96.0},
    {"created_at": "2026-11-17T14:00:00Z", "scan_type": "Email", "prediction": "phishing", "confidence": 91.0},
    {"created_at": "2026-11-17T15:20:00Z", "scan_type": "URL", "prediction": "Safe", "confidence": 95.0},
]
PRIVATE_EMAIL = "student@example.org"
PRIVATE_TOKEN = "unique-test-token"
PRIVATE_PHONE = "9876543210"
PRIVATE_PREVIEW = f"Email body for {PRIVATE_EMAIL}. Phone {PRIVATE_PHONE}. Token {PRIVATE_TOKEN}."


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "sentinelai.db"
        init_db(self.path)

    def save_samples(self):
        return [save_scan(scan, db_path=self.path) for scan in SAMPLE_SCANS]

    def test_database_initializes_empty(self):
        self.assertTrue(self.path.is_file())
        self.assertEqual(get_scan_count(db_path=self.path), 0)

    def test_save_and_retrieve_unique_ids(self):
        ids = self.save_samples()
        self.assertEqual(len(set(ids)), len(SAMPLE_SCANS))
        self.assertEqual(get_scan_count(db_path=self.path), len(SAMPLE_SCANS))

        first = get_scan_by_id(ids[0], db_path=self.path)
        self.assertEqual(first["scan_type"], "Email")
        self.assertEqual(first["prediction"], "Phishing")
        self.assertEqual(first["confidence"], 94.0)
        self.assertIsInstance(first["input_preview"], str)
        self.assertEqual(get_scan_by_id(ids[1], db_path=self.path)["prediction"], "Legitimate")

        for invalid_id in (99999, -1, "sentence", True):
            with self.subTest(scan_id=invalid_id):
                self.assertIsNone(get_scan_by_id(invalid_id, db_path=self.path))

    def test_sort_filter_search_and_paginate(self):
        ids = self.save_samples()
        newest_first = get_scan_history(db_path=self.path)
        self.assertEqual([scan["id"] for scan in newest_first], ids[::-1])

        by_confidence = get_scan_history(sort_by="confidence", order="DESC", db_path=self.path)
        scores = [scan["confidence"] for scan in by_confidence]
        self.assertEqual(scores, sorted(scores, reverse=True))

        phishing = get_scan_history(prediction="Phishing", db_path=self.path)
        self.assertEqual([scan["id"] for scan in phishing], [ids[4], ids[2], ids[0]])
        urls = get_scan_history(scan_type="URL", db_path=self.path)
        self.assertEqual([scan["id"] for scan in urls], [ids[5], ids[2], ids[1]])
        search = get_scan_history(search_query="legitimate", db_path=self.path)
        self.assertEqual([scan["id"] for scan in search], [ids[5], ids[3], ids[1]])
        page = get_scan_history(scan_type="URL", limit=1, offset=1, db_path=self.path)
        self.assertEqual([scan["id"] for scan in page], [ids[2]])

    def test_data_persists_in_a_new_python_process(self):
        ids = self.save_samples()
        code = """
import sys
from database import get_scan_by_id, get_scan_count

db_path, scan_id = sys.argv[1:]
assert get_scan_count(db_path=db_path) == 6
assert get_scan_by_id(int(scan_id), db_path=db_path)["prediction"] == "Phishing"
"""
        subprocess.run([sys.executable, "-c", code, str(self.path), str(ids[0])], cwd=ROOT, check=True)

    def test_delete_one_scan_and_clear_history(self):
        ids = self.save_samples()
        self.assertTrue(delete_scan(ids[1], db_path=self.path))
        self.assertFalse(delete_scan(ids[1], db_path=self.path))
        self.assertIsNone(get_scan_by_id(ids[1], db_path=self.path))
        self.assertEqual(get_scan_count(db_path=self.path), 5)
        self.assertEqual(clear_history(db_path=self.path), 5)
        self.assertEqual(get_scan_count(db_path=self.path), 0)
        self.assertEqual(get_scan_history(db_path=self.path), [])

    def test_raw_previews_stay_out_of_storage_and_search(self):
        save_scan({**SAMPLE_SCANS[0], "input_preview": PRIVATE_PREVIEW}, db_path=self.path)
        save_scan({
            "scan_type": "URL",
            "prediction": "Legitimate",
            "confidence": 90,
            "input_preview": f"https://example.org/?token={PRIVATE_TOKEN}",
        }, db_path=self.path)
        privacy_id = save_scan({
            "scan_type": "Privacy",
            "prediction": "Redacted",
            "confidence": None,
            "privacy_matches": 3,
            "input_preview": PRIVATE_PREVIEW,
        }, db_path=self.path)

        privacy = get_scan_by_id(privacy_id, db_path=self.path)
        self.assertEqual(privacy["privacy_matches"], 3)
        self.assertIsNone(privacy["confidence"])
        with closing(sqlite3.connect(self.path)) as connection:
            dump = "\n".join(connection.iterdump())
        for marker in (PRIVATE_EMAIL, PRIVATE_TOKEN, PRIVATE_PHONE):
            with self.subTest(marker=marker):
                self.assertNotIn(marker, dump)
                self.assertEqual(get_scan_history(search_query=marker, db_path=self.path), [])

    def test_confidence_rejects_invalid_values(self):
        for confidence in (-1, 101, float("nan"), True, "94"):
            with self.subTest(confidence=confidence):
                with self.assertRaises(ValueError):
                    save_scan({**SAMPLE_SCANS[0], "confidence": confidence}, db_path=self.path)
        self.assertEqual(get_scan_count(db_path=self.path), 0)


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "legacy.sqlite3"

    def test_existing_app_history_survives_migration(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    privacy_matches INTEGER NOT NULL DEFAULT 0
                )
            """)
            connection.executemany("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)", [
                (4, "2026-11-17T09:00:00.120Z", "url", "Phishing", "High", "URL model · 91.2% phishing probability", 0),
                (9, "2026-11-17T10:15:00.240Z", "email", "Legitimate", "Low", "Email model · 2.5% phishing probability", 0),
                (11, "2026-11-17T11:30:00.360Z", "privacy", "Redacted", "Medium", "3 pattern matches", 3),
                (12, "2026-11-17T12:00:00.480Z", "email", "Legitimate", "Low", PRIVATE_PREVIEW, 0),
            ])

        init_db(self.path)
        init_db(self.path)
        url, email, privacy, unknown_score = get_scan_history(sort_by="id", order="ASC", db_path=self.path)
        self.assertEqual([scan["id"] for scan in (url, email, privacy, unknown_score)], [4, 9, 11, 12])
        self.assertEqual([scan["scan_type"] for scan in (url, email, privacy)], ["URL", "Email", "Privacy"])
        timestamps = [datetime.fromisoformat(scan["created_at"]) for scan in (url, email, privacy)]
        self.assertEqual(timestamps, [
            datetime.fromisoformat("2026-11-17T09:00:00.120Z"),
            datetime.fromisoformat("2026-11-17T10:15:00.240Z"),
            datetime.fromisoformat("2026-11-17T11:30:00.360Z"),
        ])
        self.assertAlmostEqual(url["confidence"], 91.2)
        self.assertAlmostEqual(email["confidence"], 97.5)
        self.assertEqual(privacy["prediction"], "Redacted")
        self.assertEqual(privacy["privacy_matches"], 3)
        self.assertIsNone(privacy["confidence"])
        self.assertIsNone(unknown_score["confidence"])
        self.assertNotIn(PRIVATE_TOKEN, unknown_score["input_preview"])
        self.assertGreater(save_scan(SAMPLE_SCANS[0], db_path=self.path), 12)

    def test_teammate_history_migrates_labels_scores_and_safe_metadata(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY,
                    scan_type TEXT NOT NULL CHECK (scan_type IN ('Email', 'URL')),
                    input_preview TEXT NOT NULL,
                    prediction TEXT NOT NULL CHECK (prediction IN ('Safe', 'phishing')),
                    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 100.0),
                    created_at TEXT NOT NULL
                )
            """)
            connection.executescript("""
                CREATE INDEX idx_scans_created_at ON scans(created_at);
                CREATE INDEX idx_scans_scan_type ON scans(scan_type);
            """)
            connection.executemany("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)", [
                (5, "Email", PRIVATE_PREVIEW, "phishing", 0.94, "2026-11-17T09:00:00Z"),
                (8, "URL", f"https://example.org/?token={PRIVATE_TOKEN}", "Safe", 98, "2026-11-17T10:15:00Z"),
            ])

        init_db(self.path)
        init_db(self.path)
        email, url = get_scan_history(sort_by="id", order="ASC", db_path=self.path)
        self.assertEqual((email["id"], email["created_at"], email["prediction"]), (5, "2026-11-17T09:00:00Z", "Phishing"))
        self.assertEqual((url["id"], url["created_at"], url["prediction"]), (8, "2026-11-17T10:15:00Z", "Legitimate"))
        self.assertAlmostEqual(email["confidence"], 94.0)
        self.assertAlmostEqual(url["confidence"], 98.0)
        with closing(sqlite3.connect(self.path)) as connection:
            dump = "\n".join(connection.iterdump())
        for marker in (PRIVATE_EMAIL, PRIVATE_TOKEN, PRIVATE_PHONE):
            self.assertNotIn(marker, dump)

    def test_failed_migration_rolls_back_schema_and_rows(self):
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("""
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY,
                    scan_type TEXT NOT NULL,
                    input_preview TEXT NOT NULL,
                    prediction TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            connection.execute("CREATE INDEX idx_scans_created_at ON scans(created_at)")
            connection.executemany("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)", [
                (1, "Email", "First legacy preview", "phishing", 0.94, "2026-11-17T09:00:00Z"),
                (2, "URL", "Second legacy preview", "Safe", 0.98, "invalid timestamp"),
            ])
            original_database = list(connection.iterdump())

        with self.assertRaisesRegex(ValueError, "created_at"):
            init_db(self.path)

        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(list(connection.iterdump()), original_database)
            self.assertIsNone(connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'scans_legacy'"
            ).fetchone())


if __name__ == "__main__":
    unittest.main()
