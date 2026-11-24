"""
Sentinel AI - SQLite Database Interface
Stores threat detections, scan history, privacy audits, and user preferences.
"""

import sqlite3
import os
import json
import re
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel_ai.db")

def get_db_connection():
    conn = sqlite3.connect(os.getenv("SENTINELAI_DB_PATH", DB_PATH), timeout=5)
    conn.row_factory = sqlite3.Row
    return conn

SCAN_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    target_preview TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    confidence REAL,
    markers_json TEXT,
    metadata_json TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("BEGIN IMMEDIATE")
    cursor.execute(SCAN_SCHEMA)
    if any(column["name"] == "confidence" and column["notnull"] for column in cursor.execute("PRAGMA table_info(scan_history)")):
        cursor.execute("ALTER TABLE scan_history RENAME TO scan_history_legacy")
        cursor.execute(SCAN_SCHEMA)
        cursor.execute("INSERT INTO scan_history SELECT * FROM scan_history_legacy")
        cursor.execute("DROP TABLE scan_history_legacy")

    # Table for Privacy Guard audits
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS privacy_audits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        context TEXT NOT NULL,             -- 'gmail_compose', 'manual_scan', 'clipboard'
        detected_counts_json TEXT NOT NULL,-- e.g. {"emails": 1, "phones": 2, "aadhaar": 1}
        redacted_count INTEGER DEFAULT 0,
        original_sample TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Table for Custom Settings
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Table for Whitelist / Trusted Domains
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS domain_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE NOT NULL,
        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Insert default settings if not exists
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('theme', 'cold')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('mode', 'dark')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('privacy_guard_enabled', 'true')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('auto_redact_aadhaar', 'true')")
    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('gmail_scanner_enabled', 'true')")

    # Insert standard trusted domains
    default_trusted = ['google.com', 'mail.google.com', 'github.com', 'microsoft.com', 'apple.com', 'wikipedia.org']
    for d in default_trusted:
        cursor.execute("INSERT OR IGNORE INTO domain_whitelist (domain) VALUES (?)", (d,))

    conn.commit()
    conn.close()

def log_scan(scan_type, target_preview, risk_level, confidence, markers, metadata=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (scan_type, target_preview, risk_level, confidence, markers_json, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        scan_type,
        f"{scan_type.capitalize()} assessment",
        risk_level,
        confidence,
        json.dumps([m["id"] for m in markers or [] if re.fullmatch(r"[a-z_]{1,50}", m.get("id", ""))]),
        "{}"
    ))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def log_privacy_audit(context, detected_counts, redacted_count, original_sample=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO privacy_audits (context, detected_counts_json, redacted_count, original_sample)
        VALUES (?, ?, ?, ?)
    """, (
        context,
        json.dumps(detected_counts),
        redacted_count,
        ""
    ))
    audit_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return audit_id

def get_recent_history(limit=20, offset=0, kind=None):
    if kind not in (None, "email", "url", "webpage"):
        raise ValueError("Unknown history type.")
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, scan_type, target_preview, risk_level, confidence, markers_json, created_at
        FROM scan_history
        WHERE (? IS NULL OR scan_type = ?)
        ORDER BY id DESC LIMIT ? OFFSET ?
    """, (kind, kind, limit, offset))
    rows = cursor.fetchall()
    history = []
    for r in rows:
        history.append({
            "id": r["id"],
            "scan_type": r["scan_type"],
            "target_preview": f"{r['scan_type'].capitalize()} assessment",
            "risk_level": r["risk_level"],
            "confidence": None,
            "legacy": r["confidence"] is not None,
            "markers": [],
            "created_at": r["created_at"]
        })
    conn.close()
    return history

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_history WHERE risk_level IN ('danger', 'suspicious')")
    threats_blocked = cursor.fetchone()[0]

    cursor.execute("SELECT COALESCE(SUM(redacted_count), 0) FROM privacy_audits")
    items_redacted = cursor.fetchone()[0]

    conn.close()
    return {
        "total_scans": total_scans,
        "threats_blocked": threats_blocked,
        "items_redacted": items_redacted
    }

def get_all_settings():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {r["key"]: r["value"] for r in cursor.fetchall()}
    conn.close()
    return settings

def update_setting(key, value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
    """, (key, str(value)))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Sentinel AI SQLite database initialized successfully at:", DB_PATH)
