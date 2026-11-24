"""Opt-in local review queue for numeric features and tightly masked text."""

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import json
import os
import re
import sqlite3

import privacy_detector

TYPES = {"email", "url", "webpage"}
LABELS = {"phishing", "legitimate"}
STATUSES = {"pending", "confirmed_phishing", "confirmed_legitimate", "uncertain", "rejected", "approved"}
TEXT_VERSION = "masked-terms-v1"
TRAINING_TERMS = frozenset("""
    access account activate alert appointment approval attachment attendance agenda bank billing book
    cancelled card certificate charge classroom click closed code confirm confirmatory confirmation
    credential credentials deadline deactivate delivery denied device document download enrollment expire
    expires fee follow form fraud fraudulent gift homework identity immediate immediately information
    invoice lesson library limited link locked login mail mailbox meeting message minutes never notice
    notification official open order password passphrase pay payment phone please prize purchase
    receipt refund reminder reply request requested reset review reward schedule school security send
    service session share sign signing statement submit support suspended team token tomorrow transfer
    unexpected update urgent verification verify warning webinar within
""".split())

SCHEMA = """
CREATE TABLE IF NOT EXISTS collection (
    id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL DEFAULT 0,
    retention_days INTEGER NOT NULL DEFAULT 90
);
INSERT OR IGNORE INTO collection (id) VALUES (1);
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind TEXT NOT NULL CHECK (kind IN ('email','url','webpage')),
    fingerprint TEXT NOT NULL UNIQUE, features TEXT NOT NULL,
    assessment TEXT NOT NULL CHECK (assessment IN ('suspicious','neutral','uncertain')),
    version TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
    label TEXT CHECK (label IN ('legitimate','phishing')),
    CHECK (status != 'approved' OR label IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS text_policy (
    id INTEGER PRIMARY KEY CHECK (id = 1), enabled INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO text_policy (id) VALUES (1);
CREATE TABLE IF NOT EXISTS sanitized_samples (
    sample_id INTEGER PRIMARY KEY REFERENCES samples(id) ON DELETE CASCADE,
    subject TEXT NOT NULL, body TEXT NOT NULL
);
"""


@contextmanager
def connection():
    default = Path(__file__).with_name("sentinel_threats.db")
    path = Path(os.getenv("SENTINELAI_THREATS_PATH", str(default)))
    db = sqlite3.connect(path, timeout=5)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA secure_delete = ON")
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(SCHEMA)
        with db:
            yield db
    finally:
        db.close()


def settings(enabled=None, retention_days=None, sanitized_text_enabled=None):
    with connection() as db:
        if enabled is not None:
            if type(enabled) is not bool:
                raise ValueError("Collection must be explicitly enabled or disabled.")
            db.execute("UPDATE collection SET enabled = ? WHERE id = 1", (enabled,))
        if retention_days is not None:
            if type(retention_days) is not int or not 1 <= retention_days <= 3650:
                raise ValueError("Retention must be between 1 and 3,650 days.")
            db.execute("UPDATE collection SET retention_days = ? WHERE id = 1", (retention_days,))
        if sanitized_text_enabled is not None:
            if type(sanitized_text_enabled) is not bool:
                raise ValueError("Text collection requires a separate explicit setting.")
            db.execute("UPDATE text_policy SET enabled = ? WHERE id = 1", (sanitized_text_enabled,))
        value = db.execute("SELECT enabled, retention_days FROM collection WHERE id = 1").fetchone()
        text_enabled = db.execute("SELECT enabled FROM text_policy WHERE id = 1").fetchone()[0]
        return {"enabled": bool(value["enabled"]), "retention_days": value["retention_days"],
                "sanitized_text_enabled": bool(text_enabled)}


def masked_terms(text):
    """Return only fixed training terms, discarding complete privacy and URL spans."""
    text = re.sub(r"https?://[^\s<>]+", " ", text, flags=re.I)
    for placeholder in privacy_detector.PLACEHOLDERS.values():
        text = text.replace(placeholder, " ")
    spans = privacy_detector.find_findings(text)
    parts = []
    cursor = 0
    for hit in spans:
        parts.append(text[cursor:hit.start])
        cursor = hit.end
    parts.append(text[cursor:])
    words = re.findall(r"[^\W\d_][\w@.+/%=-]*", " ".join(parts).casefold())
    return " ".join(term for word in words if (term := word.rstrip(".")) in TRAINING_TERMS)


def collect(kind, features, assessment, consent, text_sample=None):
    if consent is not True:
        return None
    if (kind not in TYPES or assessment not in {"neutral", "suspicious", "uncertain"} or not features
            or not all(isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,49}", key)
                       and type(value) is int and 0 <= value <= 100000
                       for key, value in features.items())):
        raise ValueError("Only bounded numeric features can be collected.")
    payload = json.dumps(features, sort_keys=True, separators=(",", ":"))
    with connection() as db:
        db.execute("BEGIN IMMEDIATE")
        enabled = db.execute("SELECT enabled FROM collection WHERE id = 1").fetchone()[0]
        if not enabled:
            return None
        text_enabled = db.execute("SELECT enabled FROM text_policy WHERE id = 1").fetchone()[0]
        masked = None
        if kind == "email" and text_sample and text_enabled:
            subject, body = (masked_terms(value) for value in text_sample)
            subject, body = (" ".join(value.split()[:limit]) for value, limit in ((subject, 15), (body, 100)))
            if len(set((subject + " " + body).split())) >= 3:
                masked = (subject, body)
        fingerprint = f"{TEXT_VERSION}:{kind}:{masked}" if masked else f"features-v1:{kind}:{payload}"
        digest = sha256(fingerprint.encode()).hexdigest()
        cursor = db.execute(
            """INSERT OR IGNORE INTO samples (kind, fingerprint, features, assessment, version)
               VALUES (?, ?, ?, ?, 'features-v1')""",
            (kind, digest, payload, assessment),
        )
        if not cursor.rowcount:
            return None
        sample_id = int(cursor.lastrowid)
        if masked:
            db.execute("INSERT INTO sanitized_samples VALUES (?, ?, ?)", (sample_id, *masked))
        return sample_id


def list_samples(kind=None, status=None, approved_only=False, offset=0, mode="features"):
    if (kind is not None and kind not in TYPES) or (status is not None and status not in STATUSES):
        raise ValueError("Unknown sample filter.")
    if mode not in ("features", "text"):
        raise ValueError("Unknown export mode.")
    with connection() as db:
        if approved_only:
            if mode == "text":
                rows = db.execute("""SELECT kind, fingerprint, label, subject, body
                                     FROM samples JOIN sanitized_samples ON sample_id = id
                                     WHERE status = 'approved' AND (? IS NULL OR kind = ?) ORDER BY id""", (kind, kind))
                return [dict(row) | {"version": TEXT_VERSION, "status": "approved"} for row in rows]
            rows = db.execute("""SELECT kind, fingerprint, features, label, version FROM samples
                                 WHERE status = 'approved' AND (? IS NULL OR kind = ?) ORDER BY id""",
                              (kind, kind))
            return [dict(row) | {"features": json.loads(row["features"]), "status": "approved"} for row in rows]
        rows = db.execute(
            """SELECT id, created_at, kind, features, assessment, version, status, label,
                      subject AS sanitized_subject, body AS sanitized_body
               FROM samples LEFT JOIN sanitized_samples ON sample_id = id
               WHERE (? IS NULL OR kind = ?) AND (? IS NULL OR status = ?)
               ORDER BY id DESC LIMIT 100 OFFSET ?""", (kind, kind, status, status, offset))
        samples = [{**dict(row), "features": json.loads(row["features"])} for row in rows]
        counts = dict(db.execute("SELECT status, COUNT(*) FROM samples GROUP BY status"))
    return {"samples": samples, "counts": counts}


def review(sample_id, action):
    if type(sample_id) is not int or not 1 <= sample_id < 2**63:
        raise ValueError("Enter a valid sample ID.")
    decisions = {"phishing": "confirmed_phishing", "legitimate": "confirmed_legitimate",
                 "uncertain": "uncertain", "rejected": "rejected"}
    with connection() as db:
        if action == "delete":
            updated = db.execute("DELETE FROM samples WHERE id = ?", (sample_id,))
        elif action == "approve":
            updated = db.execute("""UPDATE samples SET status = 'approved'
                                    WHERE id = ? AND status IN ('confirmed_legitimate','confirmed_phishing')""", (sample_id,))
        elif isinstance(action, str) and action in decisions:
            label = action if action in LABELS else None
            updated = db.execute("UPDATE samples SET status = ?, label = ? WHERE id = ?",
                                 (decisions[action], label, sample_id))
        else:
            raise ValueError("Unknown review action.")
        if not updated.rowcount:
            raise ValueError("The sample is missing or has no confirmed label to approve.")


def prune():
    with connection() as db:
        return db.execute("""DELETE FROM samples WHERE created_at <
                             datetime('now', '-' || (SELECT retention_days FROM collection WHERE id = 1) || ' days')""").rowcount
