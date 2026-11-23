import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


DB_PATH = Path(__file__).resolve().with_name("scan_history.sqlite3")

VALID_SCAN_TYPES = {"Email", "URL", "Privacy"}
MODEL_PREDICTIONS = {"Phishing", "Legitimate"}
PRIVACY_PREDICTIONS = {"Redacted", "No matches"}
VALID_PREDICTIONS = MODEL_PREDICTIONS | PRIVACY_PREDICTIONS
PREDICTION_LABELS = {label.lower(): label for label in VALID_PREDICTIONS}
PREDICTION_LABELS["safe"] = "Legitimate"

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('Email', 'URL', 'Privacy')),
    input_preview TEXT NOT NULL,
    prediction TEXT NOT NULL CHECK (prediction IN ('Legitimate', 'Phishing', 'Redacted', 'No matches')),
    confidence REAL CHECK (confidence >= 0.0 AND confidence <= 100.0),
    created_at TEXT NOT NULL,
    privacy_matches INTEGER NOT NULL DEFAULT 0 CHECK (privacy_matches >= 0)
);
"""
INSERT_SQL = """
INSERT INTO scans (id, scan_type, input_preview, prediction, confidence, created_at, privacy_matches)
VALUES (:id, :scan_type, :input_preview, :prediction, :confidence, :created_at, :privacy_matches);
"""

TEAMMATE_COLUMNS = {"id", "scan_type", "input_preview", "prediction", "confidence", "created_at"}
APP_COLUMNS = {"id", "scan_type", "prediction", "timestamp", "risk_level", "findings", "privacy_matches"}
CURRENT_COLUMNS = TEAMMATE_COLUMNS | {"privacy_matches"}


def _get_connection(db_path: str | Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str | Path = DB_PATH) -> None:
    with closing(_get_connection(db_path)) as conn, conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA secure_delete = ON;")
        # Keep schema changes and row copying in one transaction.
        conn.execute("BEGIN IMMEDIATE;")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(scans);")}
        if columns in (TEAMMATE_COLUMNS, APP_COLUMNS):
            _migrate_scans(conn, columns)
        elif columns and columns != CURRENT_COLUMNS:
            raise RuntimeError("Unrecognized scans table schema. Use a separate database path.")
        conn.execute(CREATE_TABLE_SQL)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_type ON scans(scan_type);")


def _migrate_scans(conn: sqlite3.Connection, columns: set[str]) -> None:
    conn.execute("ALTER TABLE scans RENAME TO scans_legacy;")
    conn.execute(CREATE_TABLE_SQL)
    if columns == TEAMMATE_COLUMNS:
        rows = conn.execute("SELECT id, scan_type, prediction, confidence, created_at FROM scans_legacy;")
    else:
        rows = conn.execute("""
            SELECT id, scan_type, prediction, timestamp AS created_at, findings, privacy_matches
            FROM scans_legacy;
        """)
    for row in rows:
        data = dict(row)
        if columns == TEAMMATE_COLUMNS:
            # The original samples supplied fractions. Scores above one were already percentages.
            if data["confidence"] <= 1.0:
                data["confidence"] *= 100
        else:
            # The old app saved the phishing probability only, rounded to one decimal.
            confidence = None
            match = re.fullmatch(r"(URL|Email) model · ([0-9]{1,3}\.[0-9])% phishing probability", data.pop("findings"))
            if match and data["scan_type"] in {"url", "email"}:
                probability = float(match[2])
                if probability <= 100:
                    confidence = probability if data["prediction"] == "Phishing" else 100 - probability
            data["confidence"] = confidence
        clean_data = _validate_and_normalize_scan(data, allow_missing_confidence=True)
        conn.execute(INSERT_SQL, {**clean_data, "id": data["id"]})
    conn.execute("DROP TABLE scans_legacy;")


def _normalize_scan_type(scan_type: str) -> str:
    raw_type = str(scan_type).strip()
    normalized = "URL" if raw_type.upper() == "URL" else raw_type.capitalize()
    if normalized not in VALID_SCAN_TYPES:
        raise ValueError("scan_type must be Email, URL or Privacy.")
    return normalized


def _normalize_prediction(prediction: str) -> str:
    normalized = PREDICTION_LABELS.get(str(prediction).strip().lower())
    if normalized is None:
        raise ValueError("prediction must be Legitimate, Phishing, Redacted or No matches.")
    return normalized


def _normalize_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    try:
        if not isinstance(value, str):
            raise ValueError
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("created_at must be an ISO 8601 timestamp.") from None
    # Keep the exact timestamp text from either earlier schema when it is already UTC.
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value):
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _scan_preview(scan_type: str, prediction: str, confidence: float | None, privacy_matches: int) -> str:
    if scan_type == "Privacy":
        name = "pattern match" if privacy_matches == 1 else "pattern matches"
        return f"{privacy_matches} {name}"
    if confidence is None:
        return f"{scan_type} model"
    probability = confidence if prediction == "Phishing" else 100 - confidence
    return f"{scan_type} model · {probability:.1f}% phishing probability"


def _validate_and_normalize_scan(data: dict, *, allow_missing_confidence: bool = False) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Scan data must be a Python dictionary.")

    required_fields = {"scan_type", "prediction"}
    missing = required_fields - data.keys()
    if missing:
        raise ValueError(f"Missing required scan fields: {sorted(missing)}")

    scan_type = _normalize_scan_type(data["scan_type"])
    prediction = _normalize_prediction(data["prediction"])
    confidence = data.get("confidence")
    privacy_matches = data.get("privacy_matches", 0)
    if type(privacy_matches) is not int or not 0 <= privacy_matches < 2**63:
        raise ValueError("privacy_matches must be a non-negative integer.")

    if scan_type == "Privacy":
        expected = "Redacted" if privacy_matches else "No matches"
        if prediction != expected or confidence is not None:
            raise ValueError("Privacy scans require a matching verdict and no confidence score.")
    else:
        if prediction not in MODEL_PREDICTIONS or privacy_matches != 0:
            raise ValueError("Model scans require a phishing or legitimate verdict with zero privacy matches.")
        if confidence is not None or not allow_missing_confidence:
            if type(confidence) not in (int, float) or not 0 <= confidence <= 100:
                raise ValueError("confidence must be a percentage between 0 and 100.")
            confidence = float(confidence)

    return {
        "scan_type": scan_type,
        # Always generate the preview from metadata, even if a caller supplies text.
        "input_preview": _scan_preview(scan_type, prediction, confidence, privacy_matches),
        "prediction": prediction,
        "confidence": confidence,
        "created_at": _normalize_timestamp(data.get("created_at")),
        "privacy_matches": privacy_matches,
    }


def save_scan(data: dict, db_path: str | Path = DB_PATH) -> int:
    clean_data = _validate_and_normalize_scan(data)
    with closing(_get_connection(db_path)) as conn, conn:
        cursor = conn.execute(INSERT_SQL, {**clean_data, "id": None})
        return int(cursor.lastrowid)


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


ALLOWED_SORT_COLUMNS = {"id", "created_at", "confidence", "scan_type", "prediction"}


def _query_history(conn, scan_type, prediction, search_query, sort_by, order, limit, offset):
    conditions = []
    params = []
    if scan_type is not None:
        conditions.append("scan_type = ?")
        params.append(scan_type)
    if prediction is not None:
        conditions.append("prediction = ?")
        params.append(prediction)
    if search_query and search_query.strip():
        conditions.append("(input_preview LIKE ? OR prediction LIKE ? OR scan_type LIKE ?)")
        wildcard_term = f"%{search_query.strip()}%"
        params.extend([wildcard_term, wildcard_term, wildcard_term])

    sql = "SELECT * FROM scans"
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    # ISO timestamps can vary in fractional precision. Sort by time before breaking ties by ID.
    sort_column = "julianday(created_at)" if sort_by == "created_at" else sort_by
    sql += f" ORDER BY {sort_column} {order}, id DESC"
    if limit is not None or offset:
        sql += " LIMIT ? OFFSET ?"
        params.extend([limit if limit is not None else -1, offset])
    return [_row_to_dict(row) for row in conn.execute(sql, params)]


def get_scan_history(
    scan_type: str | None = None,
    prediction: str | None = None,
    search_query: str | None = None,
    sort_by: str = "created_at",
    order: str = "DESC",
    limit: int | None = None,
    db_path: str | Path = DB_PATH,
    *,
    offset: int = 0,
) -> list[dict]:
    if scan_type is not None:
        scan_type = _normalize_scan_type(scan_type)
    if prediction is not None:
        prediction = _normalize_prediction(prediction)
    if sort_by not in ALLOWED_SORT_COLUMNS:
        raise ValueError(f"Invalid sort_by column. Use one of {sorted(ALLOWED_SORT_COLUMNS)}.")
    order_upper = order.upper()
    if order_upper not in {"ASC", "DESC"}:
        raise ValueError("order must be either 'ASC' or 'DESC'.")
    if limit is not None and (type(limit) is not int or not 1 <= limit < 2**63):
        raise ValueError("limit must be a positive integer.")
    if type(offset) is not int or not 0 <= offset < 2**63:
        raise ValueError("offset must be a non-negative integer.")

    with closing(_get_connection(db_path)) as conn:
        return _query_history(conn, scan_type, prediction, search_query, sort_by, order_upper, limit, offset)


def get_scan_by_id(scan_id: int, db_path: str | Path = DB_PATH) -> dict | None:
    if type(scan_id) is not int or not 1 <= scan_id < 2**63:
        return None
    with closing(_get_connection(db_path)) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?;", (scan_id,)).fetchone()
        return _row_to_dict(row) if row is not None else None


def delete_scan(scan_id: int, db_path: str | Path = DB_PATH) -> bool:
    if type(scan_id) is not int or not 1 <= scan_id < 2**63:
        return False
    with closing(_get_connection(db_path)) as conn, conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?;", (scan_id,))
        return cursor.rowcount == 1


def clear_history(db_path: str | Path = DB_PATH) -> int:
    with closing(_get_connection(db_path)) as conn, conn:
        return conn.execute("DELETE FROM scans;").rowcount


def get_scan_count(db_path: str | Path = DB_PATH) -> int:
    with closing(_get_connection(db_path)) as conn:
        return conn.execute("SELECT COUNT(*) FROM scans;").fetchone()[0]


def read_history(db_path: str | Path, scan_type: str | None, limit: int, offset: int) -> dict:
    # The dashboard uses lowercase scan types and one consistent snapshot of rows and totals.
    normalized_type = _normalize_scan_type(scan_type) if scan_type else None
    with closing(_get_connection(db_path)) as conn, conn:
        conn.execute("BEGIN;")
        totals = conn.execute("""
            SELECT COUNT(*) AS total_scans,
                   COUNT(CASE WHEN prediction = 'Phishing' THEN 1 END) AS phishing_detections,
                   COALESCE(SUM(privacy_matches), 0) AS privacy_matches
            FROM scans;
        """).fetchone()
        total = totals["total_scans"]
        if normalized_type:
            total = conn.execute("SELECT COUNT(*) FROM scans WHERE scan_type = ?;", (normalized_type,)).fetchone()[0]
        activity = conn.execute("""
            SELECT date(created_at) AS date, COUNT(*) AS count
            FROM scans
            WHERE date(created_at) BETWEEN date('now', '-6 days') AND date('now')
            GROUP BY date(created_at)
            ORDER BY date(created_at);
        """).fetchall()
        rows = _query_history(conn, normalized_type, None, None, "id", "DESC", limit, offset)

    items = []
    for row in rows:
        prediction = row["prediction"]
        risk_level = {"Phishing": "High", "Redacted": "Medium"}.get(prediction, "Low")
        items.append({
            "id": row["id"],
            "timestamp": row["created_at"],
            "scan_type": row["scan_type"].lower(),
            "prediction": prediction,
            "risk_level": risk_level,
            "findings": row["input_preview"],
        })
    return {**dict(totals), "total": total, "items": items, "daily_activity": [dict(day) for day in activity]}
