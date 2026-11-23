import os
import sqlite3
from contextlib import asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import joblib
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, HttpUrl, ValidationError, field_validator

from database import DB_PATH, init_db, read_history, save_scan
from email_analysis import analyze_email
from email_reliability import assess_email
from privacy_detector import detect_private_info, redact_private_info
from url_reliability import analyze_url


ROOT = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    models = ROOT / "models"
    app.state.email_model = joblib.load(models / "email_phishing_model.joblib")
    app.state.url_model = joblib.load(models / "url_phishing_model_v3.joblib")
    app.state.columns = joblib.load(models / "url_features_v2.joblib")
    if list(app.state.url_model.feature_names_in_) != app.state.columns:
        raise RuntimeError("The saved URL feature list does not match the v3 model.")
    for model in (app.state.email_model, app.state.url_model):
        if set(model.classes_) != {0, 1}:
            raise RuntimeError("Expected a binary phishing classifier with labels 0 and 1.")
    app.state.db_path = Path(os.getenv("SENTINELAI_DB_PATH", DB_PATH))
    init_db(app.state.db_path)
    yield


app = FastAPI(title="SentinelAI", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class URLInput(BaseModel):
    url: str = Field(min_length=1, max_length=2083)


class TextInput(BaseModel):
    text: str = Field(min_length=1, max_length=20000)

    @field_validator("text")
    @classmethod
    def require_content(cls, value: str):
        if not value.strip():
            raise ValueError("Enter some text to scan.")
        return value


class EmailInput(TextInput):
    language: str = Field(default="en", min_length=2, max_length=16)


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    # Validation errors normally echo the rejected input. Return only the reason.
    message = error.errors()[0]["msg"].removeprefix("Value error, ")
    return JSONResponse(status_code=422, content={"detail": message})


@app.exception_handler(sqlite3.Error)
async def database_error(request: Request, error: sqlite3.Error):
    return JSONResponse(status_code=503, content={"detail": "Scan history is unavailable. Please try again."})


@app.get("/health")
def health():
    return {"status": "ok"}


def save_model_scan(scan_type, result, db_path):
    phishing_probability = result["phishing_probability"]
    # History stores scored verdicts. An abstention has no model confidence to save.
    if phishing_probability is None:
        return
    predicted_probability = (
        phishing_probability if result["prediction"] == "Phishing" else 1 - phishing_probability
    )
    save_scan({
        "scan_type": scan_type,
        "prediction": result["prediction"],
        "confidence": predicted_probability * 100,
    }, db_path)


@app.post("/scan/url")
def scan_url(body: URLInput, request: Request):
    url = body.url.strip()
    try:
        HttpUrl(url)
        if not url.lower().startswith(("https://", "http://")) or not urlsplit(url).hostname:
            raise ValueError
        if any(c.isspace() or ord(c) < 32 or c == "\\" for c in url):
            raise ValueError
    except (ValueError, ValidationError):
        raise HTTPException(422, "Enter a complete HTTP or HTTPS URL with a valid host and port.") from None

    state = request.app.state
    scheme, rest = url.split(":", 1)
    result = analyze_url(state.url_model, scheme.lower() + ":" + rest, state.columns)
    save_model_scan("url", result, state.db_path)
    return result


@app.post("/scan/email")
def scan_email(body: EmailInput, request: Request):
    state = request.app.state
    model = state.email_model
    feature_row = model.named_steps["tfidf"].transform([body.text])
    result = assess_email(model, body.text, feature_row=feature_row)
    result["analysis"] = {
        "evidence_policy": result.pop("evidence_policy"),
        **analyze_email(body.text, model, language=body.language, feature_row=feature_row),
    }
    save_model_scan("email", result, state.db_path)
    return result


@app.post("/classify/message")
def classify_message(body: TextInput, request: Request):
    try:
        local_client = request.client is not None and ip_address(request.client.host).is_loopback
    except ValueError:
        local_client = False
    if not local_client:
        raise HTTPException(403, "Messages classification requires a local connection.")
    # The desktop monitor owns its metadata history. Keep message text in memory.
    result = assess_email(request.app.state.email_model, body.text)
    result.pop("evidence_policy")
    return result


@app.post("/privacy/redact")
def redact(body: TextInput, request: Request):
    detected = detect_private_info(body.text)
    counts = {category: len(matches) for category, matches in detected.items()}
    total = sum(counts.values())
    prediction = "Redacted" if total else "No matches"
    risk = "Medium" if total else "Low"
    redacted = redact_private_info(body.text)
    save_scan({
        "scan_type": "privacy",
        "prediction": prediction,
        "privacy_matches": total,
    }, request.app.state.db_path)
    return {"prediction": prediction, "risk_level": risk, "counts": counts, "redacted_text": redacted}


@app.get("/history")
def history(
    request: Request,
    scan_type: Literal["url", "email", "privacy"] | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=2**63 - 1),
):
    return read_history(request.app.state.db_path, scan_type, limit, offset)
