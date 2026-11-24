"""
Sentinel AI - Main Backend Server
Provides REST API for Chrome Extension and In-Page Gmail Guardian.
Integrates SQLite, ML models, URL feature extraction, privacy guard, and suspicious markers.
Runs natively using Python standard library (no external server framework required).
"""

import sys
import os
import json
import base64
import hashlib
from html import escape
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs

# Ensure current and parent directory is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, CURRENT_DIR)
sys.path.insert(0, PARENT_DIR)

# Auto-detect virtualenv if running in a Python missing dependencies
try:
    import tldextract
except ImportError:
    venv_candidates = [
        os.path.join(PARENT_DIR, ".venv", "bin", "python"),
        os.path.join(PARENT_DIR, ".venv", "Scripts", "python.exe"),
        os.path.join(PARENT_DIR, ".runtime", "venv", "bin", "python"),
        os.path.join(PARENT_DIR, ".runtime", "venv", "Scripts", "python.exe"),
    ]
    re_execed = False
    for venv_py in venv_candidates:
        if os.path.exists(venv_py) and os.path.realpath(sys.executable) != os.path.realpath(venv_py):
            try:
                import subprocess
                res = subprocess.run([venv_py, "-c", "import tldextract"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if res.returncode == 0:
                    os.execv(venv_py, [venv_py] + sys.argv)
                    re_execed = True
                    break
            except Exception:
                pass
    if not re_execed:
        sys.stderr.write(
            "\n" + "=" * 60 + "\n"
            "Sentinel AI: Missing required Python dependencies!\n\n"
            "Please run './start_backend.sh' to automatically prepare the\n"
            "virtual environment, or install dependencies manually:\n"
            "    pip install -r requirements.txt\n"
            + "=" * 60 + "\n\n"
        )
        sys.exit(1)

from database import init_db, log_scan, log_privacy_audit, get_recent_history, get_stats, get_all_settings, update_setting
from assessments import destination, email_evidence, split_url, url_evidence, webpage_evidence
import privacy_detector
import threats
from scoring import apply_score, email_model, model_observation
from url_advisory import candidate, extract_features_dict, url_model_observations


MAX_REQUEST = 512 * 1024

# Safely resolve extension key/id without crashing if manifest is missing or formatted differently
manifest_path = Path(PARENT_DIR) / "extension/manifest.json"
EXTENSION_KEY = ""
EXTENSION_ID = ""
if manifest_path.exists():
    try:
        manifest_data = json.loads(manifest_path.read_text())
        EXTENSION_KEY = manifest_data.get("key", "")
        if EXTENSION_KEY:
            EXTENSION_ID = hashlib.sha256(base64.b64decode(EXTENSION_KEY)).hexdigest()[:32].translate(
                str.maketrans("0123456789abcdef", "abcdefghijklmnop")
            )
    except Exception:
        pass

APP_ORIGINS = {
    "http://127.0.0.1:5173", "http://localhost:5173",
    "http://127.0.0.1:4173", "http://localhost:4173"
}
if EXTENSION_ID:
    APP_ORIGINS.add(f"chrome-extension://{EXTENSION_ID}")
ALLOWED_ORIGINS = APP_ORIGINS | {"https://mail.google.com"}


def predict_url_risk(url):
    result = url_evidence(url)
    result["features"] = extract_features_dict(url)
    return apply_score(result, url_model_observations([url])[0], weight=.70, model_only_caution=True)


def predict_email_risk(text, sender="", links=(), subject="", reply_to="", html="", labels=()):
    result = email_evidence(text, sender, links, subject, reply_to, html, labels)
    visible = result.pop("_visible_body")
    privacy = privacy_detector.privacy_report(visible)
    observations = url_model_observations([link["url"] for link in result["links"]])
    for link, observation in zip(result["links"], observations):
        link["model_observation"] = observation
    result.update({"privacy": privacy["detected"], "private_items_count": privacy["total_redacted"],
                   "privacy_counts": privacy["counts"], "redacted_text": privacy["redacted_text"]})
    # The saved pipeline was fit on bodies. Subject and headers add independent evidence.
    observation = model_observation(email_model(), [visible], 1, "email-tfidf-v1")[0]
    link_probability = max((item.get("phishing_probability", 0) for item in observations), default=0)
    enough = result["risk_level"] == "neutral" or bool(result["markers"] or result["links"])
    return apply_score(result, observation, weight=.25, enough=enough, link_probability=link_probability)


def text_field(body, key, max_chars, default=""):
    value = body.get(key, default)
    if not isinstance(value, str) or len(value) > max_chars:
        raise ValueError(f"{key} must be text with at most {max_chars} characters.")
    return value


def list_field(body, key, limit):
    value = body.get(key, [])
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{key} must be a list with at most {limit} entries.")
    return value


def email_features(result):
    ids = {item["id"] for item in result["markers"]}
    return {key: int(key in ids) for key in (
        "credential_request", "pressure", "payment_request", "link_deception",
        "reply_domain_mismatch", "display_name_domain_mismatch", "subject_body_gap",
    )} | {"links": len(result["links"])}


def legacy_scan_response(result, gmail=False):
    """Adapt evidence to the restored three-state renderer without inventing a score."""
    level = result["display_level"]
    indicators = result["markers"]
    if not indicators or result["risk_level"] != "suspicious":
        indicators = [{
            "id": "assessment_summary", "title": result["assessment"],
            "description": result["explanation"], "severity": "medium" if level == "suspicious" else "low",
        }, *indicators]
    # The installed Gmail content script renders legacy marker strings as HTML.
    markers = [{
        "id": item["id"], "title": escape(item["title"]), "description": escape(item["description"]),
        "severity": item["severity"] if item["severity"] in {"danger", "high", "medium", "low", "safe"} else "low",
    } for item in indicators]
    legacy = {"risk_level": level, "safety_score": result["safety_score"], "markers": markers,
              "assessment": result["assessment"], "explanation": result["explanation"]}
    if gmail:
        return legacy | {"private_items_count": result.get("private_items_count", 0)}
    return result | legacy | {"evidence_level": result["risk_level"]}


def query_int(query, key, default, low, high):
    value = int(query.get(key, [default])[0])
    if not low <= value <= high:
        raise ValueError(f"{key} must be between {low} and {high}.")
    return value


class SentinelAPIHandler(BaseHTTPRequestHandler):
    timeout = 5

    def allowed(self, path):
        try:
            host = urlsplit("//" + (self.headers.get("Host") or "")).hostname
        except ValueError:
            return False
        origin = self.headers.get("Origin")
        if host not in {"localhost", "127.0.0.1", "::1"} or (origin and origin not in ALLOWED_ORIGINS):
            return False
        if origin == "https://mail.google.com":
            return path == "/api/scan-email"
        return True

    def _send_json_response(self, status, data=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            if self.command == "OPTIONS" and self.headers.get("Access-Control-Request-Private-Network") == "true":
                self.send_header("Access-Control-Allow-Private-Network", "true")
        self.end_headers()
        if data is not None:
            self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        path = self.path.partition("?")[0]
        self._send_json_response(204 if self.allowed(path) else 403)

    def do_GET(self):
        path, _, search = self.path.partition("?")
        if not self.allowed(path):
            return self._send_json_response(403, {"error": "Local SentinelAI client required."})
        try:
            query = parse_qs(search, max_num_fields=8)
            kind = query.get("kind", [None])[0]
            status = query.get("status", [None])[0]
            if path in {"/api/health", "/"}:
                result = {"status": "online", "app": "Sentinel AI Backend API", "version": "2.0.0",
                          "db_status": "connected", "models_loaded": {"url_phishing": candidate() is not None,
                                                                           "email_phishing": email_model() is not None}}
            elif path in {"/api/history", "/api/v2/history"}:
                limit = query_int(query, "limit", 25, 1, 100)
                offset = query_int(query, "offset", 0, 0, 1_000_000)
                history = get_recent_history(limit, offset, kind)
                result = {"history": history}
            elif path == "/api/stats":
                result = get_stats()
            elif path == "/api/settings":
                result = {"settings": get_all_settings()}
            elif path == "/api/threats":
                result = threats.list_samples(kind, status, offset=query_int(query, "offset", 0, 0, 1_000_000))
            elif path == "/api/threats/settings":
                result = threats.settings()
            elif path == "/api/threats/export":
                mode = query.get("mode", ["features"])[0]
                result = {"samples": threats.list_samples(kind, approved_only=True, mode=mode)}
            else:
                return self._send_json_response(404, {"error": "Not Found"})
            self._send_json_response(200, result)
        except ValueError as error:
            self._send_json_response(400, {"error": str(error)})
        except Exception:
            self._send_json_response(500, {"error": "The local operation failed."})

    def do_POST(self):
        path = self.path.partition("?")[0]
        if not self.allowed(path):
            return self._send_json_response(403, {"error": "Local SentinelAI client required."})
        if self.headers.get_content_type() != "application/json":
            return self._send_json_response(415, {"error": "Use application/json."})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST:
                return self._send_json_response(413, {"error": "Request size is outside the allowed limit."})
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError()
        except (ValueError, UnicodeError):
            return self._send_json_response(400, {"error": "Invalid JSON payload."})
        except TimeoutError:
            return self._send_json_response(408, {"error": "Request timed out."})
        try:
            result = self.handle_post(path, body)
            self._send_json_response(200, result)
        except KeyError:
            self._send_json_response(404, {"error": "Not Found"})
        except (ValueError, UnicodeError) as error:
            self._send_json_response(400, {"error": str(error)})
        except Exception:
            self._send_json_response(500, {"error": "The local operation failed."})

    def handle_post(self, path, body):
        gmail = self.headers.get("Origin") == "https://mail.google.com"
        consent = body.get("collect_sample") is True and not gmail
        preview = body.get("preview") is True and not gmail
        if path in {"/api/scan-url", "/api/v2/scan-url"}:
            url = text_field(body, "url", 2083).strip()
            result = predict_url_risk(url)
            parts, host, _ = split_url(url, assume_https=True)
            # Trainable URL counts omit credentials, query and fragments.
            features = extract_features_dict(destination(parts, host))
            if not preview:
                self.record_scan("url", result, features, consent)
            return legacy_scan_response(result) if path == "/api/scan-url" else result
        if path in {"/api/scan-email", "/api/v2/scan-email"}:
            text = text_field(body, "text", 20000)
            html = text_field(body, "html", 100000)
            subject = text_field(body, "subject", 500)
            if not (text.strip() or html.strip() or subject.strip()):
                raise ValueError("Email text or subject is required.")
            result = predict_email_risk(text, text_field(body, "sender", 500),
                                        list_field(body, "links", 80), subject,
                                        text_field(body, "reply_to", 500), html,
                                        [label[:40] for label in list_field(body, "labels", 50) if isinstance(label, str)])
            if not preview:
                text_sample = (subject, result["redacted_text"]) if consent and body.get("collect_text") is True else None
                self.record_scan("email", result, email_features(result), consent, text_sample)
            return legacy_scan_response(result, gmail) if path == "/api/scan-email" else result
        if path == "/api/scan-page":
            url = text_field(body, "url", 2083)
            result = webpage_evidence(url, body.get("observations"))
            apply_score(result, url_model_observations([url])[0], weight=.70,
                        enough=any(result["observations"].values()))
            if preview:
                return result
            return self.record_scan("webpage", result, result["observations"], consent)
        if path == "/api/privacy-redact":
            text = text_field(body, "text", 40000)
            if not text.strip():
                raise ValueError("Text is required.")
            approved = list_field(body, "approved", 1000)
            if any(not isinstance(item, str) or len(item) > 70 for item in approved):
                raise ValueError("Review selections must use returned finding IDs.")
            region = text_field(body, "region", 2, "IN").upper()
            if region not in privacy_detector.phonenumbers.SUPPORTED_REGIONS:
                raise ValueError("Unknown phone region.")
            selected = list_field(body, "selected", 2000) if "selected" in body else None
            if selected is not None and any(not isinstance(item, str) or len(item) > 70 for item in selected):
                raise ValueError("Redaction selections must use returned finding IDs.")
            result = privacy_detector.privacy_report(text, approved, region, selected)
            if body.get("findings_only") is True:
                return {key: result[key] for key in ("findings", "offset_encoding")}
            context = body.get("context")
            if context not in ("extension_redact", "gmail_compose", "manual_scan", "clipboard"):
                context = "extension_redact"
            if not preview:
                log_privacy_audit(context, result["counts"], result["total_redacted"], "")
            return result
        if path == "/api/settings":
            key = text_field(body, "key", 60)
            if key not in {"theme", "mode", "privacy_guard_enabled", "auto_redact_aadhaar", "gmail_scanner_enabled"}:
                raise ValueError("Unknown setting.")
            value = body.get("value")
            if (key == "theme" and value not in ("cold", "warm")) or (key == "mode" and value not in ("light", "dark")) or (
                key not in {"theme", "mode"} and value not in (True, False, "true", "false")
            ):
                raise ValueError("Invalid setting value.")
            update_setting(key, value)
            return {"success": True, "key": key, "value": value}
        if path == "/api/threats/settings":
            return threats.settings(body.get("enabled"), body.get("retention_days"), body.get("sanitized_text_enabled"))
        if path == "/api/threats/review":
            threats.review(body.get("id"), body.get("action"))
            return {"success": True}
        if path == "/api/threats/prune":
            return {"deleted": threats.prune()}
        raise KeyError(path)

    @staticmethod
    def record_scan(kind, result, features, consent, text_sample=None):
        log_scan(kind, f"{kind.capitalize()} assessment", result["risk_level"], result["risk_score"],
                 [{"id": item["id"]} for item in result["markers"]], metadata={"screening_score": True})
        if consent:
            result["sample_id"] = threats.collect(kind, features, result["risk_level"], consent, text_sample)
        return result

    def log_message(self, format, *args):
        # Never log request targets, headers or bodies.
        pass


def run_server(port=8000):
    init_db()
    with ThreadingHTTPServer(("127.0.0.1", port), SentinelAPIHandler) as httpd:
        print(f"SentinelAI backend listening on http://127.0.0.1:{port}", flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    port = 8000
    for arg in sys.argv[1:]:
        if arg.isdigit():
            port = int(arg)
            break
    run_server(port)
