"""
Sentinel AI - Main Backend Server
Provides REST API for Chrome Extension and In-Page Gmail Guardian.
Integrates SQLite, ML models, URL feature extraction, privacy guard, and suspicious markers.
Runs natively using Python standard library (no external server framework required).
"""

import sys
import os
import json
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qs
import ipaddress

# Ensure current and parent directory is in python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
sys.path.insert(0, CURRENT_DIR)
sys.path.insert(0, PARENT_DIR)

from database import init_db, log_scan, log_privacy_audit, get_recent_history, get_stats, get_all_settings, update_setting
from markers import analyze_url_markers, analyze_email_markers
import privacy_detector

# Try loading ML models if joblib is available
url_model = None
url_features_cols = None
email_model = None

try:
    import joblib
    model_path_url = os.path.join(PARENT_DIR, "models", "url_phishing_model_v2.joblib")
    features_path_url = os.path.join(PARENT_DIR, "models", "url_features_v2.joblib")
    email_model_path = os.path.join(PARENT_DIR, "models", "email_phishing_model.joblib")

    if os.path.exists(model_path_url) and os.path.exists(features_path_url):
        url_model = joblib.load(model_path_url)
        url_features_cols = joblib.load(features_path_url)
        print("[Sentinel AI Backend] Loaded URL ML Model v2 successfully.")

    if os.path.exists(email_model_path):
        email_model = joblib.load(email_model_path)
        print("[Sentinel AI Backend] Loaded Email ML Model successfully.")
except Exception as e:
    print(f"[Sentinel AI Backend] ML models in passive mode ({e}). Using expert heuristic engine.")


def extract_features_dict(url: str) -> dict:
    """Extracts URL numerical and structural features without hard dependency on pandas."""
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "https://" + url

    parsed = urlsplit(url)
    domain = parsed.hostname or ""

    is_ip = 0
    try:
        ipaddress.ip_address(domain)
        is_ip = 1
    except ValueError:
        pass

    letters = sum(1 for c in url if c.isalpha())
    digits = sum(1 for c in url if c.isdigit())
    subdomains = max(0, len(domain.split(".")) - 2)
    is_https = 1 if parsed.scheme == "https" else 0

    return {
        "URLLength": len(url),
        "DomainLength": len(domain),
        "IsDomainIP": is_ip,
        "NoOfSubDomain": subdomains,
        "NoOfLettersInURL": letters,
        "NoOfDegitsInURL": digits,
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "IsHTTPS": is_https
    }


def predict_url_risk(url: str):
    """Computes URL risk score (0-100), risk level, and markers."""
    features = extract_features_dict(url)
    markers = analyze_url_markers(url, features)

    # Calculate heuristic score based on features and markers
    risk_score = 5.0 # baseline low risk

    # Danger markers
    danger_count = sum(1 for m in markers if m.get("severity") in ["danger", "high"])
    medium_count = sum(1 for m in markers if m.get("severity") == "medium")

    if features["IsDomainIP"] == 1:
        risk_score += 60.0
    if features["IsHTTPS"] == 0:
        risk_score += 25.0
    if features["NoOfSubDomain"] >= 3:
        risk_score += 20.0
    if features["URLLength"] > 100:
        risk_score += 15.0

    risk_score += danger_count * 25.0 + medium_count * 10.0
    risk_score = min(99.0, max(2.0, risk_score))

    # Try ML model if loaded
    ml_confidence = None
    if url_model is not None and url_features_cols is not None:
        try:
            import pandas as pd
            df_feat = pd.DataFrame([features])[url_features_cols]
            pred = url_model.predict(df_feat)[0]
            proba = url_model.predict_proba(df_feat)[0]
            # In training: 0 = phishing, 1 = legitimate
            phish_idx = list(url_model.classes_).index(0)
            ml_phish_prob = float(proba[phish_idx])
            ml_confidence = round(ml_phish_prob * 100, 1)
            # Combine ML confidence and heuristic markers
            risk_score = round(0.6 * ml_confidence + 0.4 * risk_score, 1)
        except Exception as err:
            pass

    risk_score = round(risk_score, 1)
    if risk_score >= 65.0:
        risk_level = "danger"
    elif risk_score >= 35.0:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    return {
        "url": url,
        "risk_score": risk_score,
        "safety_score": round(100.0 - risk_score, 1),
        "risk_level": risk_level,
        "markers": markers,
        "features": features,
        "ml_evaluated": url_model is not None
    }


def predict_email_risk(text: str, sender: str = "", links: list = None):
    """Evaluates an email text for phishing, privacy leaks, and suspicious cues."""
    privacy_findings = privacy_detector.detect_private_info(text)
    markers = analyze_email_markers(text, sender, links)

    risk_score = 10.0
    danger_markers = [m for m in markers if m.get("severity") in ["danger", "high"]]
    medium_markers = [m for m in markers if m.get("severity") == "medium"]

    risk_score += len(danger_markers) * 30.0 + len(medium_markers) * 15.0

    # Privacy sensitivity factor: if sensitive numbers are requested or present
    total_private_items = len(privacy_findings.get("aadhaar_numbers", [])) + \
                          len(privacy_findings.get("phone_numbers", [])) + \
                          len(privacy_findings.get("emails", []))

    if total_private_items > 0:
        markers.append({
            "id": "privacy_data_detected",
            "title": f"Sensitive Identity Data Detected ({total_private_items} items)",
            "description": f"Contains unredacted personal identifiers: {len(privacy_findings.get('aadhaar_numbers', []))} Aadhaar, {len(privacy_findings.get('phone_numbers', []))} Phone numbers.",
            "severity": "medium",
            "category": "privacy"
        })

    # Try ML model if loaded
    if email_model is not None:
        try:
            pred = email_model.predict([text])[0]
            if hasattr(email_model, "predict_proba"):
                proba = email_model.predict_proba([text])[0]
                phish_prob = float(proba[1]) * 100.0
                risk_score = round(0.6 * phish_prob + 0.4 * risk_score, 1)
            else:
                if pred == 1:
                    risk_score = max(risk_score, 75.0)
        except Exception:
            pass

    risk_score = min(99.0, max(5.0, round(risk_score, 1)))
    if risk_score >= 65.0:
        risk_level = "danger"
    elif risk_score >= 35.0:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    return {
        "risk_score": risk_score,
        "safety_score": round(100.0 - risk_score, 1),
        "risk_level": risk_level,
        "markers": markers,
        "privacy": privacy_findings,
        "private_items_count": total_private_items
    }


class SentinelAPIHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def _send_json_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path

        if path == "/api/health" or path == "/":
            self._send_json_response(200, {
                "status": "online",
                "app": "Sentinel AI Backend API",
                "version": "1.0.0",
                "db_status": "connected",
                "models_loaded": {
                    "url_phishing": url_model is not None,
                    "email_phishing": email_model is not None
                }
            })

        elif path == "/api/history":
            try:
                history = get_recent_history(limit=25)
                self._send_json_response(200, {"history": history})
            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        elif path == "/api/stats":
            try:
                stats = get_stats()
                self._send_json_response(200, stats)
            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        elif path == "/api/settings":
            try:
                settings = get_all_settings()
                self._send_json_response(200, {"settings": settings})
            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        else:
            self._send_json_response(404, {"error": "Not Found"})

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            body = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
        except Exception:
            self._send_json_response(400, {"error": "Invalid JSON payload"})
            return

        if path == "/api/scan-url":
            url = body.get("url", "").strip()
            if not url:
                self._send_json_response(400, {"error": "URL parameter is required"})
                return

            try:
                result = predict_url_risk(url)
                # Log scan in SQLite
                log_scan(
                    scan_type="url",
                    target_preview=url,
                    risk_level=result["risk_level"],
                    confidence=result["risk_score"],
                    markers=result["markers"],
                    metadata=result["features"]
                )
                self._send_json_response(200, result)
            except Exception as e:
                self._send_json_response(500, {"error": f"Scan failed: {str(e)}"})

        elif path == "/api/scan-email":
            text = body.get("text", "").strip()
            sender = body.get("sender", "").strip()
            links = body.get("links", [])

            if not text:
                self._send_json_response(400, {"error": "Email text is required"})
                return

            try:
                result = predict_email_risk(text, sender, links)
                # Log scan in SQLite
                log_scan(
                    scan_type="email",
                    target_preview=text[:120],
                    risk_level=result["risk_level"],
                    confidence=result["risk_score"],
                    markers=result["markers"],
                    metadata={"sender": sender, "privacy_items": result["private_items_count"]}
                )
                self._send_json_response(200, result)
            except Exception as e:
                self._send_json_response(500, {"error": f"Email scan failed: {str(e)}"})

        elif path == "/api/privacy-redact":
            text = body.get("text", "")
            context = body.get("context", "extension_redact")

            if not text:
                self._send_json_response(400, {"error": "Text is required"})
                return

            try:
                detected = privacy_detector.detect_private_info(text)
                redacted_text = privacy_detector.redact_private_info(text)

                total_redacted = len(detected.get("emails", [])) + \
                                 len(detected.get("phone_numbers", [])) + \
                                 len(detected.get("aadhaar_numbers", []))

                log_privacy_audit(context, detected, total_redacted, text[:150])

                self._send_json_response(200, {
                    "original_length": len(text),
                    "redacted_text": redacted_text,
                    "detected": detected,
                    "total_redacted": total_redacted
                })
            except Exception as e:
                self._send_json_response(500, {"error": f"Redaction failed: {str(e)}"})

        elif path == "/api/settings":
            key = body.get("key")
            value = body.get("value")
            if not key:
                self._send_json_response(400, {"error": "Setting key is required"})
                return
            try:
                update_setting(key, value)
                self._send_json_response(200, {"success": True, "key": key, "value": value})
            except Exception as e:
                self._send_json_response(500, {"error": str(e)})

        else:
            self._send_json_response(404, {"error": "Not Found"})

    def log_message(self, format, *args):
        # Override to keep terminal output clean and formatted
        sys.stderr.write(f"[Sentinel AI HTTP] {self.address_string()} - {format % args}\n")


def run_server(port=8000):
    init_db()
    HTTPServer.allow_reuse_address = True
    
    server_address = ("127.0.0.1", port)
    try:
        httpd = HTTPServer(server_address, SentinelAPIHandler)
    except OSError as e:
        if e.errno == 48: # Address already in use
            print(f"\n[Warning] Port {port} is already in use by another process.")
            alt_port = port + 1
            print(f"[Sentinel AI] Attempting alternative port: http://127.0.0.1:{alt_port} ...")
            try:
                server_address = ("127.0.0.1", alt_port)
                httpd = HTTPServer(server_address, SentinelAPIHandler)
                port = alt_port
            except OSError:
                print(f"[Error] Could not bind to port {port} or {alt_port}.")
                print(f"[Tip] Run: 'lsof -ti:{port} | xargs kill -9' to free the port.")
                return
        else:
            raise e

    print(f"=====================================================")
    print(f"  SENTINEL AI - Security & Privacy Guard Server     ")
    print(f"  Listening on: http://127.0.0.1:{port}               ")
    print(f"  SQLite Database: backend/sentinel_ai.db           ")
    print(f"  Press Ctrl+C to stop the server                   ")
    print(f"=====================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Sentinel AI backend server.")
        httpd.server_close()


if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass
    run_server(port)
