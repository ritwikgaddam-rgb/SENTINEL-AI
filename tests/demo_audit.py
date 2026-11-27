"""Run a repeatable demonstration against two disposable SQLite databases."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import tempfile
from time import perf_counter
from urllib.request import Request, urlopen

from backend.assessments import PAGE_FEATURES, writing_checks

ROOT = Path(__file__).resolve().parents[1]
EMAILS = [
    "Hello.",
    "How are you doing today?",
    "Hey how are you what are you doing.",
    "Never share your password or OTP with anyone.",
    "Please send me the homework when you finish.",
]
PHISHING = {
    "subject": "Final notice: verify your account",
    "sender": "PayPal Support <notice@example.org>",
    "reply_to": "review@example.net",
    "text": "Your account will be suspended. Please reply with your password now. We recieved teh request.",
    "links": [{"url": "https://example.net/verify", "label": "https://example.org/account"}],
}
PAGE = dict.fromkeys(PAGE_FEATURES, 0)
PAGE_CASES = {
    "cookie banner": {"overlays": 1, "buttons": 2},
    "newsletter": {"overlays": 1, "buttons": 2},
    "login": {"credential_forms": 1},
    "notification": {"notification_prompt": 1},
    "scam overlay": {"infection_claim": 1, "support_request": 1, "overlays": 1, "blocking_overlay": 1},
    "prize payment": {"prize_claim": 1, "payment_request": 1},
    "browser impersonation": {"browser_impersonation": 1, "notification_prompt": 1, "blocking_overlay": 1},
}
DEMO = (ROOT / "docs/privacy-demo-email.txt").read_text()


def run(base, startup_ms):
    def call(path, data=None):
        headers = {"Content-Type": "application/json"} if data is not None else {}
        body = json.dumps(data).encode() if data is not None else None
        with urlopen(Request(base + path, data=body, headers=headers), timeout=8) as response:
            return json.load(response)

    def bench(task, n=30):
        task()
        durations = []
        for _ in range(n):
            start = perf_counter()
            task()
            durations.append((perf_counter() - start) * 1000)
        return {"median_ms": round(statistics.median(durations), 2),
                "p95_ms": round(statistics.quantiles(durations, n=20, method="inclusive")[18], 2), "n": n}

    start = perf_counter()
    health = call("/api/health")
    cold_health_ms = (perf_counter() - start) * 1000
    assert all(health["models_loaded"].values())
    email_cases = []
    for text in EMAILS + ["Let's meet at the library after school. Bring the science notes."]:
        result = call("/api/v2/scan-email", {"text": text, "preview": True})
        assert result["display_level"] in ("safe", "unknown")
        email_cases.append({"text": text, "assessment": result["assessment"], "score": result["safety_score"],
                            "model_probability": result["model_observation"]["phishing_probability"]})
    email = call("/api/v2/scan-email", {**PHISHING, "preview": True})
    ids = {marker["id"] for marker in email["markers"]}
    assert {"credential_request", "reply_domain_mismatch", "display_name_domain_mismatch", "link_deception"} <= ids
    assert email["assessment"] == "Suspicious" and email["grammar"]["count"] >= 1 and len(email["links"]) == 1
    urls = {}
    for url in ("http://example.org/", "https://example.org/", "https://example.org@example.net/review"):
        result = call("/api/v2/scan-url", {"url": url, "preview": True})
        assert 0 <= result["risk_score"] <= 100 and abs(result["risk_score"] + result["safety_score"] - 100) < 1e-6
        urls[url] = (result["assessment"], result["safety_score"])

    webpage = {}
    for name, values in PAGE_CASES.items():
        result = call("/api/scan-page", {"url": "https://example.org/", "observations": PAGE | values, "preview": True})
        assert result["risk_level"] == ("suspicious" if name in {"scam overlay", "prize payment", "browser impersonation"} else "neutral")
        webpage[name] = result["assessment"]

    redact = call("/api/privacy-redact", {"text": DEMO, "preview": True})
    assert redact["total_redacted"] == 16 and redact["total_review"] == 0
    assert call("/api/threats/settings")["enabled"] is False
    call("/api/threats/settings", {"enabled": True})
    payload = {**PHISHING, "collect_sample": True}
    first = call("/api/v2/scan-email", payload)["sample_id"]
    assert isinstance(first, int) and call("/api/v2/scan-email", payload)["sample_id"] is None
    assert call("/api/threats/export")["samples"] == []
    for action in ("phishing", "approve"):
        call("/api/threats/review", {"id": first, "action": action})
    approved, = call("/api/threats/export")["samples"]
    assert approved["label"] == "phishing" and approved["status"] == "approved"
    assert all(isinstance(value, int) for value in approved["features"].values())

    measurements = {
        "email_scan": bench(lambda: call("/api/v2/scan-email", {**PHISHING, "preview": True})),
        "url_scan": bench(lambda: call("/api/v2/scan-url", {"url": "https://example.org/", "preview": True})),
        "privacy_scan": bench(lambda: call("/api/privacy-redact", {"text": DEMO, "preview": True})),
        "privacy_35k": bench(lambda: call("/api/privacy-redact", {"text": "Ordinary meeting notes. " * 1500, "preview": True}), 10),
        "webpage_scan": bench(lambda: call("/api/scan-page", {"url": "https://example.org/", "observations": PAGE | PAGE_CASES["scam overlay"], "preview": True})),
        "grammar_in_process": bench(lambda: writing_checks(PHISHING["text"])),
        "database_history_read": bench(lambda: call("/api/history")),
    }
    start = perf_counter()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: call("/api/privacy-redact", {"text": DEMO}), range(16)))
    assert all(result["total_redacted"] == 16 for result in results)
    print(json.dumps({"startup_ms": round(startup_ms, 1), "first_health_and_model_load_ms": round(cold_health_ms, 1),
                      "email": email_cases, "phishing": {"markers": sorted(ids), "safety_score": email["safety_score"],
                                                        "grammar_count": email["grammar"]["count"]},
                      "urls": urls, "webpage": webpage, "privacy_categories": redact["total_redacted"],
                      "approved_numeric_features": approved["features"], "measurements": measurements,
                      "concurrent_privacy_requests_total_ms": round((perf_counter()-start)*1000, 1)}, indent=2))


def main():
    with tempfile.TemporaryDirectory(prefix="sentinel-demo-") as tmp:
        env = os.environ | {"SENTINELAI_DB_PATH": str(Path(tmp) / "local/history.db"),
                            "SENTINELAI_THREATS_PATH": str(Path(tmp) / "local/threats.db"),
                            "SENTINELAI_LANGUAGETOOL_PORT": "", "PYTHONDONTWRITEBYTECODE": "1"}
        start = perf_counter()
        with subprocess.Popen([sys.executable, "-u", "-m", "backend.server", "0"], cwd=ROOT, env=env,
                              stdout=subprocess.PIPE, text=True) as server:
            try:
                line = server.stdout.readline()
                match = re.search(r"127\.0\.0\.1:(\d+)", line)
                if not match:
                    raise RuntimeError("Local demo backend did not start.")
                assert Path(env["SENTINELAI_DB_PATH"]).is_file()
                run("http://127.0.0.1:" + match[1], (perf_counter() - start) * 1000)
                # The optional review store is created on its first use.
                assert Path(env["SENTINELAI_THREATS_PATH"]).is_file()
            finally:
                server.terminate()


if __name__ == "__main__":
    main()
