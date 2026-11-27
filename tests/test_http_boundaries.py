"""Defensive request-handling checks against an isolated local HTTP server."""
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch

from backend import server


class LocalHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.path = Path(directory.name)
        env = patch.dict("os.environ", SENTINELAI_DB_PATH=str(cls.path / "local/history.db"),
                         SENTINELAI_THREATS_PATH=str(cls.path / "local/threats.db"))
        env.start()
        cls.addClassCleanup(env.stop)
        server.init_db()
        cls.http = server.SentinelHTTPServer(("127.0.0.1", 0), server.SentinelAPIHandler)
        cls.addClassCleanup(cls.http.server_close)
        worker = Thread(target=cls.http.serve_forever, daemon=True)
        worker.start()
        cls.addClassCleanup(worker.join)
        cls.addClassCleanup(cls.http.shutdown)

    def request(self, method, path, data=None, **headers):
        conn = HTTPConnection("127.0.0.1", self.http.server_port, timeout=5)
        try:
            conn.request(method, path, data, headers)
            response = conn.getresponse()
            raw = response.read()
            return response.status, dict(response.getheaders()), json.loads(raw) if raw else None
        finally:
            conn.close()

    def test_approved_origins_receive_scoped_preflight(self):
        page = "http://127.0.0.1:4173"
        status, headers, _ = self.request("GET", "/api/health", Origin=page)
        self.assertEqual((status, headers["Access-Control-Allow-Origin"]), (200, page))
        gmail = {"Origin": "https://mail.google.com", "Access-Control-Request-Method": "POST"}
        status, _, _ = self.request("OPTIONS", "/api/scan-email", **gmail)
        self.assertEqual(status, 204)
        status, headers, _ = self.request("GET", "/api/threats/export", Origin=gmail["Origin"])
        self.assertEqual(status, 403)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        status, _, _ = self.request("GET", "/api/health", **{"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)

    def test_json_errors_do_not_echo_submitted_values(self):
        status, _, result = self.request("GET", "/api/history?limit=synthetic-input")
        self.assertEqual(status, 400)
        self.assertNotIn("synthetic-input", result["error"])
        status, _, _ = self.request("POST", "/api/privacy-redact", "{", **{"Content-Type": "application/json"})
        self.assertEqual(status, 400)
        status, _, _ = self.request("POST", "/api/privacy-redact", "sample", **{"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_release_accepts_current_extension_and_rejects_retired_origin(self):
        self.assertTrue(server.EXTENSION_ID)
        current = f"chrome-extension://{server.EXTENSION_ID}"
        status, headers, _ = self.request("GET", "/api/health", Origin=current)
        self.assertEqual((status, headers["Access-Control-Allow-Origin"]), (200, current))
        retired = "chrome-extension://gdjpcobloppjokojdgcidaopbpnfmoki"
        status, headers, _ = self.request("GET", "/api/health", Origin=retired)
        self.assertEqual(status, 403)
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_parallel_privacy_audits_and_large_preview(self):
        body = json.dumps({"text": "Contact demo@example.org"})
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: self.request("POST", "/api/privacy-redact", body,
                                  **{"Content-Type": "application/json"}), range(16)))
        self.assertTrue(all(status == 200 and result["total_redacted"] == 1 for status, _, result in responses))
        self.assertEqual(self.request("GET", "/api/stats")[2]["items_redacted"], 16)
        large = json.dumps({"text": "Ordinary meeting notes. " * 1500, "preview": True})
        self.assertEqual(self.request("POST", "/api/privacy-redact", large,
                         **{"Content-Type": "application/json"})[2]["total_redacted"], 0)

    def test_database_error_is_generic(self):
        with patch.object(server, "get_recent_history", side_effect=OSError("synthetic local path")):
            status, _, result = self.request("GET", "/api/history")
        self.assertEqual(status, 500)
        self.assertEqual(result["error"], "The local operation failed.")
