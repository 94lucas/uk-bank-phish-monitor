"""Notification tests using a local HTTP server (no internet needed)."""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ukphish.alerts import build_payload, format_telegram, notify  # noqa: E402
from ukphish.config import load_settings  # noqa: E402
from ukphish.scoring import score_domain  # noqa: E402

SETTINGS = load_settings()


class _Recorder(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Recorder.received.append(({k.lower(): v for k, v in self.headers.items()}, json.loads(body)))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


class TestAlerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _Recorder)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/webhook/ukphish-detection"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        _Recorder.received.clear()

    def test_payload_contents(self):
        r = score_domain("monzo-payee-verify.top", SETTINGS)
        p = build_payload(r, "certstream", SETTINGS.thresholds)
        self.assertEqual(p["domain"], "monzo-payee-verify.top")
        self.assertEqual(p["domain_defanged"], "monzo-payee-verify[.]top")
        self.assertEqual(p["alert_threshold"], SETTINGS.thresholds["alert"])

    def test_telegram_message_is_escaped_and_defanged(self):
        r = score_domain("revolut-refund.shop", SETTINGS)
        r.reasons.append("<script>")
        text = format_telegram(r, "test")
        self.assertIn("revolut-refund[.]shop", text)
        self.assertIn("&lt;script&gt;", text)

    def test_n8n_receives_detection_with_token(self):
        r = score_domain("lloyds-secure-login.xyz", SETTINGS)
        env = {"N8N_WEBHOOK_URL": self.url, "N8N_WEBHOOK_TOKEN": "s3cret"}
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch("builtins.print"):
            notify(r, "certstream", SETTINGS.thresholds)
        self.assertEqual(len(_Recorder.received), 1)
        headers, body = _Recorder.received[0]
        self.assertEqual(headers.get("x-ukphish-token"), "s3cret")
        self.assertEqual(body["brand"], "Lloyds Bank")

    def test_failure_does_not_raise(self):
        r = score_domain("hsbc-verify.top", SETTINGS)
        env = {"N8N_WEBHOOK_URL": "http://127.0.0.1:1/nowhere"}
        with mock.patch.dict(os.environ, env, clear=False), \
                mock.patch("builtins.print"), self.assertLogs("ukphish.alerts", "WARNING"):
            notify(r, "test", SETTINGS.thresholds)


if __name__ == "__main__":
    unittest.main()
