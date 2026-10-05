import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "siem_forwarder.py"
SPEC = importlib.util.spec_from_file_location("siem_forwarder", MODULE_PATH)
siem_forwarder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(siem_forwarder)


class CollectorHandler(BaseHTTPRequestHandler):
    code = 204
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.received.append((self.headers, json.loads(body)))
        self.send_response(self.code)
        self.end_headers()

    def log_message(self, *_args):
        pass


class SiemForwarderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), CollectorHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/events"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        CollectorHandler.code = 204
        CollectorHandler.received.clear()

    def test_destination_requires_https_unless_explicitly_allowed(self):
        with self.assertRaises(ValueError):
            siem_forwarder.validate_destination(self.url)
        self.assertEqual(siem_forwarder.validate_destination(self.url, allow_http=True), self.url)
        for unsafe in ("https://user:pass@siem.invalid/events", "https://siem.invalid/events?token=x",
                       "https://siem.invalid/events#fragment", "file:///etc/passwd"):
            with self.subTest(url=unsafe), self.assertRaises(ValueError):
                siem_forwarder.validate_destination(unsafe)

    def test_delivery_adds_bearer_and_idempotency_headers(self):
        event = {"id": "event-123", "request_id": "event-123", "action": "BLOCKED"}
        siem_forwarder.send_event(self.url, "test-bearer-token", event, allow_http=True)
        headers, received = CollectorHandler.received[0]
        self.assertEqual(headers.get("Authorization"), "Bearer test-bearer-token")
        self.assertEqual(headers.get("Idempotency-Key"), "event-123")
        self.assertEqual(received, event)

    def test_non_success_collector_response_is_retryable(self):
        CollectorHandler.code = 503
        with self.assertRaisesRegex(siem_forwarder.DeliveryError, "HTTP 503"):
            siem_forwarder.send_event(self.url, "token", {"id": "e", "request_id": "e"}, allow_http=True)

    def test_redirect_is_not_followed(self):
        class RedirectHandler(CollectorHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location", "https://other.invalid/events")
                self.end_headers()

        redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=redirect_server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{redirect_server.server_port}/events"
            with self.assertRaisesRegex(siem_forwarder.DeliveryError, "HTTP 302"):
                siem_forwarder.send_event(url, "token", {"id": "e", "request_id": "e"}, allow_http=True)
        finally:
            redirect_server.shutdown()
            redirect_server.server_close()
            thread.join(timeout=2)

    def test_queue_orders_events_and_ignores_temporary_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / ("a" * 64 + ".json")).write_text(json.dumps({"timestamp": "2026-01-02", "request_id": "later"}))
            (path / ("b" * 64 + ".json")).write_text(json.dumps({"timestamp": "2026-01-01", "request_id": "earlier"}))
            (path / ".pending-event").write_text("partial")
            events = siem_forwarder.pending_events(path)
            self.assertEqual([event[1]["request_id"] for event in events], ["earlier", "later"])


if __name__ == "__main__":
    unittest.main()
