"""Isolated HTTP tests; no real client events, Docker or external service."""

from contextlib import redirect_stderr
import hashlib
import hmac
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "lan-proxy.py"
SPEC = importlib.util.spec_from_file_location("lan_proxy", MODULE_PATH)
lan_proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lan_proxy)
TEST_SECRET = b"local-test-key-with-at-least-32-characters"


class BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received = []
    status = 200
    response_body = b"local result"
    delay = 0

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.received.append((self.command, self.path, self.headers, body))
        if self.delay:
            time.sleep(self.delay)
        self.send_response(self.status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Set-Cookie", "session=opaque-value; HttpOnly; SameSite=Lax")
        self.send_header("Set-Cookie", "preference=light; SameSite=Lax")
        self.send_header("Connection", "close, X-Internal-Hop")
        self.send_header("X-Internal-Hop", "omit-me")
        self.send_header("X-CyberShield-Signature", "do-not-echo")
        self.send_header("Location", "/app/dashboard.php")
        self.send_header("Content-Length", str(len(self.response_body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(self.response_body)
            except OSError:
                pass

    do_GET = respond
    do_HEAD = respond
    do_POST = respond
    do_OPTIONS = respond

    def log_message(self, *_args):
        pass


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
        cls.backend_thread = threading.Thread(target=cls.backend.serve_forever, daemon=True)
        cls.backend_thread.start()
        cls.relay = lan_proxy.RelayServer(("127.0.0.1", 0), TEST_SECRET,
                                         upstream_port=cls.backend.server_port, timeout=1)
        cls.relay_thread = threading.Thread(target=cls.relay.serve_forever, daemon=True)
        cls.relay_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.relay.shutdown()
        cls.relay.server_close()
        cls.relay_thread.join(timeout=2)
        cls.backend.shutdown()
        cls.backend.server_close()
        cls.backend_thread.join(timeout=2)

    def setUp(self):
        BackendHandler.received.clear()
        BackendHandler.status = 200
        BackendHandler.response_body = b"local result"
        BackendHandler.delay = 0

    def request(self, method="GET", target="/app/search.php", body=None, headers=None):
        client = HTTPConnection("127.0.0.1", self.relay.server_port, timeout=3)
        try:
            client.request(method, target, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, response.getheaders(), response.read()
        finally:
            client.close()

    def raw_request(self, request):
        with socket.create_connection(("127.0.0.1", self.relay.server_port), timeout=3) as client:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)

    def test_signature_uses_exact_uri_method_and_canonical_peer(self):
        target = "/app/search.php?q=%27+OR+1%3D1&x=%2f%2F"
        status, _, _ = self.request("POST", target, b"q=example", {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 200)
        method, path, headers, body = BackendHandler.received[0]
        self.assertEqual((method, path, body), ("POST", target, b"q=example"))
        self.assertEqual(headers["Host"], f"127.0.0.1:{self.backend.server_port}")
        self.assertEqual(headers["X-CyberShield-Client-IP"], "127.0.0.1")
        timestamp = headers["X-CyberShield-Timestamp"]
        self.assertLess(abs(time.time() - int(timestamp)), 3)
        message = f"v1\n127.0.0.1\n{timestamp}\nPOST\n{target}".encode()
        expected = hmac.new(TEST_SECRET, message, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-CyberShield-Signature"], expected)

    def test_client_supplied_identity_and_connection_headers_are_scrubbed(self):
        self.request(headers={
            "Host": "attacker.invalid", "Forwarded": "for=10.1.2.3",
            "X-Forwarded-For": "10.1.2.3", "X-Forwarded-Host": "attacker.invalid",
            "X-Forwarded-Proto": "https", "X-Real-IP": "10.1.2.3",
            "X-CyberShield-Client-IP": "10.1.2.3", "X-CyberShield-Timestamp": "1",
            "X-CyberShield-Signature": "forged", "Connection": "keep-alive, X-Private-Hop",
            "X_CyberShield_Client_IP": "10.9.9.9", "X_CyberShield_Signature": "underscore-forged",
            "X.Forwarded.For": "10.9.9.9",
            "X-Private-Hop": "omit", "Cookie": "session=client-cookie",
        })
        headers = BackendHandler.received[0][2]
        for name in ("Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP", "X-Private-Hop"):
            self.assertIsNone(headers.get(name))
        self.assertEqual(headers["Cookie"], "session=client-cookie")
        self.assertEqual(headers.get_all("X-CyberShield-Client-IP"), ["127.0.0.1"])
        self.assertIsNone(headers.get("X_CyberShield_Client_IP"))
        self.assertIsNone(headers.get("X_CyberShield_Signature"))
        self.assertIsNone(headers.get("X.Forwarded.For"))
        self.assertNotEqual(headers["X-CyberShield-Signature"], "forged")
        self.assertEqual(headers["Connection"], "close")

    def test_preserves_status_csp_multiple_cookies_and_relative_redirect(self):
        BackendHandler.status = 403
        status, headers, body = self.request()
        self.assertEqual(status, 403)
        self.assertEqual(body, b"local result")
        pairs = dict(headers)
        self.assertEqual(pairs["Content-Security-Policy"], "default-src 'self'")
        self.assertEqual(pairs["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(pairs["Location"], "/app/dashboard.php")
        self.assertEqual(sum(name.lower() == "set-cookie" for name, _ in headers), 2)
        self.assertNotIn("X-Internal-Hop", pairs)
        self.assertNotIn("X-CyberShield-Signature", pairs)
        self.assertEqual(pairs["Connection"], "close")

    def test_head_has_no_body_and_preserves_representation_length(self):
        status, headers, body = self.request("HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(dict(headers)["Content-Length"], str(len(b"local result")))

    def test_options_is_forwarded(self):
        self.assertEqual(self.request("OPTIONS")[0], 200)
        self.assertEqual(BackendHandler.received[0][0], "OPTIONS")

    def test_logs_do_not_contain_query_body_cookie_or_signature(self):
        output = io.StringIO()
        with redirect_stderr(output):
            self.request("POST", "/app/search.php?token=private-query", b"private-body", {
                "Cookie": "private-cookie", "X-CyberShield-Signature": "private-signature",
            })
        logged = output.getvalue()
        self.assertIn("/app/search.php", logged)
        self.assertIn("127.0.0.1", logged)
        for sensitive in ("private-query", "private-body", "private-cookie", "private-signature", TEST_SECRET.decode()):
            self.assertNotIn(sensitive, logged)

    def test_unsupported_methods_do_not_reach_backend(self):
        for method in ("CONNECT", "TRACE", "PUT", "DELETE", "PATCH"):
            with self.subTest(method=method):
                self.assertEqual(self.request(method)[0], 405)
        self.assertFalse(BackendHandler.received)

    def test_invalid_framing_and_targets_are_rejected(self):
        invalid = (
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: -1\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 0, 0\r\n\r\n",
            b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length:\r\n\r\n",
            b"GET http://attacker.invalid/ HTTP/1.1\r\nHost: local\r\n\r\n",
            b"GET /page#fragment HTTP/1.1\r\nHost: local\r\n\r\n",
        )
        for request in invalid:
            with self.subTest(request=request.split(b"\r\n", 1)[0]):
                self.assertTrue(self.raw_request(request).startswith(b"HTTP/1.1 400"))
        self.assertFalse(BackendHandler.received)

    def test_network_path_target_is_rejected_before_stdlib_normalization(self):
        result = self.raw_request(b"GET //attacker.invalid/path HTTP/1.1\r\nHost: local\r\n\r\n")
        self.assertTrue(result.startswith(b"HTTP/1.1 400"))
        self.assertFalse(BackendHandler.received)

    def test_expect_and_large_bodies_are_rejected(self):
        result = self.raw_request(b"POST / HTTP/1.1\r\nHost: local\r\nExpect: 100-continue\r\nContent-Length: 1\r\n\r\n")
        self.assertTrue(result.startswith(b"HTTP/1.1 417"))
        result = self.raw_request(b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 65537\r\n\r\n")
        self.assertTrue(result.startswith(b"HTTP/1.1 413"))
        self.assertFalse(BackendHandler.received)

    def test_incomplete_body_is_rejected(self):
        result = self.raw_request(b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 5\r\n\r\nab")
        self.assertTrue(result.startswith(b"HTTP/1.1 400"))
        self.assertFalse(BackendHandler.received)

    def test_bounded_response_does_not_forward_partial_payload(self):
        BackendHandler.response_body = b"x" * 65
        with patch.object(lan_proxy, "MAX_RESPONSE_BODY", 64):
            status, _, body = self.request()
        self.assertEqual(status, 502)
        self.assertNotIn(b"x" * 65, body)

    def test_unavailable_upstream_returns_generic_error(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
            reserved.bind(("127.0.0.1", 0))
            with patch.object(self.relay, "upstream_port", reserved.getsockname()[1]):
                status, _, body = self.request()
        self.assertIn(status, (502, 504))
        self.assertNotIn(TEST_SECRET, body)

    def test_timeout_returns_gateway_timeout(self):
        BackendHandler.delay = 0.15
        with patch.object(self.relay, "upstream_timeout", 0.02):
            status, _, _ = self.request()
        self.assertEqual(status, 504)

    def test_worker_limit_rejects_additional_connections(self):
        # Occupy the eight permits without creating slow test-client requests.
        permits = []
        try:
            for _ in range(8):
                self.assertTrue(self.relay._workers.acquire(timeout=2))
                permits.append(True)
            result = self.raw_request(b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
            self.assertTrue(result.startswith(b"HTTP/1.1 503"))
            self.assertFalse(BackendHandler.received)
        finally:
            for _ in permits:
                self.relay._workers.release()


class ConfigurationTests(unittest.TestCase):
    def test_mapped_ipv6_is_signed_as_ipv4(self):
        self.assertEqual(lan_proxy.canonical_ip("::ffff:192.168.1.30"), "192.168.1.30")
        self.assertEqual(lan_proxy.request_signature(TEST_SECRET, "::ffff:192.168.1.30", "123", "GET", "/"),
                         lan_proxy.request_signature(TEST_SECRET, "192.168.1.30", "123", "GET", "/"))

    def test_only_private_local_ipv4_is_accepted_by_cli(self):
        for value in ("0.0.0.0", "127.0.0.1", "8.8.8.8", "::1", "169.254.10.1", "192.0.2.4"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                lan_proxy.validate_bind_address(value)
        with patch.object(lan_proxy.socket, "socket") as fake_socket:
            self.assertEqual(lan_proxy.validate_bind_address("192.168.1.5"), "192.168.1.5")
            fake_socket.return_value.__enter__.return_value.bind.assert_called_once_with(("192.168.1.5", 0))
        with patch.object(lan_proxy.socket, "socket") as fake_socket:
            fake_socket.return_value.__enter__.return_value.bind.side_effect = OSError("not local")
            with self.assertRaises(ValueError):
                lan_proxy.validate_bind_address("192.168.1.5")

    def test_secret_is_read_from_file_and_never_in_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relay-test-key.txt"
            path.write_bytes(TEST_SECRET + b"\r\n")
            self.assertEqual(lan_proxy.load_secret(path), TEST_SECRET)
            for value in (b"too-short", b"x" * 4097, b"x" * 32 + b"\x00", b"x" * 32 + b"\xff"):
                path.write_bytes(value)
                with self.assertRaises(ValueError) as caught:
                    lan_proxy.load_secret(path)
                self.assertNotIn(repr(value), str(caught.exception))

    def test_ports_have_valid_bounds(self):
        self.assertEqual(lan_proxy.port_number("8081"), 8081)
        for value in ("0", "65536", "-1", "bad"):
            with self.subTest(value=value), self.assertRaises(Exception):
                lan_proxy.port_number(value)


if __name__ == "__main__":
    unittest.main()
