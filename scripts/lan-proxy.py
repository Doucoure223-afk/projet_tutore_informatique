"""Relay one private LAN address to the local Docker web port.

The peer's address is signed for CyberShield; client-supplied proxy headers are
never trusted. Only the Python standard library is needed on the Windows host.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
from http.client import HTTPConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import socket
import sys
import threading
import time


MAX_REQUEST_BODY = 64 * 1024
MAX_RESPONSE_BODY = 8 * 1024 * 1024
ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "OPTIONS"})
HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
})
IDENTITY_HEADERS = frozenset({
    "forwarded", "x-real-ip", "x-cybershield-client-ip",
    "x-cybershield-timestamp", "x-cybershield-signature",
})
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
))
HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def canonical_ip(value: str) -> str:
    if "%" in value:
        raise ValueError("Scoped addresses are not supported.")
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


def load_secret(path: Path) -> bytes:
    try:
        value = path.read_bytes().strip()
    except OSError:
        raise ValueError("The LAN relay secret file cannot be read.") from None
    if not 32 <= len(value) <= 4096 or any(char < 33 or char > 126 for char in value):
        raise ValueError("The LAN relay secret must contain 32 to 4096 printable ASCII characters.")
    return value


def request_signature(secret: bytes, client_ip: str, timestamp: str, method: str, target: str) -> str:
    message = "v1\n" + canonical_ip(client_ip) + "\n" + timestamp + "\n" + method + "\n" + target
    return hmac.new(secret, message.encode("utf-8"), hashlib.sha256).hexdigest()


def validate_bind_address(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError("--bind must be one private IPv4 address of this computer.") from None
    if not any(address in network for network in PRIVATE_NETWORKS):
        raise ValueError("--bind must be a private LAN IPv4 address, not a wildcard or loopback.")
    # Binding an ephemeral local socket proves that the address belongs to this
    # machine; it does not contact another device or open the relay yet.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind((str(address), 0))
    except OSError:
        raise ValueError("The requested LAN IPv4 address is not available on this computer.") from None
    return str(address)


def connection_tokens(headers) -> set[str]:
    return {
        token.strip().lower()
        for value in headers.get_all("Connection", [])
        for token in value.split(",")
        if token.strip()
    }


def normalized_header(name: str) -> str:
    # CGI/PHP maps separators to underscores. Strip equivalent spellings too,
    # so a client cannot shadow the signed headers through X_CyberShield_... .
    return name.lower().replace("_", "-").replace(".", "-")


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8
    allow_reuse_address = False

    def __init__(self, address, secret: bytes, upstream_port: int = 8080, timeout: float = 20.0):
        self.secret = secret
        self.upstream_port = upstream_port
        self.upstream_timeout = timeout
        self._workers = threading.BoundedSemaphore(8)
        super().__init__(address, RelayHandler)

    def process_request(self, request, client_address):
        if not self._workers.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n"
                    b"Content-Length: 0\r\nRetry-After: 2\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._workers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._workers.release()

    def handle_error(self, request, client_address):
        # The default traceback can contain request data. Log only a fixed event.
        print("LAN relay: a client connection ended unexpectedly.", file=sys.stderr, flush=True)


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "CyberShieldLAN"
    sys_version = ""
    timeout = 10.0

    def setup(self):
        super().setup()
        self.connection.settimeout(self.timeout)

    def log_message(self, _format, *_args):
        # BaseHTTPRequestHandler logs the full query and error details by default.
        pass

    def log_request(self, code="-", size="-"):
        path = getattr(self, "path", "").split("?", 1)[0][:256]
        path = "".join(char if 32 <= ord(char) <= 126 else "?" for char in path)
        print(json.dumps({
            "method": getattr(self, "command", "")[:16],
            "path": path,
            "peer": canonical_ip(self.client_address[0]),
            "status": code,
        }, ensure_ascii=True), file=sys.stderr, flush=True)

    def handle_expect_100(self):
        self.reject(417, "Expect is not supported by this relay.")
        return False

    def parse_request(self):
        if not super().parse_request():
            return False
        self.close_connection = True
        if self.request_version not in {"HTTP/1.0", "HTTP/1.1"}:
            self.reject(505, "Unsupported HTTP version.")
            return False
        if self.command not in ALLOWED_METHODS:
            self.reject(405, "Method not allowed.", allow=True)
            return False
        # origin-form only; no absolute URLs, network-path targets or fragments.
        # The exact accepted bytes (including the query) are signed upstream.
        raw_target = self.requestline.split()[1]
        if (not self.path.startswith("/") or raw_target.startswith("//")
                or "#" in self.path
                or any(ord(char) < 33 or ord(char) > 126 for char in self.path)):
            self.reject(400, "Invalid request target.")
            return False
        if self.headers.defects:
            self.reject(400, "Malformed request headers.")
            return False
        if self.headers.get_all("Transfer-Encoding"):
            self.reject(400, "Transfer-Encoding is not supported.")
            return False
        if self.headers.get_all("Expect"):
            self.reject(417, "Expect is not supported by this relay.")
            return False
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1 or (lengths and not re.fullmatch(r"[0-9]{1,10}", lengths[0])):
            self.reject(400, "Invalid Content-Length.")
            return False
        self.body_length = int(lengths[0]) if lengths else 0
        if self.body_length > MAX_REQUEST_BODY:
            self.reject(413, "Request body exceeds 64 KiB.")
            return False
        return True

    def reject(self, status: int, message: str, *, allow: bool = False):
        self.close_connection = True
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if allow:
            self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except OSError:
                pass

    def relay(self):
        try:
            body = self.rfile.read(self.body_length) if self.body_length else b""
        except (OSError, TimeoutError):
            self.reject(408, "Request body was not received in time.")
            return
        if len(body) != self.body_length:
            self.reject(400, "Incomplete request body.")
            return

        omitted = HOP_HEADERS | IDENTITY_HEADERS | connection_tokens(self.headers) | {"host", "content-length"}
        forwarded = [
            (name, value) for name, value in self.headers.items()
            if name.lower() not in omitted and normalized_header(name) not in omitted
            and not normalized_header(name).startswith("x-forwarded-")
        ]
        if any(not HEADER_NAME.fullmatch(name) or "\r" in value or "\n" in value
               for name, value in forwarded):
            self.reject(400, "Malformed request headers.")
            return

        client_ip = canonical_ip(self.client_address[0])
        timestamp = str(int(time.time()))
        connection = HTTPConnection("127.0.0.1", self.server.upstream_port,
                                    timeout=self.server.upstream_timeout)
        try:
            connection.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
            connection.putheader("Host", f"127.0.0.1:{self.server.upstream_port}")
            for name, value in forwarded:
                connection.putheader(name, value)
            connection.putheader("X-CyberShield-Client-IP", client_ip)
            connection.putheader("X-CyberShield-Timestamp", timestamp)
            connection.putheader("X-CyberShield-Signature", request_signature(
                self.server.secret, client_ip, timestamp, self.command, self.path,
            ))
            connection.putheader("Content-Length", str(len(body)))
            connection.putheader("Connection", "close")
            connection.endheaders(body)
            response = connection.getresponse()
            if response.status < 200 or response.status == 101:
                raise HTTPException("Unsupported upstream status")
            payload = response.read(MAX_RESPONSE_BODY + 1)
            if len(payload) > MAX_RESPONSE_BODY:
                raise HTTPException("Upstream response too large")
            response_headers = response.getheaders()
            if any(not HEADER_NAME.fullmatch(name) or "\r" in value or "\n" in value
                   for name, value in response_headers):
                raise HTTPException("Invalid upstream headers")
            response_omitted = HOP_HEADERS | connection_tokens(response.headers) | {"content-length"}
            # Never return the authentication envelope, even if an upstream
            # diagnostic accidentally echoes it.
            response_omitted |= IDENTITY_HEADERS
            self.send_response_only(response.status)
            self.log_request(response.status)
            for name, value in response_headers:
                if name.lower() not in response_omitted and normalized_header(name) not in response_omitted:
                    self.send_header(name, value)
            if self.command == "HEAD" or response.status == 304:
                length = response.getheader("Content-Length")
                if length and re.fullmatch(r"[0-9]{1,10}", length):
                    self.send_header("Content-Length", length)
            elif response.status != 204:
                self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD" and response.status not in {204, 304}:
                self.wfile.write(payload)
        except (TimeoutError, socket.timeout):
            self.reject(504, "The local application did not respond in time.")
        except (HTTPException, OSError, ValueError):
            self.reject(502, "The local application is unavailable.")
        finally:
            connection.close()

    do_GET = relay
    do_HEAD = relay
    do_POST = relay
    do_OPTIONS = relay


def port_number(value: str) -> int:
    if not value.isdecimal() or not 1 <= int(value) <= 65535:
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535.")
    return int(value)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="Private IPv4 address of this Windows computer")
    parser.add_argument("--port", type=port_number, default=8081)
    parser.add_argument("--upstream-port", type=port_number, default=8080)
    parser.add_argument("--secret-file", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        address = validate_bind_address(args.bind)
        secret = load_secret(args.secret_file)
        server = RelayServer((address, args.port), secret, args.upstream_port)
    except (ValueError, OSError) as exc:
        # Validation errors contain no secret values or external request data.
        print(f"LAN relay could not start: {exc}", file=sys.stderr)
        return 2
    print(f"CyberShield LAN relay listening on http://{address}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
