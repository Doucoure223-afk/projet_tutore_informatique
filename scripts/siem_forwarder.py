"""Deliver CyberShield's durable, privacy-filtered outbox to an HTTPS SIEM endpoint."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

OUTBOX = Path(os.environ.get("CYBERSHIELD_SIEM_OUTBOX", "/var/lib/cybershield/logs/siem-outbox"))
TOKEN_FILE = Path(os.environ.get("CYBERSHIELD_SIEM_TOKEN_FILE", "/run/secrets/siem_token"))
QUEUE_FILE = re.compile(r"^[a-f0-9]{64}\.json$")


class DeliveryError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def validate_destination(url: str, allow_http: bool = False) -> str:
    parts = urlsplit(url)
    allowed_schemes = {"https"} | ({"http"} if allow_http else set())
    if (parts.scheme not in allowed_schemes or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment):
        raise ValueError("Configure a complete HTTPS collector URL without credentials or query parameters.")
    try:
        parts.port
    except ValueError as exc:
        raise ValueError("Invalid SIEM collector port.") from exc
    return url


def load_token(path: Path) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("SIEM bearer-token secret is unreadable.") from exc
    if not token or len(token) > 4096 or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ValueError("SIEM bearer-token secret is empty or invalid.")
    return token


def send_event(url: str, token: str, event: dict, *, allow_http: bool = False, timeout: float = 5.0,
               opener=None) -> None:
    validate_destination(url, allow_http=allow_http)
    request_id = event.get("request_id") or event.get("id")
    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
        raise DeliveryError("Event has no valid idempotency key.")
    body = json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "Authorization": "Bearer " + token, "Idempotency-Key": request_id}
    request = Request(url, data=body, headers=headers, method="POST")
    sender = opener or build_opener(NoRedirect())
    try:
        with sender.open(request, timeout=timeout) as response:
            response.read(4096)  # Bound response memory; its content is never logged.
            if not 200 <= response.status < 300:
                raise DeliveryError(f"SIEM collector returned HTTP {response.status}.")
    except HTTPError as exc:
        exc.close()
        raise DeliveryError(f"SIEM collector returned HTTP {exc.code}.") from None
    except (URLError, TimeoutError, OSError) as exc:
        raise DeliveryError(f"SIEM delivery failed ({type(exc).__name__}).") from None


def pending_events(directory: Path) -> list[tuple[Path, dict]]:
    entries = []
    for path in directory.iterdir():
        if not QUEUE_FILE.fullmatch(path.name) or not path.is_file():
            continue
        try:
            event = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DeliveryError("An outbox record is unreadable; local incident logs remain available.") from exc
        if not isinstance(event, dict):
            raise DeliveryError("An outbox record is not a JSON object.")
        entries.append((path, event))
    entries.sort(key=lambda item: (str(item[1].get("timestamp", "")), str(item[1].get("request_id", ""))))
    return entries


def run_forever() -> None:
    url = validate_destination(os.environ.get("CYBERSHIELD_SIEM_URL", ""),
                              allow_http=os.environ.get("CYBERSHIELD_SIEM_ALLOW_HTTP") == "1")
    token = load_token(TOKEN_FILE)
    if not OUTBOX.is_dir():
        raise ValueError("The SIEM outbox volume is unavailable.")
    sender = build_opener(NoRedirect())
    failures = 0
    print("CyberShield SIEM forwarder ready; waiting for queued security events.", flush=True)
    while True:
        try:
            batch = pending_events(OUTBOX)[:25]
            if not batch:
                failures = 0
                time.sleep(2)
                continue
            for path, event in batch:
                send_event(url, token, event, allow_http=url.startswith("http://"), opener=sender)
                path.unlink()
            failures = 0
        except DeliveryError as exc:
            failures += 1
            delay = min(300, 2 ** min(failures, 8))
            print(f"{exc} Retrying in {delay} seconds.", file=sys.stderr, flush=True)
            time.sleep(delay)
        except OSError as exc:
            failures += 1
            delay = min(300, 2 ** min(failures, 8))
            print(f"Outbox operation failed ({type(exc).__name__}); retrying in {delay} seconds.",
                  file=sys.stderr, flush=True)
            time.sleep(delay)


if __name__ == "__main__":
    try:
        run_forever()
    except ValueError as error:
        print(f"SIEM forwarder configuration error: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)
