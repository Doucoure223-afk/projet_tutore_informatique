"""Isolated real HTTP test of the MLP service's 420/min admission and missing-model failure.

No real model is loaded in this fixture. It verifies admission, not throughput of inference.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import argparse
from collections import Counter
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import platform
import sys
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.request import build_opener, ProxyHandler, Request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ia-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.ia_root))
    from service import create_app
    from werkzeug.serving import make_server, WSGIRequestHandler

    class QuietHandler(WSGIRequestHandler):
        def log_request(self, *unused):
            pass

    with tempfile.TemporaryDirectory(prefix="cybershield-model-admission-") as temporary:
        app = create_app(Path(temporary) / "deliberately-missing-model.joblib")
        server = make_server("127.0.0.1", 0, app, threaded=True, request_handler=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def submit(index):
            started = time.perf_counter()
            req = Request(f"http://127.0.0.1:{server.server_port}/analyse", method="POST", data=b'{"sql":"Bonjour Bamako"}',
                          headers={"Content-Type": "application/json", "X-Forwarded-For": f"192.0.2.{index % 250 + 1}"})
            try:
                with build_opener(ProxyHandler({})).open(req, timeout=5) as response:
                    status, payload, retry = response.status, json.loads(response.read(65536)), response.headers.get("Retry-After")
            except HTTPError as exc:
                status, payload, retry = exc.code, json.loads(exc.read(65536)), exc.headers.get("Retry-After")
            return {"status": status, "error": payload.get("error"), "has_risk": "risk" in payload,
                    "retry_after": retry, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)}
        try:
            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows = list(pool.map(submit, range(425)))
            duration = time.perf_counter() - started
            statuses = dict(Counter(str(row["status"]) for row in rows))
            passed = duration < 60 and statuses == {"503": 420, "429": 5} and all(not row["has_risk"] for row in rows) and all(
                row["retry_after"] is not None for row in rows if row["status"] == 429)
            report = {"schema": 1, "at_utc": datetime.now(timezone.utc).isoformat(),
                      "scope": "isolated_actual_mlp_service_http_admission_without_model", "real_inference_exercised": False,
                      "limit_per_minute": 420, "requests": 425, "concurrency": 8, "duration_seconds": round(duration, 4),
                      "status_counts": statuses, "forwarded_ip_rotation_did_not_bypass_limit": statuses.get("429") == 5,
                      "missing_model_never_returned_a_risk": all(not row["has_risk"] for row in rows),
                      "source_sha256": hashlib.sha256((args.ia_root / "service.py").read_bytes()).hexdigest(),
                      "runtime": {"python": platform.python_version(), "flask": version("flask"), "sklearn": version("scikit-learn")},
                      "latency_ms": {"p50": sorted(row["elapsed_ms"] for row in rows)[212], "p95": sorted(row["elapsed_ms"] for row in rows)[403]},
                      "passed": passed,
                      "limitation": "The unavailable-model fixture isolates admission and cannot measure inference capacity or field effectiveness."}
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            print(json.dumps({"report": str(args.report), "passed": passed, "statuses": statuses}))
            return 0 if passed else 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
