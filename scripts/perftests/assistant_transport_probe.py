"""Measure actual assistant HTTP/LangGraph bounds with an explicitly fake model endpoint.

This checks transport, admission and cancellation. It cannot measure LLM speed,
answer quality or production model readiness, and never contacts Ollama.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.metadata import version
import json
from pathlib import Path
import platform
import secrets
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
    from assistant_service import create_app
    from werkzeug.serving import make_server

    started_hold = threading.Event()
    disconnected = threading.Event()

    class FakeModel(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.server.hold:
                started_hold.set()
                self.connection.settimeout(4)
                try:
                    if self.connection.recv(1) == b"":
                        disconnected.set()
                except OSError:
                    pass
                return
            time.sleep(.03)
            payload = json.dumps({"done": True, "message": {"content": "Réponse de transport prédéfinie. Aucun vrai modèle n'a été interrogé."}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *unused):
            pass

    fake = ThreadingHTTPServer(("127.0.0.1", 0), FakeModel)
    fake.hold = False
    fake_thread = threading.Thread(target=fake.serve_forever, daemon=True)
    fake_thread.start()
    servers, threads = [], []
    with tempfile.TemporaryDirectory(prefix="cybershield-assistant-readiness-") as temporary:
        token_path = Path(temporary) / "token.txt"
        token = secrets.token_hex(32)
        token_path.write_text(token, encoding="utf-8")

        def start_service(limit=100):
            app = create_app(token_file=token_path, ollama_url=f"http://127.0.0.1:{fake.server_port}",
                             model="fixture-model-not-an-llm", timeout_seconds=2, rate_limit=limit,
                             status_runner=lambda: {"model_installed": False, "model_loaded": False})
            server = make_server("127.0.0.1", 0, app, threaded=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
            return app, f"http://127.0.0.1:{server.server_port}"

        def ask(base, question):
            started = time.perf_counter()
            payload = json.dumps({"question": question, "context": {"totals": {"events": 10, "blocked": 2}}}).encode()
            req = Request(base + "/chat", data=payload, method="POST",
                          headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
            try:
                with build_opener(ProxyHandler({})).open(req, timeout=4) as response:
                    status, body = response.status, json.loads(response.read(65536))
            except HTTPError as exc:
                status, body = exc.code, json.loads(exc.read(65536))
            return {"status": status, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "source": body.get("source"), "kind": body.get("kind"), "error": body.get("error")}

        try:
            app, base = start_service()
            locals_ = [ask(base, "Bonjour") for _ in range(12)]
            free = ask(base, "Comment interpréter les signaux ambigus pour mon équipe ?")
            fake.hold = True
            slow_outcome = []
            slow_thread = threading.Thread(target=lambda: slow_outcome.append(ask(base, "Analyse libre lente de mes signaux ambigus")))
            slow_thread.start()
            if not started_hold.wait(1):
                raise RuntimeError("The real LangGraph path did not reach the fixture model endpoint")
            busy = ask(base, "Une autre question libre en parallèle")
            local_during = ask(base, "Bonjour")
            slow_thread.join(timeout=4)
            closed = disconnected.wait(.5)
            lock = app.extensions["cybershield_assistant_inference_lock"]
            released = lock.acquire(timeout=.5)
            if released:
                lock.release()
            fake.hold = False
            recovered = ask(base, "Explique librement un signal ambigu après expiration")
            _, admission_base = start_service(limit=2)
            admission = [ask(admission_base, "Bonjour") for _ in range(3)]
            checks = {
                "local_http_answers_under_one_second": all(row["status"] == 200 and row["source"] == "local" and row["elapsed_ms"] < 1000 for row in locals_),
                "actual_langgraph_and_model_http_transport_completed": free["status"] == 200 and free["source"] == "llm",
                "parallel_inference_refused_without_wait": busy["status"] == 429 and busy["error"] == "assistant_busy" and busy["elapsed_ms"] < 1000,
                "local_response_available_during_inference": local_during["status"] == 200 and local_during["source"] == "local" and local_during["elapsed_ms"] < 1000,
                "two_second_deadline_respected": len(slow_outcome) == 1 and slow_outcome[0]["status"] == 504 and 1800 <= slow_outcome[0]["elapsed_ms"] < 2800,
                "actual_model_socket_closed": closed,
                "gate_released_after_transport_stopped": released,
                "free_route_recovers_after_timeout": recovered["status"] == 200,
                "service_admission": [row["status"] for row in admission] == [200, 200, 429],
            }
            times = sorted(row["elapsed_ms"] for row in locals_)
            report = {"schema": 1, "at_utc": datetime.now(timezone.utc).isoformat(),
                      "scope": "isolated_actual_http_langgraph_with_fake_model_transport", "real_llm_exercised": False,
                      "latency_claim": "Only service overhead and bounded cancellation with a fixture provider; not local LLM generation performance.",
                      "runtime": {"python": platform.python_version(), "flask": version("flask"), "langgraph": version("langgraph"), "os": platform.platform()},
                      "source_sha256": {name: hashlib.sha256((args.ia_root / name).read_bytes()).hexdigest() for name in ("assistant_service.py", "assistant_graph.py", "assistant_core.py")},
                      "local_http": {"count": len(times), "p50_ms": times[5], "p95_ms": times[-1]},
                      "free_question_with_fixture": free, "concurrent_request": busy, "local_during_inference": local_during,
                      "timeout": slow_outcome, "recovered": recovered, "admission": admission,
                      "checks": checks, "passed": all(checks.values()),
                      "remaining_production_gate": "Real model cold/warm latency and independently reviewed answer quality are still required."}
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open("x", encoding="utf-8") as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
            print(json.dumps({"report": str(args.report), "passed": report["passed"], "real_llm_exercised": False}))
            return 0 if report["passed"] else 1
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=1)
            fake.shutdown()
            fake.server_close()
            fake_thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
