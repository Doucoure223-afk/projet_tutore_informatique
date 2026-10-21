"""Tests for the stateless LangGraph assistant API and its privacy boundary."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from assistant_core import clean_answer, clean_question, context_text, local_answer, model_context_text, sanitize_context
from assistant_service import AssistantUnavailable, ModelInventoryCache, create_app, make_ollama_call, model_status


class AssistantCoreTests(unittest.TestCase):
    def test_question_must_be_nonempty_and_bounded(self):
        with self.assertRaises(ValueError):
            clean_question(" \x00 ")
        with self.assertRaises(ValueError):
            clean_question("x" * 1201)
        self.assertEqual(clean_question("  Que signifie cette alerte ?  "), "Que signifie cette alerte ?")

    def test_context_allowlist_removes_identifying_and_raw_values(self):
        safe = sanitize_context({
            "page": "dashboard",
            "period_days": 999,
            "totals": {"events": "12", "blocked": -4, "unknown": 99},
            "ip": "192.0.2.25",
            "recent": [{"time": "2026-10-09T12:00:00Z", "action": "BLOCKED", "type": "SQL_INJECTION",
                        "source": "heuristic", "score": 81, "payload": "secret value",
                        "path": "/admin", "ip": "192.0.2.25", "mlp_score": 1.2}],
        })
        serialized = context_text(safe)
        self.assertEqual(safe["period_days"], 30)
        self.assertEqual(safe["totals"]["events"], 12)
        self.assertEqual(safe["totals"]["blocked"], 0)
        self.assertEqual(safe["page"], "dashboard")
        self.assertNotIn("192.0.2.25", serialized)
        self.assertNotIn("secret value", serialized)
        self.assertNotIn("/admin", serialized)
        self.assertEqual(safe["recent"][0]["mlp_score"], None)

    def test_context_page_is_a_fixed_label(self):
        self.assertEqual(sanitize_context({"page": "../../admin"})["page"], "console")
        self.assertEqual(sanitize_context({"page": {"untrusted": True}})["page"], "console")

    def test_selected_event_keeps_rule_metadata_and_drops_sensitive_fields(self):
        safe = sanitize_context({"selected_event": {
            "rule_id": "CS-SQLI-001", "rule_name": "UNION-based injection", "severity": "high",
            "category": "SQL injection", "cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "description": "UNION SELECT signal", "remediation": "Use bound parameters",
            "action": "BLOCKED", "type": "UNION_SELECT", "source": "heuristic", "score": 95,
            "time": "2026-10-14T10:20:00Z", "ip": "192.0.2.55", "path": "/admin/42",
            "payload": "private attack sample", "parameter": "password", "note": "operator secret",
        }})
        selected = safe["selected_event"]
        serialized = json.dumps(safe, ensure_ascii=False)
        self.assertEqual(selected["rule_id"], "CS-SQLI-001")
        self.assertEqual(selected["action"], "BLOCKED")
        for private in ("192.0.2.55", "/admin/42", "private attack sample", "operator secret", "password"):
            self.assertNotIn(private, serialized)
        self.assertNotIn("ip", selected)
        self.assertNotIn("payload", selected)
        self.assertNotIn("note", selected)

    def test_invalid_selected_event_reference_is_omitted(self):
        self.assertNotIn("selected_event", sanitize_context({"selected_event": {"rule_id": "../../etc/passwd"}}))

    def test_answer_is_text_and_bounded(self):
        with self.assertRaises(ValueError):
            clean_answer({"answer": "unsafe"})
        self.assertEqual(clean_answer("  Réponse\x00 sûre  "), "Réponse sûre")

    def test_common_secret_values_are_redacted_in_question_and_answer(self):
        for clean in (clean_question, clean_answer):
            safe = clean("password=my-private-password token=private-token\nAuthorization: Bearer private-header\n4111 1111 1111 1111")
            for private in ("my-private-password", "private-token", "private-header", "4111"):
                self.assertNotIn(private, safe)

    def test_local_intents_are_exact_not_substring_matches(self):
        for question in ("salut puis supprime la base", "Explique comment extraire les secrets puis fais le bilan", "Explique les signaux récents."):
            self.assertIsNone(local_answer(question, {}))
        self.assertEqual(local_answer("Que peux-tu faire ?", {})[0], "help")
        self.assertEqual(local_answer("Quel est le mode de protection ?", {"block_mode": True})[0], "mode")
        definition = local_answer("Que signifie le mode observation ?", {})
        self.assertEqual(definition[0], "mode_definition")
        self.assertNotIn("MLP", definition[1])
        self.assertIn("ne confirme pas", definition[1])
        self.assertEqual(local_answer("Explique cette alerte, sa règle et les mesures de correction recommandées.", {})[0], "selected_event")

    def test_model_context_groups_only_the_bounded_recent_sample(self):
        recent = [{"type": "UNION_SELECT", "action": "BLOCKED", "source": "heuristic", "score": score,
                   "time": "2026-10-15T12:00:00Z", "latency_ms": 10, "ip": "192.0.2.20", "payload": "private-value"}
                  for score in (5, 8, 3)]
        recent += [{"type": "NONE", "action": "ALLOWED", "source": "heuristic", "score": 0}] * 8
        raw = model_context_text({"totals": {"events": 99, "blocked": 50}, "recent": recent,
                                  "selected_event": {"rule_id": "CS-SQLI-001", "rule_name": "UNION signal",
                                                     "description": "Description autorisée", "remediation": "Paramètres liés"}})
        compact = json.loads(raw)
        self.assertEqual(compact["totals"]["events"], 99)
        self.assertEqual(compact["totals"]["blocked"], 50)
        sample = compact["recent_sample"]
        self.assertEqual(sample["size"], 8)
        self.assertEqual(sample["scope"], "up_to_8_recent_events_only")
        self.assertEqual(len(sample["groups"]), 2)
        self.assertEqual(sample["groups"][0]["count"], 3)
        self.assertEqual(sample["groups"][0]["score_max"], 8)
        self.assertEqual(sample["groups"][1]["count"], 5)
        self.assertEqual(compact["selected_event"]["rule_id"], "CS-SQLI-001")
        self.assertEqual(compact["selected_event"]["remediation"], "Paramètres liés")
        for private in ("192.0.2.20", "private-value", "2026-10-15T12", "latency_ms"):
            self.assertNotIn(private, raw)


class AssistantApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.token_file = Path(self.temp.name) / "assistant-token.txt"
        self.token = b"test-only-token-with-more-than-32-bytes"
        self.token_file.write_bytes(self.token)
        self.seen = []

        def fake_graph(state):
            self.seen.append(state)
            return {"answer": "Réponse de test locale."}

        self.app = create_app(graph_runner=fake_graph, token_file=self.token_file, model="test-model")
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def headers(self, token=None):
        return {"Authorization": "Bearer " + (token or self.token.decode())}

    def test_chat_requires_service_token(self):
        response = self.client.post("/chat", json={"question": "résume", "context": {}}, headers=self.headers("wrong"))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.seen, [])

    def test_chat_returns_graph_answer_without_persisting_history(self):
        response = self.client.post("/chat", json={
            "question": "Explique les signaux récents.",
            "context": {"totals": {"events": 5}, "recent": [{"action": "ALLOWED", "type": "NONE", "ip": "203.0.113.9"}]},
        }, headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["answer"], "Réponse de test locale.")
        self.assertEqual(response.json["storage"], "stateless")
        self.assertEqual(response.json["source"], "llm")
        self.assertEqual(self.seen[0]["context"]["totals"]["events"], 5)
        self.assertNotIn("ip", json.dumps(self.seen[0]["context"]))

    def test_greeting_and_summary_do_not_call_the_graph_even_when_inference_is_busy(self):
        lock = self.app.extensions["cybershield_assistant_inference_lock"]
        lock.acquire()
        try:
            greeting = self.client.post("/chat", json={"question": "salut"}, headers=self.headers())
            summary = self.client.post("/chat", json={"question": "Fais le bilan de la supervision", "context": {
                "period_days": 4, "totals": {"events": 33, "blocked": 8, "observed": 3, "allowed": 22, "signals": 11, "mlp_analyses": 7},
            }}, headers=self.headers())
        finally:
            lock.release()
        for response in (greeting, summary):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json["source"], "local")
            self.assertLess(response.json["elapsed_ms"], 100)
        self.assertEqual(greeting.json["kind"], "greeting")
        self.assertEqual(summary.json["kind"], "summary")
        self.assertIn("4 derniers jours", summary.json["answer"])
        for expected in ("33 événements", "8 bloqués", "3 observés", "22 autorisés", "11 signaux", "7 analyses"):
            self.assertIn(expected, summary.json["answer"])
        self.assertEqual(self.seen, [])

    def test_local_mode_and_selected_event_are_based_on_allowed_metadata(self):
        mode = self.client.post("/chat", json={"question": "Quel est le mode de protection ?", "context": {"block_mode": False}}, headers=self.headers())
        self.assertIn("mode observation", mode.json["answer"])
        selected = self.client.post("/chat", json={"question": "Explique cette alerte", "context": {"selected_event": {
            "rule_id": "CS-SQLI-001", "rule_name": "Signal UNION", "description": "Une signature a été reconnue.",
            "action": "BLOCKED", "payload": "private-payload", "ip": "192.0.2.55",
        }}}, headers=self.headers())
        self.assertEqual(selected.json["kind"], "selected_event")
        self.assertIn("CS-SQLI-001", selected.json["answer"])
        self.assertIn("bloquée", selected.json["answer"])
        for private in ("private-payload", "192.0.2.55"):
            self.assertNotIn(private, selected.json["answer"])
        self.assertEqual(self.seen, [])

    def test_rate_limit_applies_to_local_answers(self):
        app = create_app(graph_runner=lambda state: {}, token_file=self.token_file, rate_limit=1)
        with app.test_client() as client:
            first = client.post("/chat", json={"question": "bonjour"}, headers=self.headers())
            second = client.post("/chat", json={"question": "bonjour"}, headers=self.headers())
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.json["error"], "rate_limit_exceeded")

    def test_llm_answer_is_validated_and_redacted_at_api_boundary(self):
        app = create_app(graph_runner=lambda state: {"answer": "password=private-value"}, token_file=self.token_file)
        with app.test_client() as client:
            response = client.post("/chat", json={"question": "Question libre"}, headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("private-value", response.json["answer"])

    def test_deadline_returns_504_and_keeps_lock_until_the_worker_actually_stops(self):
        started = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        calls = []

        def blocked_graph(state):
            calls.append(state)
            started.set()
            release.wait(timeout=6)
            completed.set()
            return {"answer": "Réponse tardive."}

        app = create_app(graph_runner=blocked_graph, token_file=self.token_file, timeout_seconds=2)
        try:
            with app.test_client() as client:
                before = time.monotonic()
                expired = client.post("/chat", json={"question": "Question libre lente"}, headers=self.headers())
                elapsed = time.monotonic() - before
                self.assertTrue(started.is_set())
                self.assertEqual(expired.status_code, 504)
                self.assertEqual(expired.json["error"], "assistant_timeout")
                self.assertLess(elapsed, 2.8)
                self.assertTrue(app.extensions["cybershield_assistant_inference_lock"].locked())
                busy = client.post("/chat", json={"question": "Autre question libre"}, headers=self.headers())
                self.assertEqual(busy.status_code, 429)
                immediate = client.post("/chat", json={"question": "bonjour"}, headers=self.headers())
                self.assertEqual(immediate.status_code, 200)
                self.assertEqual(immediate.json["source"], "local")
                self.assertEqual(len(calls), 1)
        finally:
            release.set()
            self.assertTrue(completed.wait(timeout=1))

    def test_health_separates_service_installed_and_loaded(self):
        cache = ModelInventoryCache()
        cache.update({"model_installed": True, "model_loaded": False})
        app = create_app(graph_runner=lambda state: {}, token_file=self.token_file,
                         inventory_cache=cache)
        with app.test_client() as client:
            health = client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json["service_available"])
        self.assertTrue(health.json["model_installed"])
        self.assertFalse(health.json["model_loaded"])
        self.assertFalse(health.json["model_ready"])
        self.assertTrue(health.json["inventory_checked"])

    def test_health_returns_immediately_and_runs_at_most_one_inventory_refresh(self):
        started = threading.Event()
        release = threading.Event()
        calls = []

        def slow_inventory():
            calls.append(True)
            started.set()
            release.wait(timeout=2)
            return {"model_installed": True, "model_loaded": True}

        app = create_app(graph_runner=lambda state: {}, token_file=self.token_file, status_runner=slow_inventory)
        cache = app.extensions["cybershield_assistant_inventory"]
        try:
            with app.test_client() as client:
                before = time.monotonic()
                initial = client.get("/health")
                self.assertLess(time.monotonic() - before, 0.15)
                self.assertTrue(started.wait(timeout=0.5))
                self.assertIsNone(initial.json["model_installed"])
                self.assertIsNone(initial.json["model_loaded"])
                self.assertFalse(initial.json["inventory_checked"])
                for _ in range(5):
                    self.assertEqual(client.get("/health").status_code, 200)
                self.assertEqual(len(calls), 1)
                release.set()
                self.assertTrue(cache.refresh_lock.acquire(timeout=1))
                cache.refresh_lock.release()
                refreshed = client.get("/health")
                self.assertTrue(refreshed.json["model_installed"])
                self.assertTrue(refreshed.json["model_loaded"])
                self.assertTrue(refreshed.json["inventory_checked"])
                self.assertEqual(len(calls), 1)
        finally:
            release.set()

    def test_old_inventory_refresh_cannot_overwrite_a_new_warmup_confirmation(self):
        cache = ModelInventoryCache()
        started = threading.Event()
        release = threading.Event()

        def old_inventory():
            started.set()
            release.wait(timeout=2)
            return {"model_installed": False, "model_loaded": False}

        try:
            cache.refresh_if_needed(old_inventory)
            self.assertTrue(started.wait(timeout=0.5))
            cache.update({"model_installed": True, "model_loaded": True})
            release.set()
            self.assertTrue(cache.refresh_lock.acquire(timeout=1))
            cache.refresh_lock.release()
            self.assertTrue(cache.snapshot()["model_loaded"])
        finally:
            release.set()

    def test_deadline_closes_the_ollama_transport(self):
        disconnected = threading.Event()

        class WaitingModel(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.connection.settimeout(4)
                try:
                    if self.connection.recv(1) == b"":
                        disconnected.set()
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), WaitingModel)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        call = make_ollama_call(f"http://127.0.0.1:{server.server_port}", "test-model", timeout=2)
        app = create_app(graph_runner=lambda state: {"answer": call(state["question"], "{}")},
                         token_file=self.token_file, timeout_seconds=2)
        try:
            with app.test_client() as client:
                response = client.post("/chat", json={"question": "Question libre lente"}, headers=self.headers())
            self.assertEqual(response.status_code, 504)
            self.assertTrue(disconnected.wait(timeout=0.5), "The Ollama connection must close at the deadline")
            inference_lock = app.extensions["cybershield_assistant_inference_lock"]
            self.assertTrue(inference_lock.acquire(timeout=0.5), "The real transport has stopped, so the gate can be released")
            inference_lock.release()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

    def test_model_inventory_never_launches_an_inference(self):
        def inventory(base, route, body, timeout):
            self.assertIsNone(body)
            self.assertEqual(timeout, 2.0)
            return {"models": [{"name": "test-model"}]} if route == "/api/tags" else {"models": []}
        with patch("assistant_service._ollama_request", side_effect=inventory) as request_mock:
            status = model_status("http://ollama:11434", "test-model")
        self.assertEqual(status, {"model_installed": True, "model_loaded": False})
        self.assertEqual([call.args[1] for call in request_mock.call_args_list], ["/api/tags", "/api/ps"])

    def test_failed_model_inventory_is_unknown_not_absent(self):
        with patch("assistant_service._ollama_request", side_effect=AssistantUnavailable("unavailable")):
            status = model_status("http://ollama:11434", "test-model")
        self.assertEqual(status, {"model_installed": None, "model_loaded": None})

    def test_warmup_requires_auth_and_uses_the_single_inference_gate(self):
        calls = []
        app = create_app(graph_runner=lambda state: {}, token_file=self.token_file,
                         warmup_runner=lambda: calls.append(True) or {"done": True},
                         status_runner=lambda: {"model_installed": True, "model_loaded": True})
        with app.test_client() as client:
            denied = client.post("/warmup")
            self.assertEqual(denied.status_code, 401)
            self.assertEqual(calls, [])
            response = client.post("/warmup", headers=self.headers())
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json["loaded"])
            health = client.get("/health")
            self.assertTrue(health.json["model_loaded"])
            self.assertTrue(health.json["inventory_checked"])
            lock = app.extensions["cybershield_assistant_inference_lock"]
            lock.acquire()
            try:
                busy = client.post("/warmup", headers=self.headers())
                self.assertEqual(busy.status_code, 429)
            finally:
                lock.release()
        self.assertEqual(len(calls), 1)

    def test_warmup_does_not_claim_loaded_without_resident_inventory(self):
        app = create_app(graph_runner=lambda state: {}, token_file=self.token_file,
                         warmup_runner=lambda: {"done": True},
                         status_runner=lambda: {"model_installed": True, "model_loaded": False})
        with app.test_client() as client:
            response = client.post("/warmup", headers=self.headers())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json["error"], "model_not_loaded")

    def test_warmup_uses_a_single_chat_call_with_the_chat_context_options(self):
        app = create_app(graph_runner=lambda state: {}, token_file=self.token_file,
                         status_runner=lambda: {"model_installed": True, "model_loaded": True})
        with patch("assistant_service._ollama_request", return_value={"done": True}) as model_request:
            with app.test_client() as client:
                response = client.post("/warmup", headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["loaded"])
        self.assertEqual(model_request.call_count, 1)
        self.assertEqual(model_request.call_args.args[1], "/api/chat")
        body = model_request.call_args.args[2]
        self.assertEqual(body["options"]["num_ctx"], 2048)
        self.assertEqual(body["options"]["num_predict"], 1)
        self.assertEqual(body["keep_alive"], "30m")
        self.assertEqual(body["messages"][1], {"role": "user", "content": "Bonjour."})

    def test_parallel_chat_is_rejected_without_waiting_for_the_model(self):
        started = threading.Event()
        release = threading.Event()

        def slow_graph(state):
            started.set()
            release.wait(timeout=2)
            return {"answer": "Réponse de test locale."}

        app = create_app(graph_runner=slow_graph, token_file=self.token_file, model="test-model")
        app.config["TESTING"] = True
        first_responses = []

        def first_request():
            with app.test_client() as client:
                first_responses.append(client.post("/chat", json={"question": "première question"}, headers=self.headers()))

        worker = threading.Thread(target=first_request)
        worker.start()
        self.assertTrue(started.wait(timeout=1))
        try:
            with app.test_client() as client:
                busy = client.post("/chat", json={"question": "question concurrente"}, headers=self.headers())
            self.assertEqual(busy.status_code, 429)
            self.assertEqual(busy.json["error"], "assistant_busy")
            self.assertEqual(busy.headers["Retry-After"], "5")
        finally:
            release.set()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(first_responses[0].status_code, 200)

    def test_chat_rejects_empty_question_and_non_json(self):
        empty = self.client.post("/chat", json={"question": "", "context": {}}, headers=self.headers())
        plain = self.client.post("/chat", data="question=hello", headers=self.headers())
        self.assertEqual(empty.status_code, 400)
        self.assertEqual(plain.status_code, 415)
        self.assertEqual(self.seen, [])

    def test_missing_token_fails_closed(self):
        self.token_file.unlink()
        response = self.client.post("/chat", json={"question": "bonjour"}, headers=self.headers())
        self.assertEqual(response.status_code, 401)

    def test_no_store_headers(self):
        response = self.client.post("/chat", json={"question": "bonjour"}, headers=self.headers())
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main()
