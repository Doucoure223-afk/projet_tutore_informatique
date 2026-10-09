"""Tests for the stateless LangGraph assistant API and its privacy boundary."""

import json
from pathlib import Path
import tempfile
import unittest

from assistant_core import clean_answer, clean_question, context_text, sanitize_context
from assistant_service import create_app


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

    def test_answer_is_text_and_bounded(self):
        with self.assertRaises(ValueError):
            clean_answer({"answer": "unsafe"})
        self.assertEqual(clean_answer("  Réponse\x00 sûre  "), "Réponse sûre")


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
        self.assertEqual(self.seen[0]["context"]["totals"]["events"], 5)
        self.assertNotIn("ip", json.dumps(self.seen[0]["context"]))

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
