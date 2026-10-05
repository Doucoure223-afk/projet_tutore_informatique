import csv
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "pilot_metrics.py"
SPEC = importlib.util.spec_from_file_location("pilot_metrics", MODULE_PATH)
pilot_metrics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pilot_metrics)


class PilotMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.events = self.root / "events.jsonl"
        rows = [
            {"id": "1", "timestamp": "2026-01-01T00:00:00Z", "action": "BLOCKED", "attack_type": "UNION_SELECT", "source": "heuristic"},
            {"id": "2", "timestamp": "2026-01-01T00:01:00Z", "action": "ALLOWED", "attack_type": "NONE", "source": "heuristic"},
            {"id": "3", "timestamp": "2026-01-01T00:02:00Z", "action": "BLOCKED_BY_AI", "attack_type": "BOOLEAN_BASED", "source": "mlp"},
            {"id": "4", "timestamp": "2026-01-01T00:03:00Z", "action": "ALLOWED", "attack_type": "NONE", "source": "mlp"},
        ]
        self.events.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_review_template_excludes_payload_and_network_identifiers(self):
        data = json.loads(self.events.read_text(encoding="utf-8").splitlines()[0])
        data.update({"payload": "secret", "ip": "192.0.2.9", "path": "/user/42"})
        self.events.write_text(json.dumps(data) + "\n", encoding="utf-8")
        target = self.root / "review.csv"
        self.assertEqual(pilot_metrics.write_review_template(self.events, target), 1)
        output = target.read_text(encoding="utf-8-sig")
        self.assertNotIn("secret", output)
        self.assertNotIn("192.0.2.9", output)
        self.assertNotIn("/user/42", output)

    def test_metrics_report_confusion_matrix_and_recall(self):
        labels = self.root / "labels.csv"
        with labels.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["id", "truth", "reviewer", "notes"])
            writer.writeheader()
            writer.writerows([
                {"id": "1", "truth": "attack", "reviewer": "analyst-a"},
                {"id": "2", "truth": "benign", "reviewer": "analyst-a"},
                {"id": "3", "truth": "benign", "reviewer": "analyst-b"},
                {"id": "4", "truth": "attack", "reviewer": "analyst-b"},
            ])
        report = pilot_metrics.score_pilot(self.events, labels)
        self.assertEqual(report["confusion_matrix"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(report["precision"], 0.5)
        self.assertEqual(report["recall"], 0.5)
        self.assertEqual(report["f1"], 0.5)
        self.assertIn("Manually labelled", report["scope"])

    def test_operational_block_is_not_scored_as_sqli(self):
        operational = self.root / "operational.jsonl"
        operational.write_text(json.dumps({"id": "op", "action": "BLOCKED", "attack_type": "RATE_LIMIT", "source": "heuristic"}) + "\n")
        labels = self.root / "operational-label.csv"
        labels.write_text("id,truth\nop,benign\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "operational gate"):
            pilot_metrics.score_pilot(operational, labels)

    def test_missing_labelled_event_fails_instead_of_skewing_metrics(self):
        labels = self.root / "missing.csv"
        labels.write_text("id,truth\nmissing-id,attack\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "absent"):
            pilot_metrics.score_pilot(self.events, labels)


if __name__ == "__main__":
    unittest.main()
