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
        self.assertNotIn("predicted", output)
        self.assertNotIn("attack_type", output)
        self.assertNotIn("BLOCKED", output)
        metadata = json.loads(target.with_suffix(target.suffix + ".meta.json").read_text(encoding="utf-8"))
        self.assertTrue(metadata["review_blinded_to_detector_output"])
        self.assertEqual(metadata["selection"], "simple_random_sample_without_replacement")

    def test_random_sample_is_reproducible_and_excludes_operational_events(self):
        rows = [
            {"id": str(i), "timestamp": f"2026-01-01T00:00:{i:02d}Z", "action": "ALLOWED",
             "attack_type": "NONE", "source": "heuristic"}
            for i in range(12)
        ]
        rows.append({"id": "operational", "timestamp": "2026-01-01T00:01:00Z", "action": "BLOCKED",
                     "attack_type": "RATE_LIMIT", "source": "heuristic"})
        path = self.root / "population.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        a, population_a = pilot_metrics.sample_events(path, 5, 88)
        b, population_b = pilot_metrics.sample_events(path, 5, 88)
        self.assertEqual([row["id"] for row in a], [row["id"] for row in b])
        self.assertEqual(population_a, 12)
        self.assertEqual(population_b, 12)
        self.assertNotIn("operational", {row["id"] for row in a})

    def test_metrics_report_confusion_matrix_and_recall(self):
        labels = self.root / "labels.csv"
        with labels.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.DictWriter(stream, fieldnames=["id", "truth", "reviewer_code", "evidence_ref", "label_confidence", "notes"])
            writer.writeheader()
            writer.writerows([
                {"id": "1", "truth": "attack", "reviewer_code": "analyst-a", "evidence_ref": "case-1", "label_confidence": "high"},
                {"id": "2", "truth": "benign", "reviewer_code": "analyst-a", "evidence_ref": "case-2", "label_confidence": "high"},
                {"id": "3", "truth": "benign", "reviewer_code": "analyst-b", "evidence_ref": "case-3", "label_confidence": "medium"},
                {"id": "4", "truth": "attack", "reviewer_code": "analyst-b", "evidence_ref": "case-4", "label_confidence": "high"},
            ])
        report = pilot_metrics.score_pilot(self.events, labels)
        self.assertEqual(report["confusion_matrix"], {"tp": 1, "fp": 1, "tn": 1, "fn": 1})
        self.assertEqual(report["precision"], 0.5)
        self.assertEqual(report["recall"], 0.5)
        self.assertEqual(report["f1"], 0.5)
        self.assertIn("independently labelled sampled log events", report["scope"])
        self.assertEqual(report["false_positive_rate"], 0.5)
        self.assertEqual(report["false_negative_rate"], 0.5)
        self.assertEqual(report["reviewers"], ["analyst-a", "analyst-b"])
        self.assertIsNotNone(report["wilson_95_intervals"]["recall"])

    def test_low_confidence_labels_are_excluded_from_primary_metrics(self):
        labels = self.root / "confidence.csv"
        labels.write_text(
            "id,truth,reviewer_code,evidence_ref,label_confidence\n"
            "1,attack,r1,case-1,low\n"
            "2,benign,r1,case-2,high\n",
            encoding="utf-8",
        )
        report = pilot_metrics.score_pilot(self.events, labels)
        self.assertEqual(report["sample_size"], 1)
        self.assertEqual(report["low_confidence_excluded"], 1)
        self.assertEqual(report["label_confidence_counts"], {"high": 1, "medium": 0, "low": 1})

    def test_operational_block_is_not_scored_as_sqli(self):
        operational = self.root / "operational.jsonl"
        operational.write_text(json.dumps({"id": "op", "action": "BLOCKED", "attack_type": "RATE_LIMIT", "source": "heuristic"}) + "\n")
        labels = self.root / "operational-label.csv"
        labels.write_text("id,truth,reviewer_code,evidence_ref,label_confidence\nop,benign,r1,case-1,high\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "operational gate"):
            pilot_metrics.score_pilot(operational, labels)

    def test_missing_labelled_event_fails_instead_of_skewing_metrics(self):
        labels = self.root / "missing.csv"
        labels.write_text("id,truth,reviewer_code,evidence_ref,label_confidence\nmissing-id,attack,r1,case-1,high\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "absent"):
            pilot_metrics.score_pilot(self.events, labels)


if __name__ == "__main__":
    unittest.main()
