"""Run: python -m unittest discover -s ia -p test_*.py -v"""

from pathlib import Path
import tempfile
import unittest

from dataset import build_dataset
from evaluate_external import evaluate
from evaluate_honeypot import GatewayRejected, heuristic_score, request_inputs
from features import extract_features, normalize
from service import BASE, SlidingWindowLimiter, create_app
from train import DEFAULT_DATASET, EXPECTED_DATASET_SHA256, load_dataset


class FeatureTests(unittest.TestCase):
    def test_transport_and_comment_obfuscation(self):
        for sql in ("%2527%2520UNION%2520SELECT%2520password%2520FROM%2520users--",
                    "1 un/**/ion sel/**/ect password FROM users", "1 /*!50000UNION*/ SELECT password FROM users"):
            with self.subTest(sql=sql):
                features = extract_features(sql)
                self.assertEqual(features["union_select"], 1)
                self.assertEqual(features["has_union"], 1)

    def test_benign_substrings_are_not_sql_keywords(self):
        features = extract_features("Orlando Anderson sélectionne O'Connor")
        self.assertEqual(features["has_or"], 0)
        self.assertEqual(features["has_and"], 0)
        self.assertEqual(features["logical_comparison"], 0)

    def test_normalization_does_not_invent_patterns_between_views(self):
        self.assertEqual(extract_features("select union")["union_select"], 0)
        self.assertEqual(extract_features("price=5 and")["logical_comparison"], 0)

    def test_three_url_decodings_match_php_preprocessing(self):
        features = extract_features("admin%252527%252520--")
        self.assertEqual(features["quote_comment"], 1)

    def test_dataset_groups_and_normalized_values_do_not_leak(self):
        records = build_dataset()
        groups, values = {}, {}
        for partition in ("train", "validation"):
            rows = [row for row in records if row["partition"] == partition]
            groups[partition] = {row["group"] for row in rows}
            values[partition] = {normalize(row["sql"])[1] for row in rows}
            self.assertEqual({row["label"] for row in rows}, {0, 1})
        self.assertFalse(groups["train"] & groups["validation"])
        self.assertFalse(values["train"] & values["validation"])


class HttpParamsTrainingDataTests(unittest.TestCase):
    def test_pinned_training_split_and_binary_selection(self):
        from train import sha256_file
        rows, classes, excluded, digest = load_dataset(DEFAULT_DATASET)
        self.assertEqual(digest, EXPECTED_DATASET_SHA256)
        self.assertEqual(sha256_file(DEFAULT_DATASET), EXPECTED_DATASET_SHA256)
        self.assertEqual(len(rows), 20105)
        self.assertEqual(classes, {"norm": 12870, "sqli": 7235})
        self.assertEqual(excluded, {"xss": 355, "path-traversal": 193, "cmdi": 59})


class DetectorRuleMirrorTests(unittest.TestCase):
    def test_rule_thresholds_match_php_signatures(self):
        examples = {
            "1 UNION SELECT password FROM users": 95,
            "1 OR 1=1": 90,
            "'; DROP TABLE users; --": 100,
            "admin' --": 60,
            "SELECT name FROM users": 45,
            "Bonjour Bamako": 0,
        }
        for payload, expected in examples.items():
            with self.subTest(payload=payload):
                self.assertEqual(heuristic_score(payload), expected)


class HoneypotInputParsingTests(unittest.TestCase):
    def test_request_path_query_form_and_cookie_are_scanned(self):
        values = request_inputs({
            "request_http_request": "/route%27%20OR%201%3D1?term=hello+world",
            "request_content_type": "application/x-www-form-urlencoded",
            "request_body": "q=%27+OR+1%3D1",
            "request_cookie": "sid=abc",
        })
        self.assertEqual(values[0], "/route' OR 1=1")
        self.assertIn("hello world", values)
        self.assertIn("' OR 1=1", values)
        self.assertIn("abc", values)

    def test_oversized_scanned_value_matches_gateway_rejection(self):
        with self.assertRaises(GatewayRejected):
            request_inputs({
                "request_http_request": "/route?value=" + ("x" * 8193),
                "request_content_type": "", "request_body": "", "request_cookie": "",
            })


class AvailabilityAndProtocolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.client = create_app(Path(self.directory.name) / "missing.joblib").test_client()

    def test_missing_model_is_not_a_simulated_prediction(self):
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 503)
        self.assertFalse(health.json["model_loaded"])
        response = self.client.post("/analyse", json={"sql": "bonjour"})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("risk", response.json)

    def test_invalid_input_is_rejected_before_inference(self):
        for payload in ({}, {"sql": ["x"]}, {"sql": "a" * 8193}, {"sql": "x", "context": 42}):
            self.assertEqual(self.client.post("/analyse", json=payload).status_code, 400)
        self.assertEqual(self.client.post("/analyse", data="sql=x").status_code, 415)
        self.assertEqual(self.client.post("/analyse", data="{broken", content_type="application/json").status_code, 400)
        self.assertEqual(self.client.post("/analyse", data="a" * 32769, content_type="application/json").status_code, 413)

    def test_rate_limit_is_exposed_as_429(self):
        client = create_app(Path(self.directory.name) / "missing.joblib", rate_limit=2).test_client()
        for _ in range(2):
            self.assertEqual(client.post("/analyse", json={"sql": "x"}).status_code, 503)
        response = client.post("/analyse", json={"sql": "x"}, headers={"X-Forwarded-For": "198.51.100.1"})
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response.headers)

    def test_sliding_window_expires_old_entries(self):
        now = [0.0]
        limiter = SlidingWindowLimiter(limit=2, window=60, clock=lambda: now[0])
        self.assertTrue(limiter.allow("local")[0])
        now[0] = 10.0
        self.assertTrue(limiter.allow("local")[0])
        self.assertFalse(limiter.allow("local")[0])
        now[0] = 60.0
        self.assertTrue(limiter.allow("local")[0])
        self.assertFalse(limiter.allow("local")[0])


class TrainedModelIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model_path = BASE / "models" / "model.joblib"
        if not model_path.exists():
            raise RuntimeError("Train ia/train.py before running integration tests")
        cls.app = create_app(model_path)
        cls.client = cls.app.test_client()

    def test_loaded_artifact_and_actual_mlp(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["model_loaded"])
        self.assertEqual(response.json["rate_limit"], 420)
        artifact = self.app.extensions["cybershield_model"]
        self.assertEqual([list(layer.shape) for layer in artifact["classifier"].coefs_][1:], [[128, 64], [64, 32], [32, 1]])
        self.assertEqual(artifact["classifier"].solver, "adam")

    def test_canonical_regression_inputs(self):
        attacks = ["' OR '1'='1' --", "' UNION SELECT password FROM users --", "admin' --", "' OR SLEEP(5) --", "'; DROP TABLE users; --"]
        benign = ["test@example.com", "Bonjour Bamako", "O'Connor", "12345"]
        for sql, expected in [(item, "BLOCK") for item in attacks] + [(item, "ALLOW") for item in benign]:
            with self.subTest(sql=sql):
                response = self.client.post("/analyse", json={"sql": sql, "context": "test"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json["decision"], expected)
                self.assertEqual(response.json["analysis_method"], "MLP")
                self.assertGreaterEqual(response.json["risk"], 0)
                self.assertLessEqual(response.json["risk"], 1)
                self.assertEqual(response.json["decision"], "BLOCK" if response.json["risk"] >= 0.75 else "ALLOW")

    def test_independent_public_test_split_regression(self):
        report = evaluate()
        self.assertEqual(report["dataset"]["sha256"], "d8015e256ce4499c8ac7a8be8dd25de6487cf018601edf1a03a408a2c8f0e39d")
        self.assertEqual(report["dataset"]["rows_total"], 10355)
        self.assertEqual(report["evaluated_rows"], 10051)
        self.assertEqual(report["dataset"]["excluded_non_sqli_attacks"], {"cmdi": 30, "path-traversal": 97, "xss": 177})
        self.assertEqual(report["metrics"]["confusion_matrix"], {
            "true_negative": 6433, "false_positive": 1,
            "false_negative": 5, "true_positive": 3612,
        })
        self.assertEqual(report["metrics"]["f1"], 0.99917)


if __name__ == "__main__":
    unittest.main()
