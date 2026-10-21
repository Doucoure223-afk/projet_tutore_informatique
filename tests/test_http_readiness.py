"""Safety gates and percentile convention of the disposable acceptance runner."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "scripts/perftests/http_readiness.py"
SPEC = importlib.util.spec_from_file_location("http_readiness", PATH)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class DisposableReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "manifest.json"
        self.manifest = {"disposable": True, "clients": [
            {"id": "a", "base_url": "http://127.0.0.1:19091", "compose_project": "cybershield-accept-test-a", "containers": {"web": "cybershield-accept-test-a-web-1"}},
            {"id": "b", "base_url": "http://127.0.0.1:19092", "compose_project": "cybershield-accept-test-b", "containers": {"web": "cybershield-accept-test-b-web-1"}},
        ]}

    def read(self):
        self.path.write_text(json.dumps(self.manifest), encoding="utf-8")
        return probe.read_manifest(self.path)

    def test_two_declared_disposable_origins_are_accepted(self):
        self.assertEqual(len(self.read()["clients"]), 2)

    def test_production_and_lan_origins_are_refused(self):
        for origin in ("http://127.0.0.1:8080", "http://127.0.0.1:8082", "http://172.20.10.2:9090", "https://example.com:9090", "http://user:pw@127.0.0.1:9090"):
            with self.subTest(origin=origin):
                self.manifest["clients"][0]["base_url"] = origin
                with self.assertRaises(ValueError):
                    self.read()

    def test_live_project_or_container_name_is_refused(self):
        self.manifest["clients"][0]["containers"]["web"] = "projet_tutor_inf-web-1"
        with self.assertRaises(ValueError):
            self.read()

    def test_explicit_disposable_declaration_is_required(self):
        self.manifest["disposable"] = False
        with self.assertRaises(ValueError):
            self.read()

    def test_nearest_rank_uses_observations_without_interpolation(self):
        self.assertEqual(probe.nearest_rank([9, 1, 7, 3], .5), 3)
        self.assertEqual(probe.nearest_rank([9, 1, 7, 3], .95), 9)
        self.assertIsNone(probe.nearest_rank([], .5))


if __name__ == "__main__":
    unittest.main()
