"""Recovery guardrails, exercised without stopping or touching any real stack."""
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).resolve().parents[1] / "scripts" / "backup_restore.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def fixture(self):
        folder = self.root / "backup"
        folder.mkdir()
        (folder / "database.sql").write_text("SELECT 1;")
        for name in ("runtime.tar", "outbox.tar"):
            with tarfile.open(folder / name, "w") as archive:
                member = tarfile.TarInfo("./logs/example")
                member.size = 4
                archive.addfile(member, io.BytesIO(b"test"))
        manifest = {"version": 1, "completed": True, "source_project": "source-test", "files": {}}
        for file in folder.iterdir():
            manifest["files"][file.name] = {"sha256": recovery.file_hash(file), "size": file.stat().st_size}
        (folder / "manifest.json").write_text(json.dumps(manifest))
        return folder

    def update_manifest(self, folder, **changes):
        manifest = json.loads((folder / "manifest.json").read_text())
        manifest.update(changes)
        (folder / "manifest.json").write_text(json.dumps(manifest))

    def test_valid_snapshot(self):
        self.assertTrue(recovery.verified_manifest(self.fixture())["completed"])

    def test_existing_destination_refused(self):
        sentinel = self.root / "keep.txt"
        sentinel.write_text("preserved")
        with self.assertRaises(recovery.RecoveryError): recovery.private_directory(self.root)
        self.assertEqual(sentinel.read_text(), "preserved")

    def test_bad_project_names(self):
        for name in ("a", "Prod", "../prod", "source; rm", "*", "test/project"):
            with self.subTest(name=name), self.assertRaises(recovery.RecoveryError): recovery.validate_name(name)

    def test_same_source_project_refused_before_docker(self):
        folder = self.fixture()
        with patch.object(recovery, "docker") as command, self.assertRaises(recovery.RecoveryError):
            recovery.restore(folder, self.root / "restored", "source-test")
        command.assert_not_called()

    def test_corruption_refused_before_docker(self):
        folder = self.fixture()
        (folder / "database.sql").write_text("SELECT 2;")
        with patch.object(recovery, "docker") as command, self.assertRaises(recovery.RecoveryError):
            recovery.restore(folder, self.root / "restored", "new-project")
        command.assert_not_called()

    def test_manifest_parent_path_refused(self):
        folder = self.fixture()
        outside = self.root / "private.txt"
        outside.write_text("hidden")
        manifest = json.loads((folder / "manifest.json").read_text())
        manifest["files"]["../private.txt"] = {"sha256": recovery.file_hash(outside), "size": 6}
        self.update_manifest(folder, files=manifest["files"])
        with self.assertRaises(recovery.RecoveryError): recovery.verified_manifest(folder)

    def test_incomplete_refused(self):
        folder = self.fixture()
        self.update_manifest(folder, completed=False)
        with self.assertRaises(recovery.RecoveryError): recovery.verified_manifest(folder)

    def test_tar_links_and_traversal_refused(self):
        for member_name, kind in (("../escape", tarfile.REGTYPE), ("/escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), ("device", tarfile.CHRTYPE)):
            with self.subTest(member_name=member_name, kind=kind):
                folder = self.fixture()
                with tarfile.open(folder / "runtime.tar", "w") as archive:
                    member = tarfile.TarInfo(member_name)
                    member.type = kind
                    archive.addfile(member)
                manifest = json.loads((folder / "manifest.json").read_text())
                manifest["files"]["runtime.tar"] = {"sha256": recovery.file_hash(folder / "runtime.tar"), "size": (folder / "runtime.tar").stat().st_size}
                self.update_manifest(folder, files=manifest["files"])
                with self.assertRaises(recovery.RecoveryError): recovery.verified_manifest(folder)
                import shutil
                shutil.rmtree(folder)

    def test_secret_mapping_cannot_escape_destination(self):
        folder = self.fixture()
        self.update_manifest(folder, secret_mapping={"db": {"/run/secrets/db_password": "../../unrelated.txt"}})
        with self.assertRaises(recovery.RecoveryError): recovery.verified_manifest(folder)

    def test_quiesce_is_explicit(self):
        with patch.object(recovery, "docker") as command, self.assertRaises(recovery.RecoveryError):
            recovery.backup("source-test", self.root / "backup", quiesce=False)
        command.assert_not_called()

    def test_existing_docker_objects_refused(self):
        for returns in ((b"existing",), (b"", b"existing"), (b"", b"", b"existing"),
                        (b"", b"", b"", b"target-test_cybershield-runtime\n")):
            with self.subTest(returns=returns), patch.object(recovery, "docker", side_effect=returns), self.assertRaises(recovery.RecoveryError):
                recovery.assert_new_project("target-test")


if __name__ == "__main__": unittest.main()
