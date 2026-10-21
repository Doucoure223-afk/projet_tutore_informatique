"""Opt-in Docker recovery drill, using generated fake data and NEW projects only.

Run: python tests/backup_restore_integration_test.py --run
Existing production containers/volumes are never selected. Generated projects stay
stopped after the drill; no Docker volume is deleted, including on a failed test.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("recovery", ROOT / "scripts" / "backup_restore.py")
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if not args.run: parser.error("Use --run to create two isolated test projects; no production stack will be used.")
    suffix = uuid.uuid4().hex[:10]
    source_project = "cybershield-drill-source-" + suffix
    target_project = "cybershield-drill-restored-" + suffix
    recovery.assert_new_project(source_project)
    recovery.assert_new_project(target_project)
    base = recovery.private_directory(ROOT / "tmp" / ("recovery-drill-" + suffix))
    source = recovery.private_directory(base / "source")
    secrets_dir = source / "secrets"
    secrets_dir.mkdir()
    for name in ("db_password", "db_root_password"):
        recovery.write_private(secrets_dir / name, secrets.token_hex(32).encode())
    web_image = json.loads(recovery.docker("image", "inspect", "projet_tutor_inf-web:latest"))[0]["Id"]
    db_image = json.loads(recovery.docker("image", "inspect", "mariadb:11.4.13"))[0]["Id"]
    configuration = {
        "name": source_project,
        "services": {
            "db": {"image": db_image, "environment": {"MARIADB_DATABASE": "recovery_drill", "MARIADB_USER": "drill_app",
                    "MARIADB_PASSWORD_FILE": "/run/secrets/db_password", "MARIADB_ROOT_PASSWORD_FILE": "/run/secrets/db_root_password"},
                   "secrets": ["db_password", "db_root_password"], "volumes": ["mariadb-data:/var/lib/mysql"], "networks": ["drill"],
                   "healthcheck": {"test": ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"],
                                   "interval": "2s", "timeout": "3s", "retries": 30, "start_period": "10s"}},
            "web": {"image": web_image, "entrypoint": ["sleep", "infinity"],
                    "environment": {"DB_HOST": "db", "DB_NAME": "recovery_drill", "DB_USER": "drill_app", "DB_PASSWORD_FILE": "/run/secrets/db_password",
                                    "CYBERSHIELD_LOG_DIR": "/var/lib/cybershield/logs"},
                    "secrets": ["db_password"], "volumes": ["cybershield-runtime:/var/lib/cybershield", "siem-outbox:/var/lib/cybershield/logs/siem-outbox"],
                    "networks": ["drill"]}},
        "secrets": {name: {"file": "./secrets/" + name} for name in ("db_password", "db_root_password")},
        "volumes": {name: {} for name in ("mariadb-data", "cybershield-runtime", "siem-outbox")},
        "networks": {"drill": {"internal": True}}}
    config = source / "compose.drill.json"
    recovery.write_private(config, json.dumps(configuration).encode())
    compose = ["docker", "compose", "-p", source_project, "-f", str(config)]
    source_id = None
    target_id = None
    try:
        recovery.run([*compose, "up", "-d"])
        source_id = recovery.run([*compose, "ps", "-q", "db"]).decode().strip()
        web_id = recovery.run([*compose, "ps", "-q", "web"]).decode().strip()
        for _ in range(60):
            if recovery.inspect(source_id)["State"].get("Health", {}).get("Status") == "healthy": break
            time.sleep(1)
        else: raise AssertionError("Fixture database failed health check")
        # Real AdminTotp encrypts a fake fixture value; its private runtime key must survive recovery.
        php = ('putenv("CYBERSHIELD_LOG_DIR=/var/lib/cybershield/logs");'
               'require "/var/www/html/app/AdminTotp.php";'
               '@mkdir("/var/lib/cybershield/sessions",0700,true);'
               'file_put_contents("/var/lib/cybershield/sessions/sess_drill","must-not-return");'
               'file_put_contents("/var/lib/cybershield/logs/drill-marker.txt","runtime-marker");'
               'file_put_contents("/var/lib/cybershield/logs/siem-outbox/drill-marker.json","{\\"drill\\":true}");'
               'echo AdminTotp::encrypt("JBSWY3DPEHPK3PXP");')
        # Create fake state with the application UID; retain real file permissions.
        recovery.docker("exec", web_id, "sh", "-c", "mkdir -p /var/lib/cybershield/logs/siem-outbox /var/lib/cybershield/sessions; chown -R 33:33 /var/lib/cybershield")
        encrypted = recovery.docker("exec", "--user", "33:33", web_id, "php", "-r", php).decode()
        sql = ("USE recovery_drill; CREATE TABLE recovery_marker (id INT PRIMARY KEY, marker VARCHAR(128), mfa TEXT) ENGINE=InnoDB; "
               "INSERT INTO recovery_marker VALUES (1, 'database-marker', '" + encrypted + "');")
        recovery.run(recovery.database_command(source_id, database="recovery_drill"), stdin=sql.encode())
        backup_path = base / "backup"
        backup_result = recovery.backup(source_project, backup_path, quiesce=True)
        assert recovery.inspect(web_id)["State"]["Running"], "Backup must restart its fixture writer"
        restored_path = base / "restored"
        restored = recovery.restore(backup_path, restored_path, target_project)
        target_compose = ["docker", "compose", "-p", target_project, "-f", str(restored_path / "compose.restore.json")]
        assert not recovery.run([*target_compose, "ps", "-q", "--status", "running"]).strip(), "Restore must finish stopped"
        recovery.run([*target_compose, "start", "db"])
        target_id = recovery.run([*target_compose, "ps", "-q", "db"]).decode().strip()
        for _ in range(30):
            if recovery.inspect(target_id)["State"].get("Health", {}).get("Status") == "healthy": break
            time.sleep(1)
        query = b"SELECT marker,mfa FROM recovery_drill.recovery_marker WHERE id=1;"
        restored_row = recovery.run(recovery.database_command(target_id, database="recovery_drill"), stdin=query).decode().strip().split("\t")
        assert restored_row == ["database-marker", encrypted], "Database marker and encrypted MFA must match"
        decrypt = ('putenv("CYBERSHIELD_LOG_DIR=/var/lib/cybershield/logs"); require "/var/www/html/app/AdminTotp.php";'
                   'if(AdminTotp::decrypt($argv[1])!=="JBSWY3DPEHPK3PXP"){exit(2);} '
                   'if(file_get_contents("/var/lib/cybershield/logs/drill-marker.txt")!=="runtime-marker"){exit(3);} '
                   'if(glob("/var/lib/cybershield/sessions/sess_*")){exit(4);} '
                   'if(!is_file("/var/lib/cybershield/logs/siem-outbox/drill-marker.json")){exit(5);} echo "verified";')
        proof = recovery.docker("run", "--rm", "--network", "none", "--read-only", "--entrypoint", "php", "--user", "33:33",
                                "--mount", f"type=volume,source={target_project}_cybershield-runtime,target=/var/lib/cybershield",
                                "--mount", f"type=volume,source={target_project}_siem-outbox,target=/var/lib/cybershield/logs/siem-outbox",
                                web_image, "-r", decrypt, restored_row[1])
        assert proof == b"verified", "MFA decryption must work with recovered key"
        assert recovery.inspect(target_id)["HostConfig"]["PortBindings"] in (None, {}), "Recovery must publish no port"
        report = {"passed": True, "new_projects_only": True, "database_marker": True, "mfa_decryption": True,
                  "runtime_marker": True, "siem_outbox_marker": True, "sessions_invalidated": True, "no_published_ports": True,
                  "backup": backup_result, "restore": restored, "test_directory": base.name}
        recovery.write_private(base / "drill-result.json", json.dumps(report, indent=2).encode())
        print(json.dumps(report))
    finally:
        for project in (source_project, target_project):
            # A strict generated-name check protects every operation, even during failure cleanup.
            if not project.startswith("cybershield-drill-") or not project.endswith(suffix): raise AssertionError("Unsafe cleanup target")
            for container in recovery.project_containers(project):
                if container["State"]["Running"]: recovery.docker("stop", "--time", "15", container["Id"], timeout=35)


if __name__ == "__main__": main()
