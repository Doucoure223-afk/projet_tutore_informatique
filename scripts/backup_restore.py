#!/usr/bin/env python3
"""Private, consistent Docker backup and quarantine-only restore (Python standard library).

No command deletes a Docker volume. Restore never targets an existing project, directory
or volume, publishes no port and leaves the recovered database stopped for inspection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timezone

VERSION = 1
STATE_TARGETS = {"/var/lib/cybershield": "runtime.tar", "/var/lib/cybershield/logs/siem-outbox": "outbox.tar"}
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{2,62}$")


class RecoveryError(RuntimeError):
    pass


def run(args: list[str], *, stdin=None, stdout=None, timeout=180) -> bytes:
    result = subprocess.run(args, input=stdin, stdout=stdout or subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    if result.returncode:
        # Docker/MySQL diagnostics may contain secrets or private paths. Keep them out of chat/logs.
        raise RecoveryError(f"Command failed ({args[0]}, exit {result.returncode}); inspect the private host locally.")
    return result.stdout or b""


def docker(*args: str, **kwargs) -> bytes:
    return run(["docker", *args], **kwargs)


def inspect(object_id: str) -> dict:
    return json.loads(docker("inspect", object_id))[0]


def private_directory(path: Path) -> Path:
    path = path.absolute()
    if path.exists() or path.is_symlink():
        raise RecoveryError("Destination already exists; nothing was overwritten.")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise RecoveryError("Create a real parent directory first; symbolic-link destinations are refused.")
    path.mkdir(mode=0o700)
    if os.name == "nt":
        identity = run(["whoami"]).decode().strip()
        run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(OI)(CI)F",
             "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"])
    else:
        path.chmod(0o700)
    return path


def write_private(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
    if os.name != "nt":
        path.chmod(0o600)


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def container_environment(container: dict) -> dict[str, str]:
    return dict(line.split("=", 1) for line in container["Config"].get("Env", []) if "=" in line)


def project_containers(project: str) -> list[dict]:
    ids = docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={project}").decode().split()
    return [inspect(object_id) for object_id in ids]


def validate_name(name: str) -> str:
    if not SAFE_NAME.fullmatch(name):
        raise RecoveryError("Project name must contain 3..63 lowercase letters, numbers, hyphens or underscores.")
    return name


def database_command(container_id: str, sql: str | None = None, *, dump=False, database="") -> list[str]:
    if not re.fullmatch(r"[a-zA-Z0-9_]{1,64}", database):
        raise RecoveryError("Invalid database name.")
    # Secret is read inside the DB container; no password in host command line or stdout.
    command = 'export MYSQL_PWD="$(cat /run/secrets/db_root_password)"; exec '
    if dump:
        command += "mariadb-dump --user=root --single-transaction --quick --routines --events --triggers --hex-blob --databases " + database
    else:
        command += "mariadb --user=root --batch --skip-column-names"
    return ["docker", "exec", "-i", container_id, "sh", "-c", command]


def backup(project: str, destination: Path, *, quiesce: bool) -> dict:
    validate_name(project)
    if not quiesce:
        raise RecoveryError("A coherent backup requires --quiesce (briefly stop application writers, then restart them).")
    containers = project_containers(project)
    services = {c["Config"]["Labels"].get("com.docker.compose.service"): c for c in containers
                if c["Config"]["Labels"].get("com.docker.compose.oneoff") != "True"}
    if "db" not in services or "web" not in services or not services["db"]["State"]["Running"]:
        raise RecoveryError("Running database and web service definitions are required.")
    db, web = services["db"], services["web"]
    db_env = container_environment(db)
    database = db_env.get("MARIADB_DATABASE", "")
    state_mounts = {mount["Destination"]: mount for mount in web["Mounts"] if mount["Destination"] in STATE_TARGETS}
    if set(state_mounts) != set(STATE_TARGETS) or any(m["Type"] != "volume" for m in state_mounts.values()):
        raise RecoveryError("Expected distinct runtime and SIEM Docker volumes were not found.")
    db_mount = next((m for m in db["Mounts"] if m["Destination"] == "/var/lib/mysql"), None)
    if not db_mount or db_mount["Type"] != "volume":
        raise RecoveryError("Database must use a named Docker volume.")
    destination = private_directory(destination)
    secrets_directory = destination / "secrets"
    secrets_directory.mkdir(mode=0o700)
    secret_mapping: dict[str, dict[str, str]] = {}
    for service, container in services.items():
        if service not in {"db", "web", "ai", "assistant", "ollama", "siem-forwarder"}:
            raise RecoveryError("Unknown source service; review its write activity before backup.")
        for mount in container["Mounts"]:
            if mount["Destination"].startswith("/run/secrets/"):
                if mount["Type"] != "bind" or not Path(mount["Source"]).is_file():
                    raise RecoveryError("All Docker secret files must be readable on the host.")
                name = f"{service}-{Path(mount['Destination']).name}"
                if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
                    raise RecoveryError("Unsafe secret name.")
                write_private(secrets_directory / name, Path(mount["Source"]).read_bytes())
                secret_mapping.setdefault(service, {})[mount["Destination"]] = name
    required = {"/run/secrets/db_password", "/run/secrets/db_root_password"}
    if not required.issubset(secret_mapping.get("db", {})):
        raise RecoveryError("Database password files are missing; backup cannot be restored safely.")

    watched_volumes = {m["Name"] for m in state_mounts.values()}
    stopped: list[str] = []
    manifest: dict = {"version": VERSION, "created_utc": datetime.now(timezone.utc).isoformat(),
                      "source_project": project, "database": database, "services": {}, "files": {},
                      "secret_mapping": secret_mapping, "completed": False}
    try:
        for service, container in services.items():
            if service == "web" or any(m.get("Name") in watched_volumes and m.get("RW") for m in container["Mounts"]):
                if container["State"]["Running"]:
                    docker("stop", "--time", "20", container["Id"], timeout=45)
                    stopped.append(container["Id"])
        # No nontransactional data accepted: --single-transaction is the consistency contract.
        check_sql = ("SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='" + database
                     + "' AND TABLE_TYPE='BASE TABLE' AND ENGINE <> 'InnoDB';")
        result = run(database_command(db["Id"], database=database), stdin=check_sql.encode()).strip()
        if result != b"0":
            raise RecoveryError("Non-InnoDB tables found; a separate reviewed physical backup is required.")
        with (destination / "database.sql").open("xb") as output:
            run(database_command(db["Id"], dump=True, database=database), stdout=output)
        for target, mount in state_mounts.items():
            with (destination / STATE_TARGETS[target]).open("xb") as output:
                docker("run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                       "--cap-add", "DAC_OVERRIDE", "--user", "0", "--entrypoint", "tar",
                       "--mount", f"type=volume,source={mount['Name']},target=/state,readonly",
                       web["Image"], "-C", "/state", "-cf", "-", ".", stdout=output)
        for service, container in services.items():
            manifest["services"][service] = {"image": container["Image"],
                "environment": container_environment(container), "command": container["Config"].get("Cmd")}
        for path in sorted(destination.rglob("*")):
            if path.is_file():
                if os.name != "nt": path.chmod(0o600)
                manifest["files"][path.relative_to(destination).as_posix()] = {
                    "sha256": file_hash(path), "size": path.stat().st_size}
        manifest["completed"] = True
        write_private(destination / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode())
    finally:
        for container_id in stopped:
            docker("start", container_id, timeout=45)
    return {"completed": True, "files_verified": len(manifest["files"]), "source_restarted": len(stopped)}


def verified_manifest(directory: Path) -> dict:
    directory = directory.resolve(strict=True)
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != VERSION or manifest.get("completed") is not True:
        raise RecoveryError("Incomplete or unsupported backup.")
    files = manifest.get("files", {})
    if not {"database.sql", "runtime.tar", "outbox.tar"}.issubset(files):
        raise RecoveryError("Backup components are missing.")
    for name, expected in files.items():
        path = directory / name
        if not isinstance(name, str) or "\\" in name or path.is_symlink() or not path.resolve().is_relative_to(directory):
            raise RecoveryError("Unsafe backup path.")
        if not path.is_file() or path.stat().st_size != expected["size"] or file_hash(path) != expected["sha256"]:
            raise RecoveryError("Backup checksum mismatch; restore refused before touching Docker.")
    for archive in ("runtime.tar", "outbox.tar"):
        with tarfile.open(directory / archive, "r:") as stream:
            for member in stream:
                name = member.name
                if name.startswith("/") or ".." in Path(name).parts or "\\" in name or not (member.isfile() or member.isdir()):
                    raise RecoveryError("Unsafe archive member (links and special files are refused).")
    for mappings in manifest.get("secret_mapping", {}).values():
        if not isinstance(mappings, dict): raise RecoveryError("Invalid secret mapping.")
        for target, filename in mappings.items():
            if not re.fullmatch(r"/run/secrets/[a-zA-Z0-9_.-]+", target) or not re.fullmatch(r"[a-zA-Z0-9_.-]+", filename) \
                    or f"secrets/{filename}" not in files:
                raise RecoveryError("Unsafe secret mapping.")
    return manifest


def assert_new_project(project: str) -> None:
    validate_name(project)
    if docker("ps", "-aq", "--filter", f"label=com.docker.compose.project={project}").strip():
        raise RecoveryError("Destination Docker project already has containers.")
    for kind in ("volume", "network"):
        if docker(kind, "ls", "-q", "--filter", f"label=com.docker.compose.project={project}").strip():
            raise RecoveryError("Destination Docker project already has volumes or networks.")
    names = set(docker("volume", "ls", "--format", "{{.Name}}").decode().splitlines())
    if any(f"{project}_{suffix}" in names for suffix in ("mariadb-data", "cybershield-runtime", "siem-outbox")):
        raise RecoveryError("Destination volume name already exists.")


def restore(directory: Path, destination: Path, project: str) -> dict:
    manifest = verified_manifest(directory)
    validate_name(project)
    if project == manifest["source_project"]:
        raise RecoveryError("Restoring over the source project is forbidden.")
    assert_new_project(project)
    for service in ("db", "web"):
        image = manifest["services"][service]["image"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image): raise RecoveryError("Invalid image digest.")
        docker("image", "inspect", image)
    destination = private_directory(destination)
    (destination / "secrets").mkdir(mode=0o700)
    for name in manifest["files"]:
        if name.startswith("secrets/"):
            write_private(destination / name, (directory / name).read_bytes())
    secrets_def = {}
    definitions = {}
    # Only DB is started automatically. Application remains in a portless quarantine profile.
    for service in ("db", "web", "ai"):
        if service not in manifest["services"]: continue
        source = manifest["services"][service]
        env = dict(source["environment"])
        if service == "web":
            env.update({"CYBERSHIELD_LAN_PROXY_ENABLED": "0", "CYBERSHIELD_DOCKER_SETUP_PEER": "",
                        "CYBERSHIELD_APP_BIND_ADDRESS": "127.0.0.1", "CYBERSHIELD_HTTPS_PROXY_PEERS": "",
                        "CYBERSHIELD_REQUIRE_HTTPS": "0", "CYBERSHIELD_SIEM_URL": "",
                        "PAYMENT_ENABLED": "false", "APP_PUBLIC_URL": ""})
        definition = {"image": source["image"], "environment": env, "networks": ["recovery"]}
        if service != "db": definition["profiles"] = ["quarantine-application"]
        if service == "db":
            definition["volumes"] = ["mariadb-data:/var/lib/mysql"]
            definition["healthcheck"] = {"test": ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"],
                                          "interval": "2s", "timeout": "3s", "retries": 30, "start_period": "10s"}
        if service == "web":
            definition["volumes"] = ["cybershield-runtime:/var/lib/cybershield", "siem-outbox:/var/lib/cybershield/logs/siem-outbox"]
            # TLS certificates are optional; source default application command is used in quarantine.
            definition["command"] = ["apache2-foreground"]
        mappings = manifest["secret_mapping"].get(service, {})
        definition["secrets"] = []
        for target, filename in mappings.items():
            secret_id = filename.replace(".", "_")
            secrets_def[secret_id] = {"file": f"./secrets/{filename}"}
            definition["secrets"].append({"source": secret_id, "target": target.removeprefix("/run/secrets/")})
        definitions[service] = definition
    compose = {"name": project, "services": definitions, "secrets": secrets_def,
               "volumes": {"mariadb-data": {}, "cybershield-runtime": {}, "siem-outbox": {}},
               "networks": {"recovery": {"internal": True}}}
    config = destination / "compose.restore.json"
    write_private(config, json.dumps(compose, ensure_ascii=False, indent=2).encode())
    compose_cmd = ["docker", "compose", "--project-name", project, "--file", str(config)]
    # Docker volume-create is otherwise idempotent. A random owner token detects
    # a concurrent creator before any data is written to the destination volumes.
    owner = uuid.uuid4().hex
    for suffix in ("mariadb-data", "cybershield-runtime", "siem-outbox"):
        volume = f"{project}_{suffix}"
        docker("volume", "create", "--label", f"com.docker.compose.project={project}",
               "--label", f"com.docker.compose.volume={suffix}", "--label", f"cybershield.recovery-owner={owner}", volume)
        current = json.loads(docker("volume", "inspect", volume))[0]
        if current.get("Labels", {}).get("cybershield.recovery-owner") != owner:
            raise RecoveryError("Destination volume was created concurrently; no data was restored to it.")
    db_id = None
    try:
        run([*compose_cmd, "up", "-d", "db"])
        db_id = run([*compose_cmd, "ps", "-q", "db"]).decode().strip()
        for _ in range(60):
            state = inspect(db_id)
            if state["State"].get("Health", {}).get("Status") == "healthy": break
            time.sleep(1)
        else: raise RecoveryError("Recovered database did not become healthy.")
        # Stream the SQL backup directly to MariaDB; no SQL or credentials are logged.
        with (directory / "database.sql").open("rb") as stream:
            result = subprocess.run(database_command(db_id, database=manifest["database"]), stdin=stream,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
        if result.returncode: raise RecoveryError("Database import failed; recovered project was left isolated.")
        # State volumes were exclusively claimed before starting the recovered DB.
        for suffix, archive in (("cybershield-runtime", "runtime.tar"), ("siem-outbox", "outbox.tar")):
            volume = f"{project}_{suffix}"
            with (directory / archive).open("rb") as stream:
                # Start no application and preserve numeric ownership/MFA key permissions.
                command = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--user", "0",
                           "--entrypoint", "tar", "--mount", f"type=volume,source={volume},target=/state",
                           manifest["services"]["web"]["image"], "-C", "/state", "-xf", "-", "--numeric-owner"]
                result = subprocess.run(command, stdin=stream, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
                if result.returncode: raise RecoveryError("State restore failed; recovered project was left isolated.")
        # Restoring sessions would resurrect authenticated sessions. Clear ONLY the NEW recovery volume.
        docker("run", "--rm", "--network", "none", "--read-only", "--entrypoint", "php",
               "--mount", f"type=volume,source={project}_cybershield-runtime,target=/state",
               manifest["services"]["web"]["image"], "-r",
               'foreach(glob("/state/sessions/sess_*") ?: [] as $f){if(is_file($f)){unlink($f);}}')
    finally:
        if db_id: docker("stop", "--time", "20", db_id, timeout=45)
    write_private(destination / "recovery.json", json.dumps({"source_created_utc": manifest["created_utc"],
                  "target_project": project, "restored_utc": datetime.now(timezone.utc).isoformat(),
                  "ports_published": False, "database_stopped": True, "sessions_invalidated": True}, indent=2).encode())
    return {"completed": True, "ports_published": False, "database_stopped": True, "sessions_invalidated": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    source = commands.add_parser("backup")
    source.add_argument("--project", required=True)
    source.add_argument("--destination", type=Path, required=True)
    source.add_argument("--quiesce", action="store_true")
    target = commands.add_parser("restore")
    target.add_argument("--backup", type=Path, required=True)
    target.add_argument("--destination", type=Path, required=True)
    target.add_argument("--project", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--backup", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "backup": result = backup(args.project, args.destination, quiesce=args.quiesce)
        elif args.command == "restore": result = restore(args.backup, args.destination, args.project)
        else:
            manifest = verified_manifest(args.backup)
            result = {"verified": True, "files_verified": len(manifest["files"])}
        print(json.dumps(result))
    except (RecoveryError, OSError, ValueError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"Recovery operation refused or failed: {type(error).__name__}. No existing destination is overwritten.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
