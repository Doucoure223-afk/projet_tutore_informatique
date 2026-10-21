"""Bounded HTTP acceptance on explicitly disposable local clients, never production."""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, ProxyHandler, Request

ROOT = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_manifest(path):
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    clients = manifest.get("clients", [])
    if manifest.get("disposable") is not True or len(clients) != 2:
        raise ValueError("Exactly two explicitly disposable client deployments are required")
    for client in clients:
        parsed = urlsplit(client["base_url"])
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.path not in ("", "/") or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Only a plain HTTP loopback origin is allowed")
        if not parsed.port or parsed.port in {80, 8080, 8081, 8082}:
            raise ValueError("Production, LAN and default ports are forbidden")
        project = client["compose_project"]
        if not re.fullmatch(r"cybershield-accept-[a-z0-9-]{4,75}", project):
            raise ValueError("A disposable acceptance Compose project is required")
        for name in client.get("containers", {}).values():
            if not re.fullmatch(re.escape(project) + r"-[a-z0-9_-]+", name):
                raise ValueError("Container is outside the declared disposable project")
    if len({client["base_url"] for client in clients}) != 2:
        raise ValueError("The two clients must have separate ports")
    return manifest


def request(url, timeout=6):
    started = time.perf_counter()
    headers = {}
    body = b""
    error = None
    try:
        with build_opener(ProxyHandler({})).open(Request(url, headers={"Accept": "application/json"}), timeout=timeout) as response:
            status, headers, body = response.status, dict(response.headers), response.read(65536)
    except HTTPError as exc:
        status, headers, body = exc.code, dict(exc.headers), exc.read(65536)
    except Exception as exc:
        status, error = 0, type(exc).__name__
    lowered = {key.lower(): value for key, value in headers.items()}
    try:
        decoded = json.loads(body)
    except (ValueError, TypeError):
        decoded = None
    return {"status": status, "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "request_id": lowered.get("x-cybershield-request-id"), "retry_after": lowered.get("retry-after"),
            "body": decoded, "error": error}


def nearest_rank(values, percentile):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * percentile) - 1)] if ordered else None


def phase(base, route, count, concurrency):
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        rows = list(pool.map(lambda _: request(base.rstrip("/") + route), range(count)))
    duration = time.perf_counter() - started
    times = [row["elapsed_ms"] for row in rows]
    return {"requests": count, "concurrency": concurrency, "duration_seconds": round(duration, 4),
            "achieved_requests_per_second": round(count / duration, 3), "p50_ms": nearest_rank(times, .50),
            "p95_ms": nearest_rank(times, .95), "max_ms": max(times),
            "status_counts": dict(Counter(str(row["status"]) for row in rows)),
            "transport_errors": sum(row["error"] is not None for row in rows), "observations": rows}


def docker_json(arguments):
    try:
        value = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=10, check=True)
        return [json.loads(line) for line in value.stdout.splitlines() if line.strip()]
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return [{"unavailable": type(exc).__name__}]


class ResourceSampler:
    def __init__(self, names):
        self.names, self.rows, self.stopped = names, [], threading.Event()
        self.thread = None

    def sample(self):
        self.rows.append({"at_utc": datetime.now(timezone.utc).isoformat(),
                          "containers": docker_json(["stats", "--no-stream", "--format", "{{json .}}", *self.names])})

    def start(self):
        self.sample()
        def run():
            while not self.stopped.wait(1):
                self.sample()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stopped.set()
        if self.thread:
            self.thread.join(timeout=11)
        self.sample()


def observation(base, row):
    if not row.get("request_id"):
        return None
    value = request(base.rstrip("/") + "/__readiness/observation.php?" + urlencode({"id": row["request_id"]}))
    return value["body"] if value["status"] == 200 else None


def validate_protocol(path):
    protocol = json.loads(path.read_text(encoding="utf-8"))
    if protocol.get("scope") != "disposable_local_acceptance_only" or protocol.get("independent_validation") is not False:
        raise ValueError("An explicitly internal sealed protocol is required")
    for name, expected in protocol["sha256"].items():
        if sha(ROOT / name) != expected:
            raise ValueError(f"Code/model/suite changed since sealing: {name}. Create a new protocol before another run.")
    return protocol


def normal_client(client, suite):
    base = client["base_url"]
    if request(base + "/__readiness/baseline.php")["body"] != {"kind": "baseline", "database_called": False}:
        raise ValueError("Guarded disposable fixtures unavailable; refusing to probe application routes")
    phases = []
    for concurrency in (1, 4, 8):
        baseline = phase(base, "/__readiness/baseline.php", 12, concurrency)
        baseline["kind"] = "without_middleware_without_database"
        phases.append(baseline)
        protected = phase(base, "/__readiness/protected.php?q=Bonjour%20Bamako", 12, concurrency)
        protected["kind"] = "actual_middleware_actual_mlp_without_database"
        protected["all_successful"] = protected["status_counts"] == {"200": 12}
        sample = observation(base, protected["observations"][0])
        protected["inference_sample"] = sample
        protected["telemetry_passed"] = bool(sample and sample.get("mlp_calls", 0) >= 1)
        phases.append(protected)
    controlled = []
    confusion = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "unscored_errors": 0}
    for case in suite["cases"]:
        row = request(base + "/__readiness/protected.php?" + urlencode({"q": case["value"]}))
        event = observation(base, row)
        blocked = row["status"] == 403
        valid = row["status"] in (200, 403) and event is not None
        bucket = ("tp" if blocked else "fn") if case["truth"] == "sqli" else ("fp" if blocked else "tn")
        confusion[bucket if valid else "unscored_errors"] += 1
        expected_status = 403 if case["truth"] == "sqli" else 200
        passed = row["status"] == expected_status and event is not None
        if case["expected_source"]:
            passed = passed and event.get("source") == case["expected_source"]
        controlled.append({"case_id": case["id"], "truth": case["truth"], "expected_source": case["expected_source"],
                           "status": row["status"], "elapsed_ms": row["elapsed_ms"], "event": event, "passed": passed})
    admission = phase(base, "/__readiness/admission.php", 105, 8)
    admission["passed"] = admission["status_counts"] == {"200": 100, "429": 5} and all(
        row["retry_after"] == "60" for row in admission["observations"] if row["status"] == 429)
    # Individual status/time observations remain available; no request values or secrets are copied.
    return {"id": client["id"], "base_url": base, "compose_project": client["compose_project"],
            "phases": phases, "controlled_suite": {"independent": False, "cases": controlled, "confusion_matrix": confusion},
            "php_admission": admission,
            "passed": all(item.get("all_successful", True) and item.get("telemetry_passed", True) and item["transport_errors"] == 0 for item in phases)
                      and all(row["passed"] for row in controlled) and admission["passed"]}


def outage_client(client, restored):
    base = client["base_url"]
    rows = []
    for case in ({"id": "benign", "q": "Bonjour Bamako"}, {"id": "sqli", "q": "admin'-- "}):
        row = request(base + "/__readiness/protected.php?" + urlencode({"q": case["q"]}))
        event = observation(base, row)
        expected_status = (200 if case["id"] == "benign" else 403) if restored else 403
        passed = row["status"] == expected_status and event is not None
        if not restored:
            passed = passed and event.get("source") == "fail_safe" and event.get("mlp_failures", 0) >= 1 and event.get("mlp_calls") == 0
        rows.append({"case_id": case["id"], "status": row["status"], "elapsed_ms": row["elapsed_ms"], "event": event, "passed": passed})
    return {"id": client["id"], "phase": "restored" if restored else "model_unavailable", "cases": rows,
            "passed": all(row["passed"] for row in rows)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--phase", choices=("normal", "outage", "restored"), default="normal")
    parser.add_argument("--client", help="Disposable client id; required for outage/restored")
    args = parser.parse_args()
    manifest = read_manifest(args.manifest)
    protocol = validate_protocol(args.protocol)
    clients = [client for client in manifest["clients"] if args.client is None or client["id"] == args.client]
    if not clients or (args.phase != "normal" and (not args.client or len(clients) != 1)):
        raise ValueError("Choose exactly one disposable client for the failure/restoration checks")
    suite = json.loads((ROOT / "scripts/perftests/controlled-sqli.json").read_text(encoding="utf-8"))
    names = [name for client in clients for name in client.get("containers", {}).values()]
    sampler = ResourceSampler(names)
    resources = {
        "host": {"os": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
                 "logical_cpu_count": os.cpu_count(), "python": platform.python_version()},
        "docker_engine": docker_json(["info", "--format", '{"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}},"version":"{{.ServerVersion}}","os":"{{.OperatingSystem}}"}']),
        "containers": {name: docker_json(["inspect", "--format", '{"image":"{{.Image}}","nano_cpus":{{.HostConfig.NanoCpus}},"memory_limit_bytes":{{.HostConfig.Memory}}}', name]) for name in names},
    }
    if os.name == "nt":
        try:
            hardware = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                "$cpu = Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors; "
                "$ram = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; "
                "@{cpu=$cpu;physical_memory_bytes=$ram} | ConvertTo-Json -Compress"],
                capture_output=True, text=True, timeout=12, check=True)
            resources["host"]["hardware"] = json.loads(hardware.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            resources["host"]["hardware"] = {"unavailable": type(exc).__name__}
    sampler.start()
    started = datetime.now(timezone.utc).isoformat()
    try:
        results = [normal_client(client, suite) if args.phase == "normal" else outage_client(client, args.phase == "restored") for client in clients]
    finally:
        sampler.stop()
    report = {"schema": 1, "started_at_utc": started, "completed_at_utc": datetime.now(timezone.utc).isoformat(),
              "phase": args.phase, "scope": "controlled_disposable_http_acceptance_not_a_customer_pilot",
              "independent_validation": False, "production_gate": "not_passed_independent_pilot_and_owner_budgets_required",
              "protocol_sha256": sha(args.protocol), "manifest_sha256": sha(args.manifest), "sealed_artifacts": protocol["sha256"],
              "resources": resources, "resource_samples": sampler.rows, "results": results,
              "passed": all(result["passed"] for result in results),
              "limitations": ["Nearest-rank percentiles of small samples; local achieved throughput is not maximum capacity.",
                              "Baseline excludes middleware and database; protected fixture excludes database. Whole application journeys require separate validation.",
                              "Docker CPU samples describe shared-engine activity, not exclusive physical hardware or user-perceived assistant speed.",
                              "This known controlled suite is internal and cannot provide independent field precision/recall."]}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"report": str(args.report), "passed": report["passed"], "clients": len(results), "independent_validation": False}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as exc:
        print(f"Readiness check failed: {exc}")
        raise SystemExit(2)
