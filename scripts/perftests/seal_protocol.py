"""Freeze a local acceptance protocol before execution; never certify unseen data."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    "scripts/perftests/controlled-sqli.json", "scripts/perftests/http_readiness.py",
    "scripts/perftests/fixtures/baseline.php", "scripts/perftests/fixtures/protected.php",
    "scripts/perftests/fixtures/admission.php", "scripts/perftests/fixtures/observation.php",
    "security/middleware.php", "security/hybrid_analyzer.php", "security/ia_analyzer.php",
    "security/logger.php", "config/security.php", "config/ai.php", "ia/service.py", "ia/features.py",
    "ia/models/model.joblib", "ia/models/training_report.json", "ia/models/external_evaluation.json",
    "ia/models/honeypot_evaluation.json",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(path: Path) -> dict:
    suite = json.loads((ROOT / FILES[0]).read_text(encoding="utf-8"))
    report = {
        "schema": 1, "sealed_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "disposable_local_acceptance_only",
        "suite_provenance": suite["provenance"], "independent_validation": False,
        "external_unseen_dataset": None,
        "reason": "No new externally sourced, untouched and independently labelled application dataset is supplied. Existing public and honeypot results remain separate evidence.",
        "checks_frozen_before_execution": {
            "normal_requests": "HTTP 200 with at least one successful real MLP prediction; no inference fixture in PHP",
            "controlled_sqli": "HTTP 403; intended rule or real MLP source must match the predeclared case",
            "php_admission": "100 of 105 calls admitted in 60 seconds, 5 return 429 with Retry-After; actual PHP limiter in separate disposable state",
            "mlp_outage": "protected benign and SQLi requests fail closed before database access; service restored afterwards",
            "metrics": "Record sample counts, nearest-rank p50/p95, achieved HTTP requests/second, concurrency, errors, Docker CPU/RAM samples and limits. No invented performance target.",
            "production_gate": "NOT PASSED: independent labelled pilot, acceptable false-positive rate and owner-approved latency/error budgets still required",
        },
        "load_bounds": {"normal_calls_per_phase": 12, "concurrency": [1, 4, 8], "admission_calls": 105,
                        "maximum_request_seconds": 6, "targets": "Two disposable 127.0.0.1 client deployments, production ports excluded"},
        "sha256": {name: digest(ROOT / name) for name in FILES},
        "limits": ["Known controlled cases do not estimate field effectiveness.",
                   "Small local samples do not establish a service-level objective.",
                   "Local timestamps and hashes detect accidental changes; they are not third-party certification."],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    seal(args.output)
    print(f"Sealed internal acceptance protocol: {args.output}; sha256={digest(args.output)}")
