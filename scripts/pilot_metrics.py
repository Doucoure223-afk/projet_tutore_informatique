"""Build a privacy-minimized review sheet and score independently labelled pilot events."""

from __future__ import annotations

import argparse
from collections import deque
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

OPERATIONAL_TYPES = {"IP_ACCESS_RULE", "RATE_LIMIT", "REQUEST_SIZE", "INVALID_JSON",
                     "PROTECTION_UNAVAILABLE", "LOG_UNAVAILABLE"}
POSITIVE_ACTIONS = {"BLOCKED", "BLOCKED_BY_AI", "MONITORED"}
TEMPLATE_COLUMNS = ("id", "timestamp", "action", "predicted", "attack_type", "source", "score", "risk",
                    "truth", "reviewer", "notes")


def event_id(event: dict) -> str:
    value = event.get("id") or event.get("request_id")
    return value if isinstance(value, str) else ""


def read_events(path: Path, limit: int | None = None) -> list[dict]:
    events = deque(maxlen=limit)
    try:
        with path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid event JSON on line {number}.") from exc
                if not isinstance(event, dict) or not event_id(event):
                    raise ValueError(f"Event on line {number} has no stable id.")
                events.append(event)
    except OSError as exc:
        raise ValueError("Event log could not be read.") from exc
    return list(events)


def write_review_template(events_path: Path, output_path: Path, limit: int = 250) -> int:
    if limit < 1:
        raise ValueError("Review sample size must be positive.")
    if output_path.exists():
        raise ValueError(f"Review sheet already exists and was preserved: {output_path}")
    events = read_events(events_path, limit)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=TEMPLATE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for event in events:
            writer.writerow({
                "id": event_id(event),
                "timestamp": event.get("timestamp", ""),
                "action": event.get("action", ""),
                "predicted": "attack" if predicted_attack(event) else "benign",
                "attack_type": event.get("attack_type", ""),
                "source": event.get("source", ""),
                "score": event.get("score", ""),
                "risk": event.get("risk", ""),
            })
    return len(events)


def predicted_attack(event: dict) -> bool:
    return event.get("action") in POSITIVE_ACTIONS


def load_labels(path: Path) -> dict[str, dict[str, str]]:
    labels = {}
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            for number, row in enumerate(csv.DictReader(stream), 2):
                identifier = (row.get("id") or "").strip()
                truth = (row.get("truth") or "").strip().lower()
                if not identifier:
                    raise ValueError(f"Missing event id in labels line {number}.")
                if identifier in labels:
                    raise ValueError(f"Duplicate event id in labels line {number}.")
                if not truth:
                    continue
                if truth not in {"attack", "benign"}:
                    raise ValueError(f"Use 'attack' or 'benign' for truth on labels line {number}.")
                labels[identifier] = {"truth": truth, "reviewer": (row.get("reviewer") or "").strip()}
    except OSError as exc:
        raise ValueError("Ground-truth label file could not be read.") from exc
    if not labels:
        raise ValueError("No reviewed labels found; fill the truth column with attack or benign.")
    return labels


def score_pilot(events_path: Path, labels_path: Path) -> dict:
    labels = load_labels(labels_path)
    matched = {}
    wanted = set(labels)
    try:
        with events_path.open("r", encoding="utf-8") as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Invalid event JSON on line {number}.") from exc
                if isinstance(event, dict) and event_id(event) in wanted:
                    matched[event_id(event)] = event
    except OSError as exc:
        raise ValueError("Event log could not be read.") from exc
    missing = wanted - matched.keys()
    if missing:
        raise ValueError(f"{len(missing)} reviewed event id(s) are absent from the selected log.")

    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    by_source = {}
    for identifier, label in labels.items():
        event = matched[identifier]
        attack_type = str(event.get("attack_type", "NONE"))
        if attack_type in OPERATIONAL_TYPES or event.get("source") == "ip_policy":
            raise ValueError(f"Event {identifier} is an operational gate, not an SQLi decision.")
        truth_positive = label["truth"] == "attack"
        predicted_positive = predicted_attack(event)
        key = "tp" if truth_positive and predicted_positive else \
              "fn" if truth_positive else "fp" if predicted_positive else "tn"
        counts[key] += 1
        source = str(event.get("source", "unknown"))
        by_source[source] = by_source.get(source, 0) + 1

    precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 0.0
    recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    total = sum(counts.values())
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_size": total,
        "confusion_matrix": counts,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": (counts["tp"] + counts["tn"]) / total if total else 0.0,
        "reviewed_sources": by_source,
        "scope": "Manually labelled events only; unreviewed traffic and undetected attacks are not represented.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, default=Path("logs/events.jsonl"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--template", type=Path, help="Write a review CSV for the latest events; fill its truth column.")
    group.add_argument("--labels", type=Path, help="Score the truth labels already filled in a review CSV.")
    parser.add_argument("--limit", type=int, default=250, help="Maximum events in the review template (default: 250).")
    parser.add_argument("--report", type=Path, help="Write aggregate metrics JSON when scoring labels.")
    args = parser.parse_args(argv)
    try:
        if args.template:
            count = write_review_template(args.events, args.template, args.limit)
            print(f"Created a review sheet with {count} events. No request payloads, IPs, or URLs were copied.")
            return 0
        report = score_pilot(args.events, args.labels)
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0
    except (ValueError, OSError) as error:
        print(f"Pilot metrics failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
