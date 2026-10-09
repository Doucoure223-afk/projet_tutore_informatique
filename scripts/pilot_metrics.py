"""Build a privacy-minimized review sheet and score independently labelled pilot events."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys

OPERATIONAL_TYPES = {"IP_ACCESS_RULE", "RATE_LIMIT", "REQUEST_SIZE", "INVALID_JSON",
                     "PROTECTION_UNAVAILABLE", "LOG_UNAVAILABLE"}
POSITIVE_ACTIONS = {"BLOCKED", "BLOCKED_BY_AI", "MONITORED"}
FINAL_ACTIONS = {"BLOCKED", "BLOCKED_BY_AI", "ALLOWED", "MONITORED"}
TEMPLATE_COLUMNS = ("id", "timestamp", "evidence_ref", "truth", "reviewer_code", "label_confidence", "notes")


def event_id(event: dict) -> str:
    value = event.get("id") or event.get("request_id")
    return value if isinstance(value, str) else ""


def iter_events(path: Path):
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
                yield event
    except OSError as exc:
        raise ValueError("Event log could not be read.") from exc


def is_sqli_decision(event: dict) -> bool:
    return (
        event.get("action") in FINAL_ACTIONS
        and str(event.get("attack_type", "")) not in OPERATIONAL_TYPES
        and event.get("source") != "ip_policy"
    )


def sample_events(events_path: Path, limit: int, seed: int) -> tuple[list[dict], int]:
    """Take a reproducible simple random sample using O(limit) memory."""
    if limit < 1:
        raise ValueError("Review sample size must be positive.")
    rng = random.Random(seed)
    sample = []
    eligible = 0
    for event in iter_events(events_path):
        if not is_sqli_decision(event):
            continue
        eligible += 1
        if len(sample) < limit:
            sample.append(event)
        else:
            index = rng.randrange(eligible)
            if index < limit:
                sample[index] = event
    sample.sort(key=lambda row: (str(row.get("timestamp", "")), event_id(row)))
    return sample, eligible


def write_review_template(events_path: Path, output_path: Path, limit: int = 250, seed: int = 20261009) -> int:
    if output_path.exists():
        raise ValueError(f"Review sheet already exists and was preserved: {output_path}")
    meta_path = output_path.with_suffix(output_path.suffix + ".meta.json")
    if meta_path.exists():
        raise ValueError(f"Review sample metadata already exists and was preserved: {meta_path}")
    events, population = sample_events(events_path, limit, seed)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=TEMPLATE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for event in events:
            writer.writerow({
                "id": event_id(event),
                "timestamp": event.get("timestamp", ""),
                # Reviewers label from separately authorized evidence. Keep the
                # detector decision, rule, score, and model output out of this sheet.
                "evidence_ref": "",
                "truth": "",
                "reviewer_code": "",
                "label_confidence": "",
                "notes": "",
            })
    meta_path.write_text(json.dumps({
        "created_at": datetime.now(timezone.utc).isoformat(),
        "selection": "simple_random_sample_without_replacement",
        "seed": seed,
        "eligible_population": population,
        "sample_size": len(events),
        "review_blinded_to_detector_output": True,
        "evidence_policy": "Record a reference only; do not copy raw payloads or personal data into the review sheet.",
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
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
                reviewer = (row.get("reviewer_code") or row.get("reviewer") or "").strip()
                evidence_ref = (row.get("evidence_ref") or "").strip()
                confidence = (row.get("label_confidence") or "").strip().lower()
                if not reviewer:
                    raise ValueError(f"Missing reviewer_code on labels line {number}.")
                if not evidence_ref:
                    raise ValueError(f"Missing independent evidence_ref on labels line {number}.")
                if confidence not in {"low", "medium", "high"}:
                    raise ValueError(f"Use low, medium, or high for label_confidence on labels line {number}.")
                labels[identifier] = {
                    "truth": truth,
                    "reviewer_code": reviewer,
                    "evidence_ref": evidence_ref,
                    "label_confidence": confidence,
                }
    except OSError as exc:
        raise ValueError("Ground-truth label file could not be read.") from exc
    if not labels:
        raise ValueError("No reviewed labels found; fill the truth column with attack or benign.")
    return labels


def score_pilot(events_path: Path, labels_path: Path) -> dict:
    all_labels = load_labels(labels_path)
    low_confidence = {identifier: label for identifier, label in all_labels.items()
                      if label["label_confidence"] == "low"}
    labels = {identifier: label for identifier, label in all_labels.items()
              if label["label_confidence"] in {"medium", "high"}}
    if not labels:
        raise ValueError("No medium- or high-confidence labels found; resolve or exclude low-confidence cases.")
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
        if not is_sqli_decision(event):
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
    specificity = counts["tn"] / (counts["tn"] + counts["fp"]) if counts["tn"] + counts["fp"] else 0.0
    false_positive_rate = counts["fp"] / (counts["tn"] + counts["fp"]) if counts["tn"] + counts["fp"] else 0.0
    false_negative_rate = counts["fn"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0

    def wilson(successes: int, observations: int, z: float = 1.959963984540054) -> list[float] | None:
        if observations == 0:
            return None
        proportion = successes / observations
        denominator = 1 + z * z / observations
        center = (proportion + z * z / (2 * observations)) / denominator
        margin = z * ((proportion * (1 - proportion) / observations + z * z / (4 * observations**2)) ** 0.5) / denominator
        return [max(0.0, center - margin), min(1.0, center + margin)]

    sample_meta = None
    meta_path = labels_path.with_suffix(labels_path.suffix + ".meta.json")
    if meta_path.is_file():
        try:
            sample_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("Pilot sampling metadata could not be read.") from exc
        if sample_meta.get("selection") != "simple_random_sample_without_replacement":
            raise ValueError("Pilot sample metadata is not a recognized random sample.")
        if sample_meta.get("review_blinded_to_detector_output") is not True:
            raise ValueError("Pilot labels were not recorded using the blinded review template.")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_size": total,
        "sampling": sample_meta,
        "reviewers": sorted({label["reviewer_code"] for label in labels.values()}),
        "low_confidence_excluded": len(low_confidence),
        "label_confidence_counts": {
            confidence: sum(label["label_confidence"] == confidence for label in all_labels.values())
            for confidence in ("high", "medium", "low")
        },
        "unreviewed_template_rows": (
            max(0, int(sample_meta.get("sample_size", 0)) - len(all_labels)) if sample_meta else None
        ),
        "confusion_matrix": counts,
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": false_positive_rate,
        "false_negative_rate": false_negative_rate,
        "f1": f1,
        "accuracy": (counts["tp"] + counts["tn"]) / total if total else 0.0,
        "balanced_accuracy": (recall + specificity) / 2 if total else 0.0,
        "wilson_95_intervals": {
            "precision": wilson(counts["tp"], counts["tp"] + counts["fp"]),
            "recall": wilson(counts["tp"], counts["tp"] + counts["fn"]),
            "specificity": wilson(counts["tn"], counts["tn"] + counts["fp"]),
            "false_positive_rate": wilson(counts["fp"], counts["tn"] + counts["fp"]),
            "false_negative_rate": wilson(counts["fn"], counts["tp"] + counts["fn"]),
        },
        "reviewed_sources": by_source,
        "scope": "Metrics describe independently labelled sampled log events only. They cannot count attacks absent from the application or gateway evidence used to find these events.",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, default=Path("logs/events.jsonl"))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--template", type=Path, help="Write a blinded random review CSV; label it using independent evidence.")
    group.add_argument("--labels", type=Path, help="Score the truth labels already filled in a review CSV.")
    parser.add_argument("--limit", type=int, default=250, help="Maximum events in the review template (default: 250).")
    parser.add_argument("--seed", type=int, default=20261009, help="Reproducible random-sample seed (default: 20261009).")
    parser.add_argument("--report", type=Path, help="Write aggregate metrics JSON when scoring labels.")
    args = parser.parse_args(argv)
    try:
        if args.template:
            count = write_review_template(args.events, args.template, args.limit, args.seed)
            print(f"Created a blinded random review sheet with {count} events (seed {args.seed}). No detector decisions, payloads, IPs, or URLs were copied.")
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
