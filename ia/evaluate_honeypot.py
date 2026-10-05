"""Evaluate the unchanged MLP on observed, labeled SR-BH 2020 HTTP requests."""

import argparse
from collections import Counter
import csv
from email import policy
from email.parser import BytesParser
import html
import hashlib
import json
from http.cookies import SimpleCookie
from pathlib import Path
import re
from urllib.parse import parse_qsl, unquote, urlsplit

import numpy as np
from threadpoolctl import threadpool_limits

from features import FEATURE_NAMES, MAX_SQL_LENGTH, vectorize
from service import load_model

BASE = Path(__file__).resolve().parent
DEFAULT_MODEL = BASE / "models" / "model.joblib"
DEFAULT_REPORT = BASE / "models" / "honeypot_evaluation.json"
DATASET_DOI = "10.7910/DVN/OGOIXX"
DATASET_URL = "https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/OGOIXX"
DATASET_API_URL = "https://dataverse.harvard.edu/api/access/datafile/6319496"
OFFICIAL_MD5 = "173ec515308bdce5aec19cfd5b792596"
MAX_PARAMETERS = 128
MAX_REQUEST_BYTES = 65536
BATCH_REQUESTS = 512
MAX_AI_CALLS_PER_REQUEST = 4
REVIEW_THRESHOLD = 30
BLOCK_THRESHOLD = 80

NORMAL_LABEL = "000 - Normal"
SQLI_LABEL = "66 - SQL Injection"
OTHER_LABELS = (
    "272 - Protocol Manipulation", "242 - Code Injection", "88 - OS Command Injection",
    "126 - Path Traversal", "16 - Dictionary-based Password Attack",
    "310 - Scanning for Vulnerable Software", "153 - Input Data Manipulation",
    "248 - Command Injection", "274 - HTTP Verb Tampering",
    "194 - Fake the Source of Data", "34 - HTTP Response Splitting",
    "33 - HTTP Request Smuggling",
)

# Mirrors security/detector.php so this report can measure the deployed
# rule-first policy as well as the MLP in isolation.
RULES = (
    (r"\bunion\s+(?:(?:all|distinct)\s+)?select\b", 95),
    (r"\b(?:or|and)\s+(?:not\s+)?[+-]?\d+(?:\.\d+)?\s*(?:=|!=|<>|>=|<=|>|<)\s*[+-]?\d+(?:\.\d+)?\b", 90),
    (r"\b(?:or|and)\s+['\"][^'\"\r\n]{1,80}['\"]\s*(?:=|!=|<>|like\b)\s*['\"][^'\"\r\n]{1,80}", 90),
    (r"\b(?:or|and)\s+(?:exists\s*\(|\d+\s+(?:between\s+\d+|in\s*\(|is\s+(?:not\s+)?null))", 90),
    (r"(?:['\"]\s*|\d+\s+)(?:or|and)\s+(?:true|false)\b", 90),
    (r";\s*(?:drop|truncate|delete|insert|update|alter|create|exec(?:ute)?)\b", 100),
    (r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b", 95),
    (r"\b(?:extractvalue|updatexml)\s*\(", 95),
    (r"\bload_file\s*\(|\binto\s+(?:out|dump)file\b", 95),
    (r"['\"]\s*(?:--|#|/\*)", 60),
    (r"\b(?:information_schema|pg_catalog|sqlite_master|sysobjects)\b", 65),
    (r"\bselect\b[^;\r\n]{1,1000}\bfrom\b", 45),
    (r"\b(?:insert\s+into|delete\s+from|update\s+[\w`]+\s+set)\b", 60),
    (r"\b(?:char|nchar|chr)\s*\(\s*\d+(?:\s*,\s*\d+)+\s*\)", 45),
)
SPLIT_KEYWORDS = ("union", "select", "all", "distinct", "or", "and", "sleep", "benchmark",
                  "drop", "delete", "from", "where", "insert", "update")
COMPILED_RULES = tuple((re.compile(pattern, re.IGNORECASE), weight)
                       for pattern, weight in sorted(RULES, key=lambda item: -item[1]))


def heuristic_score(value):
    """Mirror PHP rule scores, returning as soon as the maximum is established."""
    normalized = value
    for _ in range(3):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    normalized = html.unescape(normalized).replace("\0", "")
    if "/*" in normalized:
        comment = r"(?:/\*[^*]*(?:\*(?!/)[^*]*)*\*/)*"
        for keyword in SPLIT_KEYWORDS:
            pattern = r"\b" + comment.join(re.escape(char) for char in keyword) + r"\b"
            normalized = re.sub(pattern, keyword, normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"/\*!\d{0,6}\s*(.*?)\*/", r" \1 ", normalized, flags=re.DOTALL)
    variants = tuple(dict.fromkeys((
        normalized,
        re.sub(r"/\*.*?\*/", " ", normalized, flags=re.DOTALL),
        re.sub(r"/\*.*?\*/", "", normalized, flags=re.DOTALL),
    )))
    for pattern, weight in COMPILED_RULES:
        if any(pattern.search(variant) for variant in variants):
            return weight
    return 0


def digest_file(path, algorithm):
    digest = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class GatewayRejected(Exception):
    """The PHP input size/depth limits would reject the request before inference."""


def _pairs_to_values(text):
    try:
        pairs = parse_qsl(text, keep_blank_values=True, max_num_fields=MAX_PARAMETERS + 1)
    except ValueError as error:
        raise GatewayRejected from error
    return [value for _, value in pairs]


def _json_values(value, depth=0):
    if depth > 8:
        raise GatewayRejected
    if isinstance(value, dict):
        for item in value.values():
            yield from _json_values(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            yield from _json_values(item, depth + 1)
    elif value is None or isinstance(value, (str, int, float, bool)):
        yield "" if value is None else str(value)
    else:
        raise GatewayRejected


def _multipart_values(body, content_type):
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n{body}".encode("utf-8", errors="replace")
    )
    values = []
    if not message.is_multipart():
        return values
    for part in message.iter_parts():
        if part.get_content_disposition() == "form-data" and not part.get_filename():
            value = part.get_content()
            if isinstance(value, str):
                values.append(value)
    return values


def request_inputs(row):
    target = row.get("request_http_request") or ""
    body = row.get("request_body") or ""
    parsed_target = urlsplit(target)
    query = parsed_target.query
    if len(query.encode("utf-8", errors="replace")) > MAX_REQUEST_BYTES:
        raise GatewayRejected
    if len(body.encode("utf-8", errors="replace")) > MAX_REQUEST_BYTES:
        raise GatewayRejected

    values = [unquote(parsed_target.path)] + _pairs_to_values(query)
    content_type = (row.get("request_content_type") or "").lower()
    if content_type.startswith("application/json"):
        try:
            values.extend(_json_values(json.loads(body)))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise GatewayRejected
    elif content_type.startswith("application/x-www-form-urlencoded"):
        values.extend(_pairs_to_values(body))
    elif content_type.startswith("multipart/form-data"):
        values.extend(_multipart_values(body, content_type))

    cookie_text = row.get("request_cookie") or ""
    if cookie_text:
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_text)
        except Exception:
            cookies = SimpleCookie()
        values.extend(morsel.value for morsel in cookies.values())

    if len(values) > MAX_PARAMETERS or any(len(value) > MAX_SQL_LENGTH for value in values):
        raise GatewayRejected
    return values


def metric(counts):
    tn, fp, fn, tp = (counts[name] for name in ("tn", "fp", "fn", "tp"))
    total = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "rows": total,
        "accuracy": round((tn + tp) / total, 6) if total else 0.0,
        "precision": round(precision, 6), "recall": round(recall, 6),
        "specificity": round(specificity, 6), "f1": round(f1, 6),
        "balanced_accuracy": round((recall + specificity) / 2, 6),
        "confusion_matrix": {"true_negative": tn, "false_positive": fp,
                             "false_negative": fn, "true_positive": tp},
    }


def evaluate(dataset_path, model_path=DEFAULT_MODEL, max_rows=None):
    dataset_path, model_path = Path(dataset_path), Path(model_path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Fichier SR-BH 2020 manquant : {dataset_path}")
    md5 = digest_file(dataset_path, "md5")
    if md5 != OFFICIAL_MD5:
        raise ValueError("MD5 différent de la version officielle Harvard Dataverse v1.2.")
    sha256 = digest_file(dataset_path, "sha256")
    artifact = load_model(model_path)
    classifier, scaler = artifact["classifier"], artifact["scaler"]
    threshold = float(artifact["threshold"])

    counts = Counter()
    labels = Counter()
    mlp_counts = Counter()
    gateway_plus_mlp = Counter()
    hybrid_counts = Counter()
    bounded_prescreen_counts = Counter()
    pending = []

    def add_result(counter, expected, predicted):
        counter[{(0, 0): "tn", (0, 1): "fp", (1, 0): "fn", (1, 1): "tp"}[(expected, predicted)]] += 1

    def flush():
        if not pending:
            return
        vectors, request_lengths = [], []
        for _, values, _, _ in pending:
            selected = [vectorize(value) for value in values]
            vectors.extend(selected)
            request_lengths.append(len(selected))
        if vectors:
            matrix = np.asarray(vectors, dtype=float)
            with threadpool_limits(limits=1):
                predictions = classifier.predict_proba(scaler.transform(matrix))[:, 1] >= threshold
        else:
            predictions = np.asarray([], dtype=bool)
        offset = 0
        for (expected, values, gateway_rejected, rule_scores), length in zip(pending, request_lengths):
            request_predictions = predictions[offset:offset + length]
            model_block = bool(np.any(request_predictions))
            offset += length
            # Rows rejected by the input size/depth guard are counted as blocked
            # by the gateway; the MLP result is reported separately.
            if not gateway_rejected:
                add_result(mlp_counts, expected, int(model_block))
            add_result(gateway_plus_mlp, expected, int(gateway_rejected or model_block))

            # Match HybridAnalyzer and middleware order: explicit signatures
            # block immediately; only the 30..79 gray zone reaches the MLP;
            # at most four gray-zone values call it per request. When that
            # budget is exceeded, the production behavior is fail-safe block.
            hybrid_block = gateway_rejected
            ai_calls = 0
            if not hybrid_block:
                for rule_score, mlp_block in zip(rule_scores, request_predictions):
                    if rule_score >= BLOCK_THRESHOLD:
                        hybrid_block = True
                        break
                    if rule_score >= REVIEW_THRESHOLD:
                        if ai_calls >= MAX_AI_CALLS_PER_REQUEST:
                            hybrid_block = True
                            break
                        ai_calls += 1
                        if mlp_block:
                            hybrid_block = True
                            break
            add_result(hybrid_counts, expected, int(hybrid_block))

            # Candidate policy for validation: use the same four-call request
            # budget to pre-screen the first four values even when rules score
            # below the current review threshold. Gray-zone values beyond the
            # budget retain the existing fail-safe behavior.
            prescreen_block = gateway_rejected
            prescreen_calls = 0
            if not prescreen_block:
                for rule_score, mlp_block in zip(rule_scores, request_predictions):
                    if rule_score >= BLOCK_THRESHOLD:
                        prescreen_block = True
                        break
                    if prescreen_calls < MAX_AI_CALLS_PER_REQUEST:
                        prescreen_calls += 1
                        if mlp_block:
                            prescreen_block = True
                            break
                    elif rule_score >= REVIEW_THRESHOLD:
                        prescreen_block = True
                        break
            add_result(bounded_prescreen_counts, expected, int(prescreen_block))
        pending.clear()

    with dataset_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"request_http_request", "request_body", "request_content_type", "request_cookie", NORMAL_LABEL, SQLI_LABEL, *OTHER_LABELS}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("Colonnes inattendues dans la capture SR-BH 2020.")
        for row in reader:
            if max_rows is not None and counts["source_rows"] >= max_rows:
                break
            counts["source_rows"] += 1
            normal = row[NORMAL_LABEL].strip() == "1"
            sqli = row[SQLI_LABEL].strip() == "1"
            other_attack = any(row[column].strip() == "1" for column in OTHER_LABELS)
            if normal and sqli:
                counts["excluded_conflicting_normal_and_sqli_labels"] += 1
                continue
            if sqli:
                expected = 1
                counts["sqli_label_rows"] += 1
                if other_attack:
                    counts["sqli_rows_with_other_attack_labels"] += 1
            elif normal and not other_attack:
                expected = 0
                counts["strict_normal_rows"] += 1
            else:
                counts["excluded_other_or_ambiguous_labels"] += 1
                continue

            try:
                values = request_inputs(row)
                rejected = False
            except GatewayRejected:
                values, rejected = [], True
                counts["gateway_rejected_rows"] += 1
            if not values and not rejected:
                counts["labeled_rows_without_scanned_parameters"] += 1
            pending.append((expected, values, rejected, [heuristic_score(value) for value in values]))
            counts["evaluation_rows"] += 1
            if len(pending) >= BATCH_REQUESTS:
                flush()
    flush()

    return {
        "evaluation": "development_replay_on_observed_honeypot_capture",
        "model_was_trained_on_capture": False,
        "gate_policy_selected_after_diagnostic_replay": True,
        "dataset": {
            "name": "SR-BH 2020 multi-label web honeypot requests",
            "doi": DATASET_DOI,
            "source_url": DATASET_URL,
            "download_api": DATASET_API_URL,
            "license": "CC0 1.0",
            "official_md5": md5,
            "sha256": sha256,
            "version": "1.2",
            "source_rows_processed": counts["source_rows"],
            "evaluation_rows": counts["evaluation_rows"],
            "strict_normal_rows": counts["strict_normal_rows"],
            "sqli_label_rows": counts["sqli_label_rows"],
            "sqli_rows_with_other_attack_labels": counts["sqli_rows_with_other_attack_labels"],
            "excluded_conflicting_normal_and_sqli_labels": counts["excluded_conflicting_normal_and_sqli_labels"],
            "excluded_other_or_ambiguous_labels": counts["excluded_other_or_ambiguous_labels"],
            "gateway_rejected_rows": counts["gateway_rejected_rows"],
            "labeled_rows_without_scanned_parameters": counts["labeled_rows_without_scanned_parameters"],
        },
        "model": {
            "version": artifact["model_version"], "sha256": digest_file(model_path, "sha256"),
            "training_dataset": artifact["dataset_source"], "threshold": threshold,
            "feature_schema": artifact["feature_schema"], "feature_count": len(FEATURE_NAMES),
        },
        "protocol": "The unchanged model is applied to the decoded URL path and GET/POST/JSON/cookie values, matching the PHP middleware input scope. SQLi CAPEC labels are positive; strictly normal rows are negative. Other attack families and conflicting labels are excluded. No training or threshold selection uses this capture. MLP-only metrics exclude requests stopped by gateway size/depth limits; gateway-plus-MLP metrics count those rejects as blocks. Runtime-hybrid metrics simulate detector.php rule scores and middleware ordering, the 30/80 thresholds, MLP pre-screening of up to four request values, and fail-safe blocking for gray-zone values after that budget is exceeded. Previous gray-zone-only metrics are retained for comparison. The Python rule mirror is regression-tested against representative PHP signatures.",
        "mlp_only_metrics": metric(mlp_counts),
        "gateway_plus_mlp_metrics": metric(gateway_plus_mlp),
        "previous_gray_zone_only_metrics": metric(hybrid_counts),
        "runtime_hybrid_metrics": metric(bounded_prescreen_counts),
        "previous_gray_zone_only_policy": {
            "mlp_values": "only values with rule scores from 30 to 79 received MLP analysis",
            "max_mlp_calls_per_request": MAX_AI_CALLS_PER_REQUEST,
            "budget_exceeded": "fail-safe block",
        },
        "runtime_hybrid_policy": {
            "rules": "security/detector.php immediate-block signatures; maximum matching score is used",
            "review_threshold": REVIEW_THRESHOLD,
            "block_threshold": BLOCK_THRESHOLD,
            "mlp_values": "first four non-immediately-blocked values per request are screened by the MLP, including score-0 values",
            "max_mlp_calls_per_request": MAX_AI_CALLS_PER_REQUEST,
            "budget_exceeded": "gray-zone values fail-safe block; lower-scored values skip MLP",
            "note": "Replay of the middleware decision policy with an equivalent Python rule mirror; not an end-to-end HTTP load test.",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True, help="Path to data_capec_multilabel.csv from Harvard Dataverse")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--max-rows", type=int, help="Optional prefix limit for development checks; omit for the complete capture")
    args = parser.parse_args()
    if args.max_rows is not None and args.max_rows < 1:
        parser.error("--max-rows must be positive")
    report = evaluate(args.dataset, args.model, args.max_rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
