"""Evaluate the unchanged local MLP on the independent HttpParams test split."""

import argparse
import csv
from collections import Counter
import hashlib
import json
from pathlib import Path

import numpy as np
from threadpoolctl import threadpool_limits

from features import FEATURE_NAMES, MAX_SQL_LENGTH, vectorize
from service import load_model

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
DEFAULT_DATASET = ROOT / "tests" / "fixtures" / "HttpParamsDataset" / "payload_test.csv"
DEFAULT_MODEL = BASE / "models" / "model.joblib"
DEFAULT_REPORT = BASE / "models" / "external_evaluation.json"
EXPECTED_DATASET_SHA256 = "d8015e256ce4499c8ac7a8be8dd25de6487cf018601edf1a03a408a2c8f0e39d"
DATASET_URL = "https://github.com/Morzeux/HttpParamsDataset/blob/master/payload_test.csv"
BATCH_SIZE = 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_metrics(counts):
    tn, fp = counts["tn"], counts["fp"]
    fn, tp = counts["fn"], counts["tp"]
    total = tn + fp + fn + tp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": round((tn + tp) / total, 6) if total else 0.0,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "specificity": round(specificity, 6),
        "f1": round(f1, 6),
        "balanced_accuracy": round((recall + specificity) / 2, 6),
        "confusion_matrix": {
            "true_negative": tn, "false_positive": fp,
            "false_negative": fn, "true_positive": tp,
        },
    }


def evaluate(dataset_path=DEFAULT_DATASET, model_path=DEFAULT_MODEL):
    dataset_path, model_path = Path(dataset_path), Path(model_path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Jeu externe manquant : {dataset_path}")
    dataset_hash = sha256_file(dataset_path)
    if dataset_hash != EXPECTED_DATASET_SHA256:
        raise ValueError("Empreinte du jeu externe incorrecte; vérifier sa provenance avant l’évaluation.")

    artifact = load_model(model_path)
    classifier, scaler = artifact["classifier"], artifact["scaler"]
    threshold = float(artifact["threshold"])
    rows = Counter()
    source_labels = Counter()
    excluded_attacks = Counter()
    confusion = Counter()
    batch_x, batch_y = [], []

    def flush_batch():
        if not batch_x:
            return
        values = np.asarray(batch_x, dtype=float)
        with threadpool_limits(limits=1):
            scores = classifier.predict_proba(scaler.transform(values))[:, 1]
        for expected, score in zip(batch_y, scores):
            predicted = int(float(score) >= threshold)
            confusion[{(0, 0): "tn", (0, 1): "fp", (1, 0): "fn", (1, 1): "tp"}[(expected, predicted)]] += 1
        batch_x.clear()
        batch_y.clear()

    with dataset_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not {"payload", "attack_type", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("Le CSV ne contient pas les colonnes attendues (payload, attack_type, label).")
        for row in reader:
            rows["total"] += 1
            category, label = (row.get("attack_type") or "").strip().lower(), (row.get("label") or "").strip().lower()
            source_labels[f"{category}:{label}"] += 1
            if category == "norm" and label == "norm":
                expected = 0
            elif category == "sqli" and label == "anom":
                expected = 1
            elif category in {"xss", "cmdi", "path-traversal"} and label == "anom":
                excluded_attacks[category] += 1
                continue
            else:
                raise ValueError(f"Étiquette inattendue ou incohérente : attack_type={category!r}, label={label!r}")

            payload = row.get("payload") or ""
            if len(payload) > MAX_SQL_LENGTH:
                rows["too_long_rejected_by_gateway"] += 1
                continue
            batch_x.append(vectorize(payload))
            batch_y.append(expected)
            rows["evaluated"] += 1
            if len(batch_x) >= BATCH_SIZE:
                flush_batch()
    flush_batch()

    return {
        "evaluation": "independent_public_test_split",
        "dataset": {
            "name": "HttpParamsDataset payload_test.csv",
            "source_url": DATASET_URL,
            "license": "MIT (upstream LICENSE included beside the fixture)",
            "sha256": dataset_hash,
            "rows_total": rows["total"],
            "source_label_counts": dict(sorted(source_labels.items())),
            "excluded_non_sqli_attacks": dict(sorted(excluded_attacks.items())),
            "excluded_overlength_payloads": rows["too_long_rejected_by_gateway"],
        },
        "model": {
            "version": artifact["model_version"],
            "sha256": sha256_file(model_path),
            "training_dataset": artifact["dataset_source"],
            "threshold": threshold,
            "feature_schema": artifact["feature_schema"],
            "feature_count": len(FEATURE_NAMES),
        },
        "protocol": "Unchanged model; no retraining or threshold tuning on this test split. SQLi is positive and norm is negative. Other attack families are outside this SQLi-only MVP and excluded.",
        "evaluated_rows": rows["evaluated"],
        "metrics": binary_metrics(confusion),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    args = parser.parse_args()
    report = evaluate(args.dataset, args.model)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
