"""Train the SQLi MLP from the pinned public HttpParamsDataset training split."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import warnings

import joblib
import numpy as np
import sklearn
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

from features import FEATURE_NAMES, FEATURE_SCHEMA, vectorize

BASE = Path(__file__).resolve().parent
ROOT = BASE.parent
DEFAULT_DATASET = ROOT / "tests" / "fixtures" / "HttpParamsDataset" / "payload_train.csv"
EXPECTED_DATASET_SHA256 = "dfa6e59c87b2bafc485c9cb14d37e3f86607d180e5a22e7c46dae6d3d1dd6a16"
DATASET_SOURCE = "HttpParamsDataset_payload_train"
DATASET_URL = "https://github.com/Morzeux/HttpParamsDataset/blob/master/payload_train.csv"
MODEL_VERSION = "cybershield-mlp-httpparams-v2"
THRESHOLD = 0.75
BATCH_SIZE = 256
VALIDATION_FRACTION = 0.1


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_dataset(dataset_path):
    dataset_path = Path(dataset_path)
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Jeu d'entraînement manquant : {dataset_path}")
    dataset_hash = sha256_file(dataset_path)
    if dataset_path.resolve() == DEFAULT_DATASET.resolve() and dataset_hash != EXPECTED_DATASET_SHA256:
        raise ValueError("Empreinte du jeu d'entraînement incorrecte; vérifier sa provenance avant l'entraînement.")

    rows = []
    classes = {"norm": 0, "sqli": 0}
    excluded = {}
    with dataset_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if not {"payload", "attack_type", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("Le CSV ne contient pas les colonnes attendues (payload, attack_type, label).")
        for row in reader:
            category = (row.get("attack_type") or "").strip().lower()
            label = (row.get("label") or "").strip().lower()
            if category == "norm" and label == "norm":
                expected = 0
            elif category == "sqli" and label == "anom":
                expected = 1
            elif category in {"xss", "cmdi", "path-traversal"} and label == "anom":
                excluded[category] = excluded.get(category, 0) + 1
                continue
            else:
                raise ValueError(f"Étiquette inattendue ou incohérente : attack_type={category!r}, label={label!r}")
            payload = row.get("payload") or ""
            # The deployed endpoint rejects these before inference. Keep training
            # aligned with its reachable input domain rather than truncating them.
            if len(payload) > 8192:
                excluded["overlength"] = excluded.get("overlength", 0) + 1
                continue
            rows.append((payload, expected))
            classes["sqli" if expected else "norm"] += 1
    if not rows or not classes["norm"] or not classes["sqli"]:
        raise ValueError("Le jeu doit contenir des exemples normaux et SQLi.")
    return rows, classes, excluded, dataset_hash


def train(output_dir=BASE / "models", dataset_path=DEFAULT_DATASET, max_iter=300):
    dataset_path = Path(dataset_path)
    records, class_counts, excluded, dataset_hash = load_dataset(dataset_path)
    pinned_source = dataset_hash == EXPECTED_DATASET_SHA256
    dataset_source = DATASET_SOURCE if pinned_source else "custom_training_csv"
    x_train = np.asarray([vectorize(payload) for payload, _ in records], dtype=float)
    y_train = np.asarray([label for _, label in records], dtype=int)
    scaler = StandardScaler().fit(x_train)
    classifier = MLPClassifier(hidden_layer_sizes=(128, 64, 32), activation="relu", solver="adam",
                               learning_rate_init=0.001, random_state=42, max_iter=max_iter,
                               batch_size=BATCH_SIZE, early_stopping=True, n_iter_no_change=15,
                               validation_fraction=VALIDATION_FRACTION, tol=1e-5)
    with warnings.catch_warnings(record=True) as caught, threadpool_limits(limits=1):
        warnings.simplefilter("always", ConvergenceWarning)
        classifier.fit(scaler.transform(x_train), y_train)
    converged = not any(issubclass(item.category, ConvergenceWarning) for item in caught)
    report = {
        "model_version": MODEL_VERSION,
        "dataset_source": dataset_source,
        "dataset": {
            "name": "HttpParamsDataset payload_train.csv" if pinned_source else dataset_path.name,
            "source_url": DATASET_URL if pinned_source else None,
            "license": "MIT (upstream LICENSE included beside the fixture)" if pinned_source else "not asserted for custom data",
            "sha256": dataset_hash,
            "selected_rows": len(records),
            "class_counts": class_counts,
            "excluded_rows": excluded,
            "selection": "attack_type=norm/label=norm as negative; attack_type=sqli/label=anom as positive; other attack families excluded",
        },
        "limitations": ("Upstream normal values are derived from CSIC 2010 and SQLi values are generated with sqlmap and other public corpora. This is a reproducible public benchmark, not live traffic; it does not establish production effectiveness." if pinned_source else "Custom training data: independently verify its source, license, labels, and separation from evaluation data; training scores do not establish production effectiveness."),
        "validation_method": "MLP early stopping reserves 10% of the training split internally. The separate upstream payload_test.csv and SR-BH 2020 capture are not used for fitting or threshold selection.",
        "random_seed": 42,
        "architecture": [len(FEATURE_NAMES), 128, 64, 32, 1],
        "activation": "relu",
        "output_activation": "logistic",
        "optimizer": "adam",
        "learning_rate": 0.001,
        "batch_size": BATCH_SIZE,
        "early_stopping": True,
        "validation_fraction": VALIDATION_FRACTION,
        "n_iter_no_change": 15,
        "threshold": THRESHOLD,
        "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(),
        "numpy_version": np.__version__,
        "feature_schema": FEATURE_SCHEMA,
        "feature_names": list(FEATURE_NAMES),
        "epochs": int(classifier.n_iter_),
        "converged": converged,
        "best_internal_validation_accuracy": float(classifier.best_validation_score_),
        "training_records": len(records),
    }
    artifact = {"model_version": MODEL_VERSION, "feature_schema": FEATURE_SCHEMA, "feature_names": list(FEATURE_NAMES),
                "threshold": THRESHOLD, "dataset_source": dataset_source, "dataset_sha256": dataset_hash,
                "sklearn_version": sklearn.__version__, "classifier": classifier, "scaler": scaler}
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    temporary = output_dir / "model.joblib.tmp"
    joblib.dump(artifact, temporary, compress=3)
    os.replace(temporary, output_dir / "model.joblib")
    (output_dir / "training_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output-dir", type=Path, default=BASE / "models")
    parser.add_argument("--max-iter", type=int, default=300)
    args = parser.parse_args()
    if not 1 <= args.max_iter <= 5000:
        parser.error("--max-iter must be between 1 and 5000")
    print(json.dumps(train(args.output_dir, args.dataset, args.max_iter), indent=2, ensure_ascii=False))
