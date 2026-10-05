"""Train the documented dense MLP and evaluate held-out synthetic templates."""

import argparse
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
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from threadpoolctl import threadpool_limits

from dataset import build_dataset
from features import FEATURE_NAMES, FEATURE_SCHEMA, vectorize

BASE = Path(__file__).resolve().parent
THRESHOLD = 0.75
MODEL_VERSION = "cybershield-mlp-demo-v1"


def metrics(labels, scores):
    predictions = (np.asarray(scores) >= THRESHOLD).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
    return {"accuracy": float(accuracy_score(labels, predictions)), "precision": float(precision),
            "recall": float(recall), "f1": float(f1),
            "confusion_matrix": {"true_negative": int(tn), "false_positive": int(fp),
                                 "false_negative": int(fn), "true_positive": int(tp)}}


def train(output_dir=BASE / "models", max_iter=500):
    records = build_dataset()
    training = [row for row in records if row["partition"] == "train"]
    validation = [row for row in records if row["partition"] == "validation"]
    x_train = np.asarray([vectorize(row["sql"]) for row in training])
    y_train = np.asarray([row["label"] for row in training])
    x_validation = np.asarray([vectorize(row["sql"]) for row in validation])
    y_validation = np.asarray([row["label"] for row in validation])
    scaler = StandardScaler().fit(x_train)
    classifier = MLPClassifier(hidden_layer_sizes=(128, 64, 32), activation="relu", solver="adam",
                               learning_rate_init=0.001, random_state=42, max_iter=max_iter,
                               batch_size=32, early_stopping=False, n_iter_no_change=35, tol=1e-5)
    with warnings.catch_warnings(record=True) as caught, threadpool_limits(limits=1):
        warnings.simplefilter("always", ConvergenceWarning)
        classifier.fit(scaler.transform(x_train), y_train)
    converged = not any(issubclass(item.category, ConvergenceWarning) for item in caught)
    scores = classifier.predict_proba(scaler.transform(x_validation))[:, 1]
    dataset_bytes = json.dumps(records, sort_keys=True, ensure_ascii=False).encode("utf-8")
    dataset_sha256 = hashlib.sha256(dataset_bytes).hexdigest()
    report = {
        "model_version": MODEL_VERSION, "dataset_source": "synthetic_demo", "dataset_sha256": dataset_sha256,
        "limitations": "Small generated teaching corpus. Not the original 10,000-record corpus. Not production validation; scores are uncalibrated.",
        "split_method": "Disjoint template groups declared before training; no tuning on validation.",
        "random_seed": 42, "architecture": [len(FEATURE_NAMES), 128, 64, 32, 1],
        "activation": "relu", "output_activation": "logistic", "optimizer": "adam",
        "learning_rate": 0.001, "threshold": THRESHOLD, "sklearn_version": sklearn.__version__,
        "python_version": platform.python_version(), "numpy_version": np.__version__,
        "feature_schema": FEATURE_SCHEMA, "feature_names": list(FEATURE_NAMES),
        "epochs": int(classifier.n_iter_), "converged": converged,
        "training_records": len(training), "validation_records": len(validation),
        "training_groups": sorted({row["group"] for row in training}),
        "validation_groups": sorted({row["group"] for row in validation}),
        "validation_metrics": metrics(y_validation, scores),
        "per_family": {},
    }
    for family in sorted({row["family"] for row in validation}):
        indexes = [index for index, row in enumerate(validation) if row["family"] == family]
        correct = sum(int(scores[index] >= THRESHOLD) == validation[index]["label"] for index in indexes)
        report["per_family"][family] = {"records": len(indexes), "correct": correct, "accuracy": correct / len(indexes)}
    artifact = {"model_version": MODEL_VERSION, "feature_schema": FEATURE_SCHEMA, "feature_names": list(FEATURE_NAMES),
                "threshold": THRESHOLD, "dataset_source": "synthetic_demo", "dataset_sha256": dataset_sha256,
                "sklearn_version": sklearn.__version__, "classifier": classifier, "scaler": scaler}
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    temporary = output_dir / "model.joblib.tmp"
    joblib.dump(artifact, temporary, compress=3)
    os.replace(temporary, output_dir / "model.joblib")
    (output_dir / "training_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "synthetic_dataset.json").write_text(json.dumps(records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=BASE / "models")
    parser.add_argument("--max-iter", type=int, default=500)
    args = parser.parse_args()
    if not 1 <= args.max_iter <= 5000:
        parser.error("--max-iter must be between 1 and 5000")
    print(json.dumps(train(args.output_dir, args.max_iter), indent=2, ensure_ascii=False))
