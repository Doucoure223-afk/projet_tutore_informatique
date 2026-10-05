"""
Entraînement du modèle ML (réseau de neurones MLP) pour la détection SQLi.
Utilise SQLiV3.csv + bénins, StandardScaler, MLPClassifier.
Génère model.joblib (pipeline scaler+MLP) et metrics.json.
Usage: python train_model.py
"""
import json
import os
from datetime import datetime, timezone

import numpy as np
import joblib
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score

from dataset import get_labeled_data
from features import FEATURE_NAMES, extract_features_dict, features_to_vector

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(MODEL_DIR, "model.joblib")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")


def main():
    texts, y_risk, _ = get_labeled_data(use_csv=True, max_sqli=10000)
    X = []
    for t in texts:
        feats = extract_features_dict(t)
        X.append(features_to_vector(feats))
    X = np.array(X, dtype=np.float64)
    y = np.array(y_risk, dtype=np.int32)

    n_sqli = int(np.sum(y == 1))
    n_benign = int(np.sum(y == 0))
    print(f"Dataset: {len(texts)} échantillons (SQLi: {n_sqli}, Bénins: {n_benign})")

    # Pipeline : StandardScaler + MLPClassifier (réseau de neurones)
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            solver="adam",
            max_iter=300,
            early_stopping=True,
            validation_fraction=0.1,
            random_state=42,
        )),
    ])
    pipeline.fit(X, y)

    # Validation croisée (scaler et MLP dans le pipeline = pas de fuite de données)
    f1_scores = cross_val_score(pipeline, X, y, cv=5, scoring="f1")
    acc_scores = cross_val_score(pipeline, X, y, cv=5, scoring="accuracy")
    precision_scores = cross_val_score(pipeline, X, y, cv=5, scoring="precision")
    recall_scores = cross_val_score(pipeline, X, y, cv=5, scoring="recall")

    f1_mean, f1_std = float(f1_scores.mean()), float(f1_scores.std())
    acc_mean = float(acc_scores.mean())
    precision_mean = float(precision_scores.mean())
    recall_mean = float(recall_scores.mean())

    print(f"\nMétriques (5-fold CV):")
    print(f"  F1:       {f1_mean:.3f} (+/- {f1_std:.3f})")
    print(f"  Accuracy: {acc_mean:.3f}")
    print(f"  Precision: {precision_mean:.3f}")
    print(f"  Recall:   {recall_mean:.3f}")

    joblib.dump({"model": pipeline, "feature_names": FEATURE_NAMES}, MODEL_PATH)
    print(f"\nModèle enregistré: {MODEL_PATH}")

    metrics = {
        "precision": round(precision_mean, 2),
        "recall": round(recall_mean, 2),
        "f1_score": round(f1_mean, 2),
        "accuracy": round(acc_mean, 2),
        "training_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "n_samples": len(texts),
        "model_type": "MLP",
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Métriques enregistrées: {METRICS_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
