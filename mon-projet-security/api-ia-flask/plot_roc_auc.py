"""
Génère la courbe ROC et l'AUC du classifieur MLP (détection SQLi).
Usage: python plot_roc_auc.py
Produit: figure_roc_auc.png
"""
import os
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_curve, roc_auc_score

from dataset import get_labeled_data
from features import extract_features_dict, features_to_vector

RANDOM_STATE = 42
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
FIGURE_PATH = os.path.join(OUTPUT_DIR, "figure_roc_auc.png")


def main():
    texts, y_risk, _ = get_labeled_data(use_csv=True, max_sqli=10000)
    X = np.array([features_to_vector(extract_features_dict(t)) for t in texts], dtype=np.float64)
    y = np.array(y_risk, dtype=np.int32)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, stratify=y, random_state=RANDOM_STATE
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", MLPClassifier(
            hidden_layer_sizes=(128, 64, 32),
            activation="relu",
            solver="adam",
            max_iter=300,
            early_stopping=True,
            validation_fraction=0.1,
            random_state=RANDOM_STATE,
        )),
    ])
    pipeline.fit(X_train, y_train)

    # Probabilités pour la classe positive (SQLi = 1)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_proba)
    auc = roc_auc_score(y_test, y_proba)

    print(f"AUC = {auc:.4f}")
    print(f"Courbe ROC : {len(fpr)} points")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib requis : pip install matplotlib")
        return 1

    fig, ax = plt.subplots(figsize=(7, 6))
    ax.plot(fpr, tpr, color="#2563eb", linewidth=2, label=f"MLP (AUC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], "k--", linewidth=1, label="Aléatoire (AUC = 0.500)")
    ax.set_xlabel("Taux de faux positifs (FPR)", fontsize=11)
    ax.set_ylabel("Taux de vrais positifs (TPR)", fontsize=11)
    ax.set_title("Courbe ROC — Classifieur MLP (détection SQLi)", fontsize=12, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.set_aspect("equal")
    plt.tight_layout()
    plt.savefig(FIGURE_PATH, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"Figure enregistrée : {FIGURE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
