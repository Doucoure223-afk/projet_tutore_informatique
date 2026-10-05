"""
Génère la Figure 4.3 : Courbes d'apprentissage (Accuracy / Loss) lors de l'entraînement du modèle MLP.
Usage: python plot_learning_curves.py
Produit: figure_4_3_learning_curves.png (dans api-ia-flask/ ou dossier indiqué)
"""
import os
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn.neural_network")
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from dataset import get_labeled_data
from features import extract_features_dict, features_to_vector

# Paramètres identiques à train_model.py
RANDOM_STATE = 42
MAX_ITER = 300
HIDDEN_LAYER_SIZES = (128, 64, 32)
VALIDATION_FRACTION = 0.1
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
FIGURE_PATH = os.path.join(OUTPUT_DIR, "figure_4_3_learning_curves.png")


def main():
    # Chargement des données (même logique que train_model.py)
    texts, y_risk, _ = get_labeled_data(use_csv=True, max_sqli=10000)
    X = np.array([features_to_vector(extract_features_dict(t)) for t in texts], dtype=np.float64)
    y = np.array(y_risk, dtype=np.int32)

    # Séparation train / validation pour les courbes
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=VALIDATION_FRACTION, random_state=RANDOM_STATE, stratify=y
    )

    # Normalisation (scaler sur l'entraînement uniquement)
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    # MLP avec warm_start pour enregistrer loss et accuracy à chaque époque
    clf = MLPClassifier(
        hidden_layer_sizes=HIDDEN_LAYER_SIZES,
        activation="relu",
        solver="adam",
        max_iter=1,
        warm_start=True,
        early_stopping=False,
        random_state=RANDOM_STATE,
    )

    history_loss = []
    history_acc_train = []
    history_acc_val = []

    print("Entraînement époque par époque (Loss + Accuracy)...")
    for epoch in range(1, MAX_ITER + 1):
        clf.fit(X_train_scaled, y_train)
        loss = clf.loss_
        history_loss.append(loss)
        acc_train = (clf.predict(X_train_scaled) == y_train).mean()
        acc_val = (clf.predict(X_val_scaled) == y_val).mean()
        history_acc_train.append(acc_train)
        history_acc_val.append(acc_val)
        if epoch % 50 == 0 or epoch == 1:
            print(f"  Epoch {epoch:3d} — Loss: {loss:.4f} — Acc train: {acc_train:.4f} — Acc val: {acc_val:.4f}")

    # Génération de la figure
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib non installé. Installer avec: pip install matplotlib")
        return 1

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(8, 6), sharex=True)

    epochs = np.arange(1, len(history_loss) + 1)

    # Courbe Loss
    ax1.plot(epochs, history_loss, color="#0ea5e9", linewidth=1.5, label="Loss (entraînement)")
    ax1.set_ylabel("Loss", fontsize=11)
    ax1.set_title("Figure 4.3 — Courbes d'apprentissage (Accuracy / Loss)", fontsize=12, fontweight="bold")
    ax1.legend(loc="upper right", fontsize=9)
    ax1.grid(True, alpha=0.3)
    ax1.set_ylim(bottom=0)

    # Courbes Accuracy
    ax2.plot(epochs, history_acc_train, color="#22c55e", linewidth=1.5, label="Accuracy (entraînement)")
    ax2.plot(epochs, history_acc_val, color="#f59e0b", linewidth=1.5, label="Accuracy (validation)")
    ax2.set_xlabel("Époque", fontsize=11)
    ax2.set_ylabel("Accuracy", fontsize=11)
    ax2.legend(loc="lower right", fontsize=9)
    ax2.grid(True, alpha=0.3)
    ax2.set_ylim(0, 1.02)

    plt.tight_layout()
    plt.savefig(FIGURE_PATH, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"\nFigure enregistrée : {FIGURE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
