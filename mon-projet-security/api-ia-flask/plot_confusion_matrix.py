"""
Génère la Figure 5.2 : Matrice de confusion du classifieur MLP sur 10 000 requêtes.
Usage: python plot_confusion_matrix.py
Produit: figure_5_2_confusion_matrix.png
"""
import os
import numpy as np

# Matrice de confusion sur 10 000 requêtes (lignes = Classe réelle, colonnes = Prédit)
# Réel Sain : 4975 VN, 25 FP  |  Réel SQLi : 12 FN, 4988 VP
CM = np.array([
    [4975, 25],   # Réel Sain  : 4975 (VN), 25 (FP)
    [12, 4988],   # Réel SQLi  : 12 (FN), 4988 (VP)
])

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
FIGURE_PATH = os.path.join(OUTPUT_DIR, "figure_5_2_confusion_matrix.png")


def main():
    cm = CM
    n_actual = int(cm.sum())
    print(f"Matrice de confusion (sur {n_actual:,} requêtes) :")
    print("  Réel Sain :", cm[0, 0], "VN,", cm[0, 1], "FP")
    print("  Réel SQLi :", cm[1, 0], "FN,", cm[1, 1], "VP")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib requis : pip install matplotlib")
        return 1

    labels = ["Sain", "SQLi"]
    annotations = [
        ["4 975 (VN)", "25 (FP)"],
        ["12 (FN)", "4 988 (VP)"],
    ]
    fig, ax = plt.subplots(figsize=(6, 5))

    im = ax.imshow(cm, cmap="Blues", aspect="auto", vmin=0)

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels([f"Prédit : {l}" for l in labels])
    ax.set_yticklabels([f"Réel : {l}" for l in labels])
    ax.set_xlabel("Classe prédite", fontsize=11)
    ax.set_ylabel("Classe réelle", fontsize=11)
    ax.set_title(
        f" Matrice de confusion du classifieur MLP\n(sur {n_actual:,} requêtes)",
        fontsize=12,
        fontweight="bold",
    )

    thresh = cm.max() / 2
    for i in range(2):
        for j in range(2):
            ax.text(
                j, i, annotations[i][j],
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=11,
                fontweight="bold",
            )

    plt.colorbar(im, ax=ax, label="Effectif")
    plt.tight_layout()
    plt.savefig(FIGURE_PATH, dpi=150, bbox_inches="tight")
    plt.close()

    print(f"Figure enregistrée : {FIGURE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
