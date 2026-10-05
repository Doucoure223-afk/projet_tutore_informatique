"""
Test du chargement du dataset (étape 1).
Usage: python test_dataset_load.py
"""
from dataset import get_labeled_data, load_sqliv3_csv, SQLIV3_PATH


def main():
    print("=" * 60)
    print("Test chargement dataset - Étape 1")
    print("=" * 60)
    print(f"\nFichier SQLiV3.csv : {SQLIV3_PATH}")
    print(f"Existe : {SQLIV3_PATH.is_file()}")

    # Test load_sqliv3_csv
    csv_texts, csv_labels = load_sqliv3_csv(max_sqli=100)
    n_sqli = sum(1 for l in csv_labels if l == 1)
    n_benign = sum(1 for l in csv_labels if l == 0)
    print(f"\n--- load_sqliv3_csv(max_sqli=100) ---")
    print(f"  SQLi (label=1) : {n_sqli}")
    print(f"  Bénins (label=0) : {n_benign}")
    if csv_texts:
        print(f"  Exemple : {repr(csv_texts[0][:60])}...")

    # Test get_labeled_data (avec CSV)
    texts, y_risk, y_types = get_labeled_data(use_csv=True, max_sqli=500)
    n_sqli_full = sum(1 for r in y_risk if r == 1)
    n_benign_full = sum(1 for r in y_risk if r == 0)
    print(f"\n--- get_labeled_data(use_csv=True, max_sqli=500) ---")
    print(f"  Total : {len(texts)}")
    print(f"  SQLi : {n_sqli_full}")
    print(f"  Bénins : {n_benign_full}")
    print(f"  Ratio SQLi/Bénins : {n_sqli_full / max(n_benign_full, 1):.2f}")

    # Test get_labeled_data (sans CSV - repli)
    texts_fb, y_fb, _ = get_labeled_data(use_csv=False)
    print(f"\n--- get_labeled_data(use_csv=False) [repli] ---")
    print(f"  Total : {len(texts_fb)}")
    print(f"  SQLi : {sum(1 for r in y_fb if r == 1)}")
    print(f"  Bénins : {sum(1 for r in y_fb if r == 0)}")

    print("\n" + "=" * 60)
    print("OK - Étape 1 validée")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
