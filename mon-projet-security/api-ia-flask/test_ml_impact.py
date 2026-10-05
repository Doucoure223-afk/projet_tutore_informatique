"""
Script pour mesurer l'impact réel du modèle ML.
Appelle l'API /analyze avec plusieurs entrées et affiche risk, confidence, ml_used.
Lancer l'API avant : python app.py (sur port 5000).
Comparer : avec model.joblib (ml_used=true) vs sans (renommer model.joblib, ml_used=false).
"""
import json
import urllib.request
import sys

API_URL = "http://127.0.0.1:5000/analyze"

# Entrées de test : bénin, zone grise (déclenche l'IA côté PHP), SQLi évident
TEST_CASES = [
    ("Bénin", "admin"),
    ("Bénin", "user123"),
    ("Zone grise (IA)", "1 and 1=1"),
    ("Zone grise (IA)", "select from table"),
    ("Zone grise (IA)", "user' or 'a'='a"),
    ("SQLi évident", "' OR '1'='1'--"),
    ("SQLi évident", "' UNION SELECT null,null--"),
]

def call_analyze(input_str: str) -> dict:
    req = urllib.request.Request(
        API_URL,
        data=json.dumps({
            "input": input_str,
            "context": {"type": "login", "parameter": "username"},
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


def main():
    print("=" * 60)
    print("Test impact ML - API Flask (127.0.0.1:5000)")
    print("=" * 60)
    print()

    for label, input_str in TEST_CASES:
        try:
            out = call_analyze(input_str)
            risk = out.get("risk", 0)
            conf = out.get("confidence", 0)
            ml = out.get("ml_used", False)
            typ = out.get("type", "?")
            bloc = "BLOQUER" if risk > 0.75 else "autorisé"
            print(f"[{label}]")
            print(f"  Entrée  : {input_str[:50]!r}")
            print(f"  Risk    : {risk:.3f}  |  Confidence : {conf:.3f}  |  Type : {typ}")
            print(f"  ML utilisé : {ml}  =>  Décision : {bloc}")
            print()
        except Exception as e:
            print(f"[{label}] Erreur : {e}")
            print("  => Lancez l'API avec : python app.py")
            print()
            sys.exit(1)

    print("=" * 60)
    print("Pour comparer avec/sans ML :")
    print("  1. Avec modèle  : python app.py (model.joblib présent) => ml_used=true")
    print("  2. Sans modèle  : renommer model.joblib, relancer app.py => ml_used=false")
    print("  3. Relancer ce script : python test_ml_impact.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
