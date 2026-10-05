"""
Jeu de données étiqueté pour l'entraînement du modèle ML (détection SQLi).
- label 1 = injection SQL (malveillant)
- label 0 = entrée normale (bénin)
- threat_type = type de menace (pour classification multi-classe optionnelle)

Charge en priorité SQLiV3.csv du dossier dataset/ ; repli sur listes Python si absent.
"""
import csv
from pathlib import Path
from typing import List, Optional, Tuple, Union

# Chemin vers SQLiV3.csv (dossier dataset/ à la racine du projet)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
SQLIV3_PATH = _PROJECT_ROOT / "dataset" / "SQLiV3.csv"

# Payloads SQLi réels (label=1) — repli si CSV absent
SQLI_SAMPLES = [
    ("' OR '1'='1", "BOOLEAN_BASED_INJECTION"),
    ("' OR 1=1--", "BOOLEAN_BASED_INJECTION"),
    ("admin'--", "COMMENT_INJECTION"),
    ("' UNION SELECT null,null,null--", "UNION_SQLi"),
    ("' UNION ALL SELECT username,password FROM users--", "UNION_SQLi"),
    ("1' AND '1'='1", "BOOLEAN_BASED_INJECTION"),
    ("'; DROP TABLE users--", "DESTRUCTIVE_SQLi"),
    ("' OR SLEEP(5)--", "TIME_BASED_SQLi"),
    ("' OR BENCHMARK(10000000,SHA1('x'))--", "TIME_BASED_SQLi"),
    ("1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "ERROR_BASED_INJECTION"),
    ("' AND 1=0 UNION ALL SELECT '1','2','3", "UNION_SQLi"),
    ("admin' #", "COMMENT_INJECTION"),
    ("' OR ''='", "BOOLEAN_BASED_INJECTION"),
    ("1; WAITFOR DELAY '0:0:5'--", "TIME_BASED_SQLi"),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", "TIME_BASED_SQLi"),
    ("' UNION SELECT table_name FROM information_schema.tables--", "UNION_SQLi"),
    ("' OR 1=1#", "BOOLEAN_BASED_INJECTION"),
    ("' OR 'x'='x", "BOOLEAN_BASED_INJECTION"),
    ("1' ORDER BY 1--", "UNION_SQLi"),
    ("' AND 1=2 UNION SELECT 1,2,3,4,5--", "UNION_SQLi"),
    ("'; TRUNCATE TABLE users; --", "DESTRUCTIVE_SQLi"),
    ("' OR ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--", "BOOLEAN_BASED_INJECTION"),
    ("1' AND (SELECT COUNT(*) FROM users)>0--", "BOOLEAN_BASED_INJECTION"),
    ("' OR EXISTS(SELECT * FROM users WHERE username='admin')--", "BOOLEAN_BASED_INJECTION"),
    ("' OR 1 IN (SELECT 1)--", "BOOLEAN_BASED_INJECTION"),
    ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "UNION_SQLi"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--", "ERROR_BASED_INJECTION"),
    ("1' AND SLEEP(3)=0--", "TIME_BASED_SQLi"),
    ("' OR (SELECT 1 FROM (SELECT SLEEP(2))a)--", "TIME_BASED_SQLi"),
    ("' OR '1'='1' /*", "COMMENT_INJECTION"),
]

# Entrées normales (label=0)
BENIGN_SAMPLES = [
    "admin",
    "user123",
    "john.doe",
    "marie-dupont",
    "test@example.com",
    "utilisateur",
    "demo",
    "guest",
    "support",
    "contact",
    "alice",
    "bob",
    "charlie",
    "password123",
    "Welcome1",
    "Paris2024",
    "Jean-Pierre",
    "user_name",
    "a",
    "abcdefgh",
    "normal_input",
    "login",
    "signin",
    "myemail@domain.fr",
    "user+tag@gmail.com",
    "12345",
    "simple",
    "texte normal",
    "recherche valide",
    "mot de passe fort",
    # Enrichissement pour équilibrer avec SQLiV3
    "recherche",
    "produit",
    "2024",
    "contact@site.fr",
    "Marie",
    "Jean",
    "Sophie",
    "motdepasse",
    "azerty",
    "qwerty",
]


def load_sqliv3_csv(
    path: Optional[Union[Path, str]] = None,
    min_length: int = 2,
    max_sqli: Optional[int] = 15000,
    encoding: str = "utf-8",
) -> Tuple[List[str], List[int]]:
    """
    Charge SQLiV3.csv : (texts, labels).
    - Filtre : lignes vides, Sentence < min_length
    - Dédoublonnage par texte
    - max_sqli : limite le nombre de SQLi (équilibrage, performances). None = tout charger.
    """
    p = Path(path) if path else SQLIV3_PATH
    if not p.is_file():
        return [], []

    texts: List[str] = []
    labels: List[int] = []
    seen: set = set()

    with open(p, "r", encoding=encoding, newline="", errors="replace") as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        # Colonnes possibles : Sentence, Label (ou sentence, label)
        for row in reader:
            text = (row.get("Sentence") or row.get("sentence") or "").strip()
            if not text or len(text) < min_length:
                continue
            if text in seen:
                continue
            seen.add(text)

            raw_label = row.get("Label") or row.get("label") or "1"
            try:
                label = 1 if int(float(str(raw_label).strip())) else 0
            except (ValueError, TypeError):
                label = 1

            texts.append(text)
            labels.append(label)

            if max_sqli and label == 1 and sum(1 for l in labels if l == 1) >= max_sqli:
                break

    return texts, labels


def get_labeled_data(
    use_csv: bool = True,
    max_sqli: Optional[int] = 15000,
    benign_ratio: float = 1.0,
) -> Tuple[List[str], List[int], List[str]]:
    """
    Retourne (texts, y_risk, y_types) pour l'entraînement.
    - use_csv : charger SQLiV3.csv en priorité
    - max_sqli : limite SQLi du CSV (None = tout)
    - benign_ratio : multiplicateur pour les bénins (1.0 = même nombre que SQLi si possible)
    """
    texts: list[str] = []
    y_risk: list[int] = []
    y_types: list[str] = []

    if use_csv and SQLIV3_PATH.is_file():
        csv_texts, csv_labels = load_sqliv3_csv(max_sqli=max_sqli)
        n_sqli = sum(1 for l in csv_labels if l == 1)
        for t, lbl in zip(csv_texts, csv_labels):
            texts.append(t)
            y_risk.append(lbl)
            y_types.append("SQL_INJECTION" if lbl == 1 else "NONE")

        # Équilibrage : ajouter des bénins (BENIGN_SAMPLES répétés pour atteindre ~n_sqli)
        n_benign_target = max(int(n_sqli * benign_ratio), len(BENIGN_SAMPLES))
        n_added = 0
        idx = 0
        while n_added < n_benign_target:
            b = BENIGN_SAMPLES[idx % len(BENIGN_SAMPLES)]
            texts.append(b)
            y_risk.append(0)
            y_types.append("NONE")
            n_added += 1
            idx += 1
    else:
        # Repli : listes Python
        for payload, threat_type in SQLI_SAMPLES:
            texts.append(payload)
            y_risk.append(1)
            y_types.append(threat_type)
        for text in BENIGN_SAMPLES:
            texts.append(text)
            y_risk.append(0)
            y_types.append("NONE")

    return texts, y_risk, y_types
