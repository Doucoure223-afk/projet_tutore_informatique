"""
Export des payloads bloqués depuis security_blocks.log pour enrichir le jeu de données ML.
Chaque ligne exportée est un payload confirmé comme SQLi (label=1).
Usage: python export_payloads_for_ml.py [chemin_vers_security_blocks.log]
        python export_payloads_for_ml.py   # utilise ../../src/var/logs/security_blocks.log par défaut
Sortie: collected_sqli.csv (payload,label) ou affichage pour copier dans dataset.py
"""
import os
import re
import sys
import csv

# Format log: [date] SECURITY_BLOCK - Type: ... | IP: ... | Payload: <payload> | Context: ...
PAYLOAD_RE = re.compile(r"\|\s*Payload:\s*(.+?)\s*\|\s*Context:", re.DOTALL)

def extract_payloads(log_path: str) -> list[str]:
    payloads = []
    seen = set()
    if not os.path.isfile(log_path):
        return payloads
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if "SECURITY_BLOCK" not in line or "Payload:" not in line:
                continue
            m = PAYLOAD_RE.search(line)
            if not m:
                continue
            payload = m.group(1).strip()
            if not payload or payload in seen:
                continue
            seen.add(payload)
            payloads.append(payload)
    return payloads


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log = os.path.normpath(os.path.join(script_dir, "..", "src", "var", "logs", "security_blocks.log"))
    log_path = sys.argv[1] if len(sys.argv) > 1 else default_log

    payloads = extract_payloads(log_path)
    if not payloads:
        print("Aucun payload trouvé dans", log_path)
        return 0

    out_csv = os.path.join(script_dir, "collected_sqli.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["payload", "label"])
        for p in payloads:
            w.writerow([p, 1])

    print(f"Exporté {len(payloads)} payload(s) vers {out_csv}")
    print("Pour réentraîner le modèle avec ces données, ajoutez-les à dataset.py (SQLI_SAMPLES) ou utilisez un script qui fusionne collected_sqli.csv avec le dataset avant train_model.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
