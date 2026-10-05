# Module IA Flask - Analyse SQL Injection (ML)

API d'analyse des menaces SQLi avec **modèle ML entraîné** (RandomForest), appelée par le **Middleware Sécurité (PHP)** selon l'architecture du projet.

## Prérequis

- Python 3.9+

## Installation

```bash
cd api-ia-flask
pip install -r requirements.txt
```

## Modèle ML (partie cruciale)

L'API utilise un **RandomForest** entraîné sur un jeu de données étiqueté (payloads SQLi vs entrées normales). Sans modèle, l'API retombe sur des règles heuristiques.

### Entraîner le modèle (recommandé)

```bash
python train_model.py
```

Cela génère `model.joblib`. Au démarrage, l'API charge ce fichier et utilise le ML pour le score de risque (`ml_used: true` dans la réponse).

### Fichiers ML

| Fichier        | Rôle |
|----------------|------|
| `dataset.py`   | Payloads SQLi et entrées bénignes étiquetés |
| `features.py`  | Extraction de features (partagée train + API) |
| `train_model.py` | Entraînement RandomForest, sauvegarde `model.joblib` |
| `model.joblib` | Modèle entraîné (créé par `train_model.py`) |

### Enrichir le modèle (ML plus significatif)

1. **Plus de données** : ajouter des exemples dans `dataset.py` (SQLI_SAMPLES, BENIGN_SAMPLES) ou charger un CSV externe (ex. listes de payloads SQLi publiques).
2. **Ré-entraîner** : `python train_model.py` après modification du dataset.
3. **Auto-apprentissage** : exporter les payloads déjà bloqués depuis les logs pour enrichir le dataset :
   ```bash
   python export_payloads_for_ml.py [chemin/vers/security_blocks.log]
   ```
   Génère `collected_sqli.csv` (payload, label=1). Vous pouvez ensuite ajouter ces lignes à `dataset.py` (SQLI_SAMPLES) ou les fusionner dans un pipeline avant d’exécuter `train_model.py`. Idéal en cron après une période de collecte.
4. **Option avancée** : remplacer RandomForest par XGBoost/LightGBM ou un petit réseau de neurones (LSTM/Transformer) pour une détection encore plus fine.

## Configuration MySQL (pour le chat)

Pour que l’assistant chat utilise les données du dashboard (incidents, WAF vs IA, 5 dernières attaques), il faut connecter Flask à la **même base MySQL** que le projet PHP.

1. **Créer un fichier `.env`** dans le dossier `api-ia-flask` à partir de l’exemple :
   ```bash
   cd api-ia-flask
   copy .env.example .env
   ```
   (sous Linux/macOS : `cp .env.example .env`)

2. **Modifier `.env`** avec tes identifiants MySQL (les mêmes que dans le `.env` à la racine du projet PHP) :
   ```
   MYSQL_HOST=127.0.0.1
   MYSQL_PORT=3306
   MYSQL_USER=root
   MYSQL_PASSWORD=ta_mot_de_passe
   MYSQL_DATABASE=mon_projet_securite
   ```

3. Au lancement, Flask charge ce `.env` automatiquement. Si la connexion échoue, le chat répond tout de même mais sans les stats d’incidents (métriques du modèle uniquement).

## Lancement

```bash
python app.py
```

L'API écoute sur `http://127.0.0.1:5000`.

## Endpoints

### `POST /analyze`

Corps JSON attendu :

```json
{
  "input": "valeur utilisateur à analyser",
  "context": {
    "type": "login",
    "parameter": "username",
    "ip": "192.168.1.1",
    "user_agent": "..."
  },
  "session_id": null
}
```

Réponse (200) :

```json
{
  "risk": 0.92,
  "confidence": 0.85,
  "type": "UNION_SQLi",
  "model_version": "2026.2.0-ml",
  "processing_time_ms": 12.5,
  "ml_used": true
}
```

`ml_used: true` indique que le modèle entraîné a été utilisé ; sinon l'API utilise les règles de secours.

### `GET /health`

Contrôle de disponibilité : `{"status": "ok", "model_version": "...", "ml_loaded": true/false}`.

### `POST /chat` (assistant dashboard)

Logique **intelligence** du chat admin : réponses à partir des données du dashboard (blocages, WAF vs IA, métriques, recommandations, 5 dernières attaques). Le PHP appelle cet endpoint en priorité ; en cas d'indisponibilité, le repli se fait côté PHP. Corps : `{"message": "...", "history": [{"role","content"}]}` (history optionnel pour le LLM). Réponse : `{"ok": true, "reply": "..."}`. Pour les données en base : `MYSQL_*` ou `DB_*`. **LLM optionnel** (questions libres) : `ENABLE_LLM_CHAT=1` puis `OPENAI_API_KEY` ou `OLLAMA_URL` (voir .env.example). Les messages sont persistés par admin côté PHP (`chat_messages`).

## Tester l’impact du ML

- **Script** : `python test_ml_impact.py` (l’API doit tourner sur le port 5000). Affiche risk, confidence et `ml_used` pour plusieurs entrées.
- **Guide détaillé** : voir [TEST_IMPACT_ML.md](TEST_IMPACT_ML.md) (comparaison avec/sans modèle, test via la page de login, vérification dans les logs).

## Intégration

Le middleware PHP envoie les requêtes nécessitant une analyse IA (`needsAiAnalysis`) vers cette API. En cas d'indisponibilité ou de timeout, le moteur PHP (ThreatIntelligenceEngine) est utilisé en secours.
