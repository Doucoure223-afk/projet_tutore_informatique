# Arborescence technique du projet – Structure des dossiers PHP et Python

## Vue d’ensemble

```
mon-projet-security/
├── api-ia-flask/                    # Module Python (API IA / ML)
├── config/                          # Configuration PHP
├── database/                        # Schéma et migrations SQL
├── dataset/                         # Jeux de données SQLi (CSV)
├── docs/                            # Documentation
├── public/                          # Point d’entrée web (PHP)
├── scripts/                         # Scripts utilitaires
├── src/                             # Code source PHP (namespace App)
├── templates/                       # Templates (si utilisés)
├── tests/                           # Tests unitaires PHP
├── var/                             # Logs, cache, sessions
├── .env.example
├── composer.json
├── phpunit.xml.dist
└── README.md
```

---

## 1. Partie PHP – Structure détaillée

```
mon-projet-security/
│
├── config/
│   ├── config.php                   # Configuration applicative (DB, AI, reCAPTCHA)
│   └── config.example.php           # Exemple de configuration
│
├── database/
│   ├── schema.sql                   # Schéma complet de la base (tables, vues, procédures)
│   └── migrations/
│       ├── 2026_fix_security_incidents_columns.sql
│       ├── 2026_create_ip_access_rules.sql
│       ├── 2026_create_ip_geo_cache.sql
│       ├── 2026_create_products_table.sql
│       ├── 2026_create_chat_messages.sql
│       ├── 2026_add_ai_insights_columns.sql
│       └── 2026_add_missing_users_columns.sql
│
├── public/                          # Racine web (document root)
│   ├── index.php                    # Point d’entrée principal
│   ├── login.php                    # Connexion + middleware sécurité
│   ├── inscription.php              # Inscription utilisateur
│   ├── dashboard.php                # Tableau de bord sécurité
│   ├── dashboard-api.php            # API AJAX (stats, chat)
│   ├── admin-ip-rules.php           # Gestion liste noire / blanche IP
│   ├── search.php                   # Recherche sécurisée
│   ├── export-incidents.php         # Export CSV des incidents
│   ├── rapport.php                  # Rapport PDF imprimable
│   ├── a-propos.php
│   ├── terms.php
│   ├── politique-confidentialite.php
│   └── assets/
│       ├── chartjs/
│       │   └── datalabels.min.js
│       └── css/
│
├── scripts/
│   └── purge-retention.php          # Purge incidents + logs (rétention configurable)
│
├── src/
│   └── App/
│       ├── config/
│       │   └── database.php         # Configuration BDD
│       ├── Infrastructure/
│       │   ├── ApplicationConfig.php  # Chargement config + DB + logger
│       │   ├── config.php
│       │   └── Database/
│       │       ├── ConnectionPool.php
│       │       └── DatabaseFactory.php
│       └── Security/
│           ├── Detector/
│           │   └── SqlInjectionDetector.php   # Détection + scoring SQLi
│           ├── Dashboard/
│           │   └── SecurityDashboard.php      # Agrégation stats dashboard
│           ├── AI/
│           │   ├── FlaskAiClient.php         # Client HTTP vers API Flask
│           │   └── ThreatIntelligenceEngine.php  # Fallback analyse PHP
│           ├── Logger/
│           │   ├── SecurityLogger.php
│           │   └── SecurityLoggerInterface.php
│           ├── Response/
│           │   └── SecurityResponseFactory.php  # Réponses 403, CAPTCHA
│           ├── IpAccessControl.php           # Liste noire / blanche
│           ├── IpGeolocation.php              # Géolocalisation IP
│           ├── RateLimiter.php                # Limitation tentatives login
│           ├── IncidentRetention.php          # Rétention / purge
│           ├── SecureDataGateway.php          # Requêtes préparées + filtrage
│           └── response_handler.php
│
├── tests/
│   └── Unit/
│       └── Security/
│           └── Detector/
│               └── SqlInjectionDetectorTest.php
│
├── var/                             # Données volatiles (hors versioning)
│   ├── log/                         # Logs applicatifs (security, access, errors, ai_analysis)
│   ├── logs/
│   ├── cache/
│   └── sessions/
│
├── vendor/                          # Dépendances Composer (autoload PSR-4)
├── .env.example
├── composer.json                    # Dépendances PHP, scripts (test, analyze, purge-retention)
└── phpunit.xml.dist                 # Configuration PHPUnit
```

---

## 2. Partie Python – Structure détaillée (api-ia-flask)

```
mon-projet-security/api-ia-flask/
│
├── app.py                           # Application Flask – routes /analyze, /chat, /health, /metrics
├── features.py                      # Extraction des 11 features ML (partagé train + API)
├── dataset.py                       # Chargement SQLiV3.csv + BENIGN_SAMPLES / SQLI_SAMPLES
├── train_model.py                   # Entraînement MLP (StandardScaler + MLPClassifier)
├── chat_assistant.py                # Logique assistant chat + LLM (Gemini, Groq, OpenAI)
├── export_payloads_for_ml.py         # Export payloads bloqués → CSV pour enrichir le dataset
│
├── model.joblib                     # Modèle entraîné (généré par train_model.py)
├── metrics.json                     # Métriques 5-fold CV (precision, recall, f1, accuracy)
│
├── requirements.txt                 # Dépendances Python (flask, scikit-learn, joblib, etc.)
├── .env                             # Config (MYSQL_*, GEMINI_API_KEY, GROQ_API_KEY, etc.)
├── .env.example
├── README.md
├── TEST_IMPACT_ML.md
│
├── test_dataset_load.py             # Tests chargement dataset
├── test_ml_impact.py                # Test impact ML (avec/sans modèle)
├── test_mlp_api.py                  # Tests API MLP
├── train.bat                        # Script Windows pour lancer l’entraînement
│
└── __pycache__/                     # Cache bytecode Python (ignoré en prod)
```

---

## 3. Données et assets partagés

```
mon-projet-security/
├── dataset/                         # Jeux de données (à la racine, utilisés par api-ia-flask)
│   ├── SQLiV3.csv                   # Dataset principal (Sentence, Label)
│   ├── sqliv2.csv
│   └── sqli.csv
│
├── docs/                            # Documentation projet
└── templates/                       # Templates PHP (si présents)
```

---

## 4. Récapitulatif par rôle

| Dossier / fichier        | Rôle |
|---------------------------|------|
| **config/**               | Configuration centralisée PHP |
| **database/**             | Schéma MySQL et migrations |
| **public/**               | Point d’entrée web ; pages et API AJAX |
| **src/App/Security/**     | Cœur métier : détection, IA, gateway, rate limit, IP, logs |
| **src/App/Infrastructure/**| Config, DB, factory |
| **api-ia-flask/**         | API Python : analyse ML, chat, métriques |
| **scripts/**              | Maintenance (purge rétention) |
| **tests/**                | Tests unitaires (SqlInjectionDetector) |
| **var/**                  | Logs, cache, sessions |

---

## 5. Fichiers de configuration principaux

| Fichier              | Rôle |
|----------------------|------|
| `.env` (racine)      | Variables d’environnement PHP (DB_*, AI, etc.) |
| `config/config.php`  | Configuration applicative (app, database, ai.flask_url, recaptcha) |
| `composer.json`      | Dépendances PHP, autoload `App\` → `src/App`, scripts |
| `api-ia-flask/.env`  | MYSQL_*, GEMINI_API_KEY, GROQ_API_KEY, ENABLE_LLM_CHAT |
| `api-ia-flask/requirements.txt` | Dépendances Python (Flask, scikit-learn, joblib, pymysql, etc.) |

Cette arborescence peut être reprise telle quelle dans le mémoire (annexe « Structure technique du projet »).
