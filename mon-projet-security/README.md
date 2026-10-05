# Système de sécurité SQL Injection 2026

Protection automatique des applications web contre les injections SQL : détection, scoring, blocage et tableau de bord de surveillance.

## Fonctionnalités

- **Détection SQL Injection** : patterns OWASP, analyse statistique, entropie, contexte (login, search, api, admin).
- **Scoring et risque** : score ajusté par contexte, niveaux NONE / LOW / MEDIUM / HIGH / CRITICAL.
- **Réponse sécurisée** : blocage, enregistrement des incidents en base, logs.
- **Dashboard** : statistiques, graphiques (24 h / 7 j / 30 j), dernières attaques, Top pays (géolocalisation), export CSV, rapport PDF, rafraîchissement AJAX.
- **Rate limiting** : limitation des tentatives de connexion par IP.
- **Liste noire / blanche d’IP** : blocage ou restriction d’accès par adresse IP.
- **Géolocalisation** : cache des IP (ip-api.com), affichage lieu dans les incidents et Top pays.
- **Thème clair / sombre** et mise en page responsive (mobile, tablette).
- **Logs structurés** : une ligne = un objet JSON (JSON Lines), pour intégration ELK/Splunk.
- **Rétention** : purge configurable des incidents et des fichiers de log (script + cron).
- **CAPTCHA (page 403)** : reCAPTCHA v2 (case « Je ne suis pas un robot ») sur la page de blocage pour afficher le lien « Retour à la connexion » (optionnel, voir configuration).
- **IA / ML** : module Flask avec **modèle RandomForest entraîné** pour le score de risque SQLi ; fallback sur règles si le modèle n’est pas chargé. Voir ci‑dessous « Partie IA / ML ».

## Prérequis

- PHP 8.2+
- Extensions : `pdo`, `json`, `mbstring`, `openssl`
- MySQL / MariaDB
- Composer

## Installation

```bash
git clone <repo> mon-projet-security
cd mon-projet-security
composer install
cp .env.example .env
```

Configurer `.env` (base de données, etc.). Créer la base et exécuter les migrations dans `database/migrations/` :

- `2026_fix_security_incidents_columns.sql`
- `2026_create_ip_access_rules.sql`
- `2026_create_ip_geo_cache.sql`
- etc.

Documenter le schéma complet dans `database/schema.sql` si besoin.

## Structure du projet

```
mon-projet-security/
├── public/           # Point d’entrée web
│   ├── login.php
│   ├── dashboard.php
│   ├── admin-ip-rules.php
│   ├── export-incidents.php
│   ├── rapport.php
│   └── a-propos.php
├── src/App/
│   ├── Security/
│   │   ├── Detector/SqlInjectionDetector.php
│   │   ├── Dashboard/SecurityDashboard.php
│   │   ├── IpAccessControl.php
│   │   ├── IpGeolocation.php
│   │   ├── RateLimiter.php
│   │   ├── IncidentRetention.php
│   │   ├── SecureDataGateway.php   # Requête sécurisée → DB → filtrage → données nettoyées
│   │   └── Response/SecurityResponseFactory.php
│   └── Infrastructure/
├── database/migrations/
├── scripts/
│   └── purge-retention.php
├── tests/Unit/Security/Detector/
└── composer.json
```

**Partie IA / ML** : entraîner le modèle avec `cd api-ia-flask && python train_model.py` ; lancer l'API avec `python app.py`. Si `model.joblib` est présent, les réponses ont `ml_used: true`. Enrichir `dataset.py` et ré-entraîner pour un ML plus performant. Voir `api-ia-flask/README.md`.

## Concordance avec l’architecture et le diagramme de séquence

Le projet suit le flux du diagramme à **100 %** : Requête → Middleware → (optionnel) API IA → Blocage ou passage → **Requête sécurisée → DB → Filtrage → Données nettoyées → App**.

| Élément diagramme | Implémentation | Statut |
|-------------------|----------------|--------|
| Requête HTTP → Application PHP | `login.php` reçoit GET/POST | ✅ |
| Interception + extraction entrées | `processSecurityMiddleware()` analyse `$_GET`/`$_POST` | ✅ |
| Pattern matching (score > 80) | `SqlInjectionDetector` → `shouldBlock` si score ≥ 80 | ✅ |
| Log attaque (fichier + DB) | `logSqlInjection()` + INSERT `security_incidents` | ✅ |
| Réponse 403 + CAPTCHA | `SecurityResponseFactory::createBlockedResponse()` + reCAPTCHA v2 | ✅ |
| Analyse IA → POST /analyze | `needsAiAnalysis` → `FlaskAiClient::analyze()` | ✅ |
| API Flask (features, risk/confidence/type) | `api-ia-flask` : extraction, **modèle ML** (RandomForest) ou règles, type (ex. UNION_SQLI) | ✅ |
| Fallback si API indisponible | `ThreatIntelligenceEngine::analyzeThreat()` | ✅ |
| Risque élevé (>0.7) → blocage + page | `riskScore > 0.75` → blocage, log, page 403 | ✅ |
| Risque faible → Requête sécurisée préparée → MySQL | `SecureDataGateway` envoie la requête préparée à la base | ✅ |
| Résultats → Middleware | Le gateway reçoit les résultats de la DB | ✅ |
| Filtrage données sensibles | `SecureDataGateway::filterSensitiveData()` (aucun `password_hash` retourné) | ✅ |
| Données nettoyées → Application | L’app reçoit uniquement `id`, `username`, `email`, `role` via `authenticateAndGetUser()` | ✅ |

L’application ne dialogue plus avec la base pour le flux login : tout passe par **SecureDataGateway** (couche sécurité), conformément à l’architecture et au diagramme de séquence.

## Utilisation

1. **Connexion** : `public/login.php` (rate limiting et liste noire/blanche appliqués).
2. **Dashboard** : après connexion, accès à `public/dashboard.php` (période 24 h, 7 j, 30 j).
3. **Règles IP** : `public/admin-ip-rules.php` pour gérer liste noire et liste blanche.
4. **Export** : bouton « Exporter CSV » sur le dashboard (période courante).
5. **Rapport** : « Rapport PDF » pour une vue imprimable / enregistrement en PDF.

## Tests

```bash
composer test
# ou
vendor/bin/phpunit tests/Unit
```

Les tests unitaires couvrent le `SqlInjectionDetector` (scoring, contexte, niveaux de risque, blocage).

## Logs structurés

Les logs de sécurité sont écrits au format **JSON Lines** (une ligne = un objet JSON) avec `@timestamp`, `level`, `message`, `request_id` et le contexte. Cela permet une ingestion directe par des outils type ELK, Splunk ou Datadog.

## CAPTCHA (page de blocage 403)

La page « Requête bloquée » utilise **reCAPTCHA v2** (case « Je ne suis pas un robot »). Après validation du CAPTCHA, le lien « Retour à la connexion » s’affiche.

Configurer les clés dans `config/config.php` :

```php
'recaptcha' => [
    'site_key' => 'votre_clé_site',
    'secret_key' => 'votre_clé_secrète',
],
```

Créer un site **reCAPTCHA v2** (option « Case à cocher Je ne suis pas un robot ») sur [Google reCAPTCHA Admin](https://www.google.com/recaptcha/admin) et ajouter les domaines (ex. localhost, 127.0.0.1). Si `site_key` est vide, la page 403 s’affiche sans CAPTCHA (boutons Retour et Accueil restants).

## Rétention (purge)

Pour limiter la croissance des données, un script supprime les incidents et les fichiers de log plus anciens que la période configurée (par défaut **90 jours**).

```bash
# Purge avec rétention par défaut (90 jours)
composer purge-retention

# Ou avec un nombre de jours personnalisé
php scripts/purge-retention.php 30
```

À planifier en cron (ex. chaque dimanche à 3 h) :

```cron
0 3 * * 0 cd /chemin/vers/mon-projet-security && php scripts/purge-retention.php
```

## Standards et bonnes pratiques (OWASP / Zero-Trust)

- **OWASP Top 10** : le projet adresse notamment **A03:2021 – Injection** (détection et blocage SQLi, requêtes préparées via SecureDataGateway), **A07:2021 – Authentification défaillante** (rate limiting, CSRF, mots de passe non exposés), et **A05:2021 – Sécurité mal configurée** (en-têtes de sécurité, CSP, logs).
- **Zero-Trust** : aucune confiance a priori dans les entrées utilisateur ; chaque requête est analysée (middleware), les identifiants sont validés et assainis, et l’accès aux données passe par un **proxy sécurisé** (SecureDataGateway) qui ne retourne jamais de données sensibles (ex. `password_hash`). Les incidents sont tracés (logs + base) pour un audit continu.

## Licence

MIT.
