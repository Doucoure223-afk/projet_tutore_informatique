# Rapport technique – Mémoire d’ingénierie  
## « Protection automatique des applications web contre les attaques par injection SQL »

Ce document est une synthèse technique exhaustive du projet, destinée à alimenter la rédaction du mémoire et à garantir la cohérence avec l’implémentation réelle.

---

# 1️⃣ Présentation générale du projet

## Nom du projet
- **Nom technique :** Mon Projet Sécurité / Système de sécurité SQL Injection avec IA – Standard 2026  
- **Référence interne :** `entreprise/security-system-2026` (composer), « SHIELD CORE 2026 » (interface utilisateur)

## Objectif principal
Protéger automatiquement les applications web contre les attaques par injection SQL en combinant :
1. **Détection par règles (WAF)** : signatures, patterns regex, score de risque et contexte (login, search, admin, etc.).
2. **Module IA** : analyse en zone grise (score 30–80) via une API Flask (MLP entraîné ou fallback heuristique) pour réduire les faux positifs et améliorer la précision.
3. **Réponse coordonnée** : blocage, logging structuré, enregistrement en base, géolocalisation, rate limiting, listes d’IP.

## Problématique adressée
- **Sécurisation des entrées utilisateur** (formulaires login, recherche, inscription) sans modifier le cœur métier de l’application.
- **Réduction des faux positifs** sur des chaînes ambiguës (ex. recherche contenant des mots-clés SQL) grâce à une zone grise traitée par l’IA.
- **Traçabilité et gouvernance** : incidents en base, rapports, tableau de bord, exports CSV, rétention configurable.

## Type d’architecture
- **WAF intégré (middleware applicatif)** : la protection n’est pas un reverse proxy externe ; elle est intégrée au début du traitement de chaque requête (point d’entrée PHP : `login.php`, `search.php`, etc.).  
- **Architecture hybride** : application PHP monolithique + service IA externe (API Flask) appelé en HTTP pour l’analyse en zone grise. En cas d’indisponibilité de l’API, un moteur PHP (ThreatIntelligenceEngine) assure le fallback.

## Type d’application protégée
- **Application web classique (MVC / scripts PHP)** : pages de login, inscription, recherche, dashboard, rapports.  
- **Flux protégés** : paramètres GET/POST analysés avant tout traitement métier ; pas de couche REST API générique unique — chaque point d’entrée (login, search, etc.) inclut le même middleware de sécurité.  
- **Pas de SPA** : le frontend est du HTML/CSS/JS classique (formulaires, Shoelace, thème clair/sombre).

## Environnement cible
- **Développement / déploiement local** : stack WAMP (Windows, Apache, MySQL/MariaDB, PHP).  
- **Hébergement** : non conteneurisé dans le dépôt (pas de Dockerfile, pas de docker-compose). Déploiement typique sur **VPS ou hébergement mutualisé** avec PHP 8.2+, MySQL, et possibilité de lancer le service Flask en local ou sur un autre port.  
- **Cloud / Kubernetes** : non prévu par défaut ; l’architecture (config par fichier, URL Flask en config) reste compatible avec un déploiement cloud si l’on configure les variables d’environnement et l’URL de l’API IA.

---

# 2️⃣ Stack technologique complète

## Backend
- **Langage :** PHP 8.2+ (strict_types, typage natif).  
- **Framework :** Aucun framework MVC complet ; utilisation de **Slim PSR-7** (ServerRequestFactory) et **PSR-4** pour l’autoload. Le projet est structuré en namespaces (`App\Security`, `App\Infrastructure`) sans framework applicatif type Laravel/Symfony.  
- **Librairies sécurité / utilitaires :**  
  - **Monolog** (PSR-3) pour les logs.  
  - **Ramsey UUID** pour l’identifiant unique des incidents.  
  - **PHP dotenv** (vlucas/phpdotenv) pour la configuration (optionnel).  
  - Pas de librairie dédiée « WAF » : le détecteur et le moteur IA sont développés en interne.  
- **ORM :** Aucun ORM ; accès base **PDO** uniquement (requêtes préparées partout : `SecureDataGateway`, `RateLimiter`, `SecurityResponseFactory`, etc.).

## Frontend
- **Framework :** Aucun framework JS (React/Vue/Angular).  
- **Librairies UI :**  
  - **Shoelace** (v2, thème dark) pour certains composants sur la page de login.  
  - **Font Awesome** pour les icônes.  
  - Polices Google (Space Grotesk, JetBrains Mono) pour la page de blocage et le dashboard.  
- **Comportement :** JavaScript vanilla (validation formulaire, thème clair/sombre, copie ID incident, reCAPTCHA callback).

## Base de données
- **SGBD :** MySQL ou MariaDB (utf8mb4, InnoDB).  
- **Structure générale :**  
  - **users** : comptes (username, email, password_hash, role, login_attempts, locked_until, mfa_enabled, tokens de vérification, etc.).  
  - **user_profiles** : profil lié à l’utilisateur (1–1).  
  - **security_incidents** : chaque incident (uuid, type, ip_address, payload_hash, payload_preview, risk_score, ai_confidence, ai_risk_factors, detection_method, threat_level, action_taken, blocked, country_code, threat_type, endpoint, created_at, etc.).  
  - **ai_analysis_logs** : logs des analyses IA (request_id, analyzed_at, ai_verdict, human_verdict, processing_time_ms, risk_score, context).  
  - **rate_limits** : fenêtre de rate limiting par (key_hash, endpoint) (count, window_start).  
  - **ip_geo_cache** : cache de géolocalisation (ip_address, country_code, country_name, region, city, updated_at).  
  - **ip_access_rules** : liste noire / blanche d’IP (ip_address, rule_type enum blacklist/whitelist, comment).  
  - **Vues :** `daily_security_report`, `threat_intelligence`.  
  - **Procédures stockées :** `cleanup_old_incidents(retention_days)`, `get_user_security_stats(p_user_id)`.

## Infrastructure
- **Reverse proxy :** Non imposé par le projet ; en production, Apache (ou Nginx) peut être placé en frontal.  
- **Docker :** Aucun Dockerfile ni docker-compose dans le dépôt.  
- **CI/CD :** Aucun pipeline dédié dans le dépôt (seuls des fichiers dans vendor font référence à des workflows).  
- **Hébergement :** Local (WAMP) ou VPS ; configuration via `config/config.php` et variables d’environnement (DB_*, RECAPTCHA, etc.).

---

# 3️⃣ Architecture détaillée

## Modules et couches

1. **Point d’entrée (couche présentation)**  
   - `public/login.php`, `public/search.php`, `public/inscription.php`, etc.  
   - Responsabilités : démarrer la session, charger l’autoload et la config, instancier les services (détecteur, rate limiter, IP access control, Flask client, ThreatIntelligenceEngine, SecureDataGateway), puis exécuter le **middleware de sécurité** sur `$_GET` et `$_POST` avant tout traitement métier.

2. **Middleware de sécurité (logique de décision)**  
   - Implémenté dans des fonctions dédiées dans chaque script (ex. `processSecurityMiddleware()` dans `login.php`).  
   - Pour chaque paramètre de requête (chaîne) :  
     - Appel à `SqlInjectionDetector::analyze($value, $param, $context)`.  
     - Si `shouldBlock` → log + retour « bloquer » avec type d’attaque et contexte.  
     - Si `needsAiAnalysis` (score entre 30 et 80) → appel à `FlaskAiClient::analyze()` ; si l’API est indisponible, appel à `ThreatIntelligenceEngine::analyzeThreat()`.  
     - Si le risque IA > 0.75 → blocage avec type `AI_DETECTED_THREAT`.  
   - Aucune requête métier (DB, affichage) n’est exécutée tant que le middleware n’a pas autorisé la requête.

3. **Détecteur SQL (règles)**  
   - `App\Security\Detector\SqlInjectionDetector`.  
   - Normalisation de l’entrée (urldecode multi-niveaux, espaces, lowercase), calcul de score (patterns regex + statistiques + longueur + entropie de Shannon), application d’un poids de contexte (login, search, admin, api, etc.), décision `shouldBlock` (score ≥ 80), `needsAiAnalysis` (30 ≤ score < 80).

4. **Client API IA**  
   - `App\Security\AI\FlaskAiClient`.  
   - POST vers `{baseUrl}/analyze` avec `input`, `context`, `session_id` ; timeout 2 s.  
   - Retour attendu : `risk`, `confidence`, `type`, optionnellement `risk_factors`.  
   - Health check : GET `{baseUrl}/health`.

5. **Moteur d’intelligence des menaces (fallback PHP)**  
   - `App\Security\AI\ThreatIntelligenceEngine`.  
   - Analyse locale : normalisation, extraction de features (longueur, mots-clés SQL, entropie, patterns union/tautology/time-based/comment, etc.), patterns avec scores, contexte, fusion risque contextuel/comportemental, classification de la menace, seuil 0.75 pour bloquer.

6. **Réponse et logging**  
   - `App\Security\Response\SecurityResponseFactory` : en cas de blocage, envoi 403, en-têtes de sécurité (CSP, X-Frame-Options, etc.), log fichier (`var/logs/security_blocks.log`), insertion en base dans `security_incidents` (avec géolocalisation si disponible), rendu de la page HTML de blocage (SHIELD CORE 2026, reCAPTCHA optionnel, ID incident copiable).

7. **Gestion des incidents et persistance**  
   - Enregistrement dans `security_incidents` (uuid, type, ip, payload_hash, payload_preview, risk_score, ai_confidence, ai_risk_factors, detection_method, threat_level, country_code, endpoint, etc.).  
   - Géolocalisation : `App\Security\IpGeolocation` (API ip-api.com, cache en base `ip_geo_cache`).  
   - Rétention : `App\Security\IncidentRetention` (purge incidents + fichiers de log par âge) ; script `scripts/purge-retention.php` et procédure `cleanup_old_incidents`.

8. **Contrôle d’accès et rate limiting**  
   - `App\Security\IpAccessControl` : liste noire / blanche (table `ip_access_rules`). Si whitelist non vide, seules les IP whitelistées sont autorisées.  
   - `App\Security\RateLimiter` : par (key_hash, endpoint), fenêtre et nombre max de tentatives (ex. login : 15 min, 5 tentatives).  
   - Vérification IP et rate limit avant le middleware SQLi sur les pages concernées (ex. login).

9. **Authentification et données utilisateur**  
   - `App\Security\SecureDataGateway` : authentification via requêtes préparées, filtrage des données sensibles (pas de password_hash retourné), gestion des tentatives échouées et verrouillage.

10. **Tableau de bord**  
    - `App\Security\Dashboard\SecurityDashboard` : statistiques temps réel, dernières attaques, carte des menaces (pays), graphiques d’activité, export CSV, rafraîchissement AJAX.  
    - Consommation des tables `security_incidents`, vues, et éventuellement logs.

11. **Configuration et infrastructure applicative**  
    - `App\Infrastructure\ApplicationConfig` : chargement de `config/config.php`, connexion PDO singleton, loggers (Monolog + SecurityLogger pour le canal security), génération/vérification de jetons CSRF.

## Flux complet d’une requête HTTP (ex. POST login)

1. Requête HTTP reçue par le serveur web → `public/login.php`.  
2. Session démarrée, autoload et `ApplicationConfig::initialize()`.  
3. Instanciation des services (DB, RateLimiter, IpAccessControl, SqlInjectionDetector, ThreatIntelligenceEngine, FlaskAiClient, SecureDataGateway).  
4. Vérification maintenance (`ApplicationConfig::get('maintenance')`).  
5. **Contrôle IP** : `IpAccessControl::isBlocked($clientIp)` → si bloqué, affichage message et exit.  
6. **Middleware de sécurité** :  
   - Pour chaque entrée dans `$_GET` et `$_POST` :  
     - `SqlInjectionDetector::analyze($value, $param, 'login')`.  
     - Si `shouldBlock` → SecurityLogger::logSqlInjection, retour `SecurityMiddlewareResult(shouldBlock: true, threatInfo)` → `SecurityResponseFactory::createBlockedResponse()` → 403 + log fichier + INSERT `security_incidents` + page de blocage → exit.  
     - Si `needsAiAnalysis` → appel `FlaskAiClient::analyze()` (ou ThreatIntelligenceEngine en fallback) ; si risk > 0.75 → même blocage avec type AI_DETECTED_THREAT.  
7. Si pas de blocage : traitement du formulaire (CSRF, validation, `SecureDataGateway::authenticateAndGetUser()`).  
8. Rate limiting : avant authentification, `RateLimiter::isAllowed()` pour l’IP sur l’endpoint `login` ; en cas d’échec de login, `recordAttempt()`.  
9. Réponse : redirection vers dashboard ou affichage du formulaire avec erreur.

## Point exact où l’analyse SQLi est effectuée
- **Première analyse (règles)** : à l’intérieur de `processSecurityMiddleware()`, pour chaque paire (paramètre, valeur), immédiatement après la réception de la requête et avant toute utilisation des données en base ou en logique métier.  
- **Deuxième analyse (IA)** : uniquement si le score du détecteur est dans [30, 80[, soit dans la même boucle du middleware, juste après l’appel au détecteur et avant de passer au paramètre suivant ou de considérer la requête comme sûre.

## Dépendances entre modules
- **ApplicationConfig** : utilisé par SecurityResponseFactory (DB, config recaptcha), login (DB, logger, config), SecureDataGateway (DB fournie par config).  
- **SqlInjectionDetector** : indépendant (optionnellement un LoggerInterface).  
- **FlaskAiClient** : dépend de l’URL configurée (ai.flask_url) et du logger.  
- **ThreatIntelligenceEngine** : autonome (pas de DB).  
- **SecurityResponseFactory** : utilise ApplicationConfig::getDatabase(), IpGeolocation, Ramsey Uuid ; écrit dans var/logs et dans security_incidents.  
- **RateLimiter, IpAccessControl, IpGeolocation** : dépendent de PDO.  
- **SecurityDashboard** : dépend de SecurityLogger et PDO (ou ConnectionPool).  
- **IncidentRetention** : PDO + répertoire des logs.

## Description textuelle équivalente à un diagramme de composants
- **Composant « Point d’entrée »** : scripts PHP publics (login, search, inscription, dashboard). Ils utilisent le **Composant « Middleware de sécurité »** (logique dans le script).  
- **Composant « Détecteur SQL »** : reçoit (entrée, paramètre, contexte), retourne (score, shouldBlock, needsAiAnalysis, patterns, riskLevel).  
- **Composant « Client API IA »** : appelle le service Flask /analyze ; retourne risk, confidence, type, risk_factors ou null.  
- **Composant « Moteur IA (fallback) »** : ThreatIntelligenceEngine, même interface sémantique (analyse → risque, confiance, type).  
- **Composant « Réponse / Logging »** : SecurityResponseFactory crée la réponse 403, écrit les logs, insère les incidents, utilise IpGeolocation.  
- **Composant « Contrôle d’accès »** : IpAccessControl (règles IP), RateLimiter (fenêtre par endpoint).  
- **Composant « Données »** : PDO (MySQL), SecureDataGateway pour l’authentification.  
- **Composant « Tableau de bord »** : SecurityDashboard lit security_incidents et vues, produit HTML et CSV.  
- **Service externe** : API Flask (analyse + health) ; API ip-api.com (géolocalisation).

## Description textuelle équivalente à un diagramme de séquence (requête avec blocage WAF)
- **Acteur** : Utilisateur (navigateur).  
- **Système** : Serveur web → login.php.  
1. Requête POST (username, password, _token).  
2. login.php : init config, DB, détecteur, IP access, rate limiter.  
3. IpAccessControl::isBlocked(IP) → non.  
4. processSecurityMiddleware : pour paramètre "username", valeur "' OR 1=1--".  
5. SqlInjectionDetector::analyze("' OR 1=1--", "username", "login").  
6. Détecteur : normalisation, calcul score (patterns + heuristiques), contexte login (×1.3), score ≥ 80 → shouldBlock=true.  
7. Middleware : SecurityLogger::logSqlInjection(...).  
8. Retour SecurityMiddlewareResult(shouldBlock: true, threatInfo).  
9. login.php : SecurityResponseFactory::createBlockedResponse("SQL_INJECTION", payload, context).  
10. createBlockedResponse : http_response_code(403), logIncident (fichier + INSERT security_incidents + géo si dispo), renderBlockedPage(), exit.  
11. Réponse HTTP 403 + page HTML « Requête bloquée » au client.

## Description textuelle équivalente à un diagramme de déploiement
- **Nœud « Machine développeur / serveur »** :  
  - **Serveur web** (Apache) : document root vers `public/`, exécution PHP.  
  - **Processus PHP** : exécution des scripts (login.php, search.php, dashboard.php, etc.) ; accès au système de fichiers (config, var/logs).  
  - **Processus Python** (optionnel) : serveur Flask (api-ia-flask) écoutant sur 127.0.0.1:5000 ; charge model.joblib et metrics.json.  
- **Nœud « Base de données »** : MySQL/MariaDB (localhost ou distant), base `mon_projet_securite`, tables décrites plus haut.  
- **Communication** : PHP → MySQL (PDO), PHP → Flask (HTTP POST/GET), PHP → ip-api.com (HTTP GET pour géolocalisation).  
- **Artifacts** : code source (src/App, public, config), modèle ML (api-ia-flask/model.joblib), schéma SQL (database/schema.sql, migrations).

---

# 4️⃣ Mécanisme de détection SQL Injection

## Méthode basée sur règles (regex, parsing, signatures)
- **Signatures regex** : une quinzaine de patterns dans `SqlInjectionDetector::PATTERNS`, chacun associé à un score (60 à 120). Exemples :  
  - `' OR '1'='1`, `' OR 1=1`, `' UNION SELECT`, `' UNION ALL SELECT`, `' AND/OR '1'='1` (100) ;  
  - `'; DROP/ DELETE/ TRUNCATE`, `' OR SLEEP(`, `BENCHMARK(`, `WAITFOR DELAY` (120) ;  
  - commentaires `'?--`, `#`, `/* */` (80) ;  
  - blind `' AND/OR \d+=\d+` (90) ;  
  - mots-clés SQL (SELECT/INSERT/… FROM/INTO/TABLE), DATABASE()/VERSION() (60).  
- **Pas de parsing SQL** : pas d’arbre syntaxique ; uniquement des regex et des comptages (caractères spéciaux, longueur, entropie).  
- **Score composite** : somme des scores des patterns déclenchés + bonus statistiques (caractères spéciaux × 10 si > 2), longueur (> 100 +20, > 250 +30), entropie de Shannon (> 4.5 +25), plafonné à 150.  
- **Contexte** : poids multiplicatif par type de page (login 1.3, registration 1.2, search 1.1, admin 1.5, api 1.4, default 1.0). Le score final (ajusté) détermine shouldBlock (≥ 80) et needsAiAnalysis ([30, 80[).

## Analyse comportementale
- **Côté PHP (ThreatIntelligenceEngine)** : facteurs simulés ou simples (heure 0–5h, longueur selon contexte, densité de mots-clés) pour un bonus de risque comportemental, fusionné à 70% risque contextuel + 30% comportemental.  
- **Côté application** : rate limiting (nombre de tentatives login/inscription) et verrouillage de compte après échecs ; pas d’analyse de séquence de requêtes pour la décision SQLi elle-même.

## Machine Learning
- **Côté API Flask** : modèle **MLP (MLPClassifier)** entraîné avec `train_model.py` (StandardScaler + MLPClassifier, couches 128–64–32, ReLU, Adam, early stopping). Features : length, special_chars, special_char_ratio, sql_keywords, has_union_pattern, has_tautology, has_time_based, has_comment, has_error_based, entropy, keyword_density.  
- **Utilisation** : uniquement en **zone grise** (score WAF entre 30 et 80). Le middleware envoie l’entrée à l’API ; si le modèle renvoie un risque > 0.75, la requête est bloquée (type AI_DETECTED_THREAT).  
- **Pas de ML côté PHP** : ThreatIntelligenceEngine utilise des heuristiques et patterns, pas un modèle entraîné.

## Score de décision
- **WAF** : score entier 0–150 (après contexte), seuil de blocage 80, zone grise 30–80 pour l’IA.  
- **IA** : risque flottant 0–1, seuil de blocage 0.75 ; confiance retournée pour traçabilité.  
- **Niveau de menace** : NONE (< 30), LOW (30–50), MEDIUM (50–80), HIGH (80–100), CRITICAL (≥ 100).

## Seuils
- Blocage WAF : score ajusté ≥ 80.  
- Appel IA : 30 ≤ score ajusté < 80.  
- Blocage IA : risk > 0.75 (Flask ou ThreatIntelligenceEngine).  
- ThreatIntelligenceEngine (PHP) : RISK_THRESHOLD = 0.75, et confiance > 0.7 pour shouldBlock.

## Gestion des faux positifs
- **Zone grise** : les entrées à score moyen sont réanalysées par l’IA pour éviter de bloquer des recherches légitimes contenant des mots-clés.  
- **Contexte** : poids différent selon la page (ex. search 1.1 vs admin 1.5) pour adapter la sévérité.  
- **Liste blanche IP** : SecurityResponseFactory::shouldContinue() autorise 127.0.0.1 et ::1 ; IpAccessControl permet une whitelist globale.  
- **Pas de mécanisme de feedback utilisateur** (ex. « Débloquer ») ni de liste blanche de payloads dans le code analysé.

## Protection contre l’obfuscation
- **Normalisation** : urldecode jusqu’à 3 niveaux (SqlInjectionDetector et ThreatIntelligenceEngine), suppression espaces multiples, passage en minuscules.  
- **Patterns** : certains patterns ciblent des encodages (%27, %20OR%20, etc.) dans ThreatIntelligenceEngine.  
- **Pas de désobfuscation avancée** (Unicode, encodages multiples, caractères homoglyphes) ni de sandbox d’exécution.

---

# 5️⃣ Module IA

## Type d’algorithme
- **En production (API Flask)** : **MLPClassifier** (réseau de neurones multicouches), scikit-learn, pipeline StandardScaler + MLP.  
- **Paramètres** : hidden_layer_sizes=(128, 64, 32), activation ReLU, solver Adam, max_iter=300, early_stopping=True, validation_fraction=0.1, random_state=42.  
- **Fallback** (modèle non chargé ou API indisponible) : règles heuristiques (poids par feature : has_union_pattern, has_tautology, has_time_based, has_comment, special_char_ratio, entropy, sql_keywords, longueur, keyword_density) avec seuil 0.75 et poids de contexte.

## Features utilisées
- **Liste fixe (features.py / FEATURE_NAMES)** : length, special_chars, special_char_ratio, sql_keywords, has_union_pattern, has_tautology, has_time_based, has_comment, has_error_based, entropy, keyword_density.  
- **Extraction** : normalisation (strip, lower, collapse spaces), comptages (caractères spéciaux, mots-clés SQL), détection de patterns (union+select, 1=1/'1'='1', sleep/benchmark/waitfor/delay, commentaires, extractvalue/updatexml/exp), entropie de Shannon, densité de mots-clés.

## Dataset d’entraînement
- **Source principale** : fichier CSV `dataset/SQLiV3.csv` (colonnes Sentence, Label). Label 1 = SQLi, 0 = bénin.  
- **Limite optionnelle** : `max_sqli=10000` (ou 15000 dans dataset.py) pour équilibrer ou limiter la taille.  
- **Repli** : si le CSV est absent, listes Python `SQLI_SAMPLES` (payloads étiquetés par type) et `BENIGN_SAMPLES` (entrées normales).  
- **Équilibrage** : ajout de bénins (répétition de BENIGN_SAMPLES) pour viser un ratio configurable (benign_ratio=1.0) par rapport au nombre de SQLi.

## Méthode d’évaluation
- **Validation croisée 5-fold** sur le même jeu (scaler et MLP dans le pipeline pour éviter la fuite de données).  
- **Métriques** : F1, accuracy, precision, recall (moyenne et écart-type pour F1).  
- **Sauvegarde** : metrics.json (precision, recall, f1_score, accuracy, training_date, n_samples, model_type).

## Taux de précision / faux positifs
- **Non fixés dans le code** : les métriques dépendent du run d’entraînement (dataset, split). Le rapport technique doit s’appuyer sur les valeurs figurant dans `metrics.json` après un entraînement réel (ex. F1 ~0.xx, précision ~0.xx, recall ~0.xx).  
- **En production** : le seuil 0.75 et la zone grise (30–80) limitent les blocages directs par le WAF sur des cas ambigus et reportent la décision sur l’IA, ce qui peut réduire les faux positifs par rapport à un WAF pur.

## Mise à jour du modèle
- **Manuelle** : exécution de `python train_model.py` dans `api-ia-flask/`, régénération de `model.joblib` et `metrics.json`.  
- **Redémarrage** du service Flask pour charger le nouveau modèle (pas de rechargement à chaud).  
- **Aucun pipeline CI/CD** ni réentraînement périodique automatique ; pas de versioning de modèle dans le code (la version est fixée dans app.py : MODEL_VERSION = "2026.2.0-ml").

---

# 6️⃣ Gestion des incidents

## Lorsqu’une attaque est détectée
- **Blocage** : réponse HTTP 403, exécution stoppée (exit après rendu de la page de blocage).  
- **Log fichier** : écriture dans `var/logs/security_blocks.log` (ligne avec date, type, source WAF/AI, IP, payload tronqué, contexte JSON).  
- **Log structuré** : SecurityLogger::logSqlInjection (niveau warning/alert selon implémentation) avec IP, payload, score, patterns, action BLOCKED/BLOCKED_BY_AI, paramètre, contexte.  
- **Enregistrement en base** : INSERT dans `security_incidents` (uuid, type SQL_INJECTION ou AI_DETECTED_THREAT, ip_address, payload_hash, payload_preview, risk_score, ai_confidence, ai_risk_factors, detection_method WAF/AI, threat_level, action_taken blocked, blocked=1, country_code, threat_type, subtype, endpoint, created_at).  
- **Géolocalisation** : résolution de l’IP via IpGeolocation (cache ip_geo_cache ou API ip-api.com) et stockage country_code (et city, region dans la table si prévu) pour les rapports et la carte des menaces.

## Blacklist IP
- **IpAccessControl** : table `ip_access_rules` (rule_type = blacklist). Si l’IP est blacklistée, elle est refusée avant même le middleware SQLi (sur les pages qui appellent isBlocked, ex. login).  
- **Pas de blacklist automatique** après N incidents : l’ajout en blacklist est manuel (interface admin-ip-rules ou équivalent).

## Rate limiting
- **RateLimiter** : par (hash(IP), endpoint), fenêtre temporelle et nombre max de tentatives.  
- **Login** : 15 min (900 s), 5 tentatives ; après dépassement, message « Réessayez dans X minute(s) » et recordAttempt à chaque échec.  
- **Inscription** : 24 h, 5 inscriptions max par IP (constantes définies, à appliquer dans inscription.php).  
- **Stockage** : table `rate_limits` (key_hash, endpoint, count, window_start).

## Alertes
- **SecurityLogger** : pour les niveaux CRITICAL, EMERGENCY, ALERT, la méthode sendAlert() est un hook vide (commentaire « Hook futur : email, Slack, webhook SOC »).  
- **Dashboard** : affichage d’une alerte visuelle si today_incidents > 5 (seuil configurable dans le template).  
- **Pas d’envoi d’email/SMS/webhook** implémenté dans le code analysé.

---

# 7️⃣ Sécurité du système lui-même

## Authentification
- **Pages métier** : login via formulaire, vérification des identifiants par SecureDataGateway (requêtes préparées, password_verify).  
- **Session** : session_regenerate_id(true) au démarrage et après login réussi ; variables de session (authenticated, user_id, username, role, login_time, session_id).  
- **Dashboard / search** : vérification `$_SESSION['authenticated']` et `user_id` ; redirection vers login si non authentifié.  
- **Pas d’authentification HTTP (Basic/Digest)** ni de JWT pour les endpoints analysés.

## Autorisation
- **Rôles** : champ `role` en base (ex. user, admin) ; utilisé pour l’affichage ou les droits (ex. admin pour certaines pages).  
- **CSRF** : token généré par ApplicationConfig::generateCsrfToken(), vérifié via validateCsrfToken() sur les formulaires POST (login, inscription).  
- **Cookies** : remember_token en Secure, HttpOnly, SameSite=Strict (durée 30 jours).

## Protection des logs
- **Fichiers** : écriture dans var/logs (droits à configurer en déploiement) ; pas de chiffrement des fichiers de log.  
- **Base** : payload stocké en aperçu (payload_preview, limite 500 caractères) et en hash (payload_hash) ; pas de stockage du payload brut complet en clair pour les incidents.  
- **Logs applicatifs** : username logué sous forme de hash (username + IP) pour les échecs de login, pas le mot de passe.

## Chiffrement
- **Mots de passe** : hash avec password_hash (bcrypt/argon2 selon PHP), vérification avec password_verify.  
- **Flux** : pas de chiffrement spécifique des échanges avec l’API Flask (en localhost ou à sécuriser en production par HTTPS).  
- **SSL** : FlaskAiClient désactive verify_peer pour les appels HTTPS (à durcir en production).

## Protection contre le contournement
- **Analyse sur tous les paramètres** : le middleware parcourt tous les paramètres GET/POST ; un attaquant ne peut pas contourner en changeant le nom du champ sans que la valeur soit analysée.  
- **Sortie immédiate** : en cas de blocage, exit() empêche l’exécution du reste du script.  
- **Liste blanche IP** : réservée aux IP de confiance (ex. localhost) dans shouldContinue ; whitelist globale gérée par IpAccessControl.  
- **Pas de paramètre secret** pour désactiver la protection (test_mode=1 dans shouldContinue n’est pas utilisé dans le flux principal décrit ; à ne pas exposer en production).

---

# 8️⃣ Points forts techniques

- **Double couche (WAF + IA)** : décision en deux temps (règles rapides + IA en zone grise) pour équilibrer détection et faux positifs.  
- **Score contextuel** : poids selon la page (login, search, admin, api) reflète le risque métier.  
- **Fallback IA** : si l’API Flask est indisponible, ThreatIntelligenceEngine (PHP) assure la continuité sans tout autoriser.  
- **Traçabilité complète** : incidents en base avec uuid, payload_hash, payload_preview, risk_score, ai_confidence, ai_risk_factors, detection_method, géolocalisation, vues et procédures pour rapports.  
- **Rate limiting et contrôle IP** : limitation des tentatives et listes noire/blanche intégrées au flux.  
- **Authentification sécurisée** : SecureDataGateway, requêtes préparées, filtrage des données sensibles, verrouillage après échecs.  
- **Tableau de bord temps réel** : statistiques, graphiques, carte des menaces, export CSV, rafraîchissement AJAX.  
- **Rétention et conformité** : purge configurable des incidents et des logs (IncidentRetention, procédure cleanup_old_incidents).  
- **Modèle ML reproductible** : pipeline StandardScaler + MLP, features définies, validation croisée, metrics.json et model.joblib versionnables.  
- **Tests unitaires** : SqlInjectionDetectorTest couvre entrées saines, patterns classiques, contexte, niveau de risque, mode blocage.  
- **Page de blocage soignée** : UX claire, ID incident copiable, reCAPTCHA optionnel pour reprendre le flux, en-têtes de sécurité (CSP, X-Frame-Options, etc.).

---

# 9️⃣ Limites actuelles

- **Pas de reverse proxy WAF** : la protection est dans l’application ; une faille en amont (ex. autre script non protégé) n’est pas couverte.  
- **Couverture des points d’entrée** : chaque script doit inclure manuellement le middleware ; risque d’oubli sur de nouveaux formulaires ou API.  
- **API Flask en HTTP/localhost** : verify_peer désactivé ; en production il faut HTTPS et vérification SSL.  
- **Géolocalisation** : dépendance à ip-api.com (quota gratuit, disponibilité) ; pas de fallback si l’API ou la table ip_geo_cache est absente.  
- **Alertes** : sendAlert() non implémenté ; pas de notification temps réel (email, Slack, SOC).  
- **Blacklist automatique** : pas de mise en blacklist après N incidents par IP.  
- **Feedback utilisateur** : pas de « débloquer » ou liste blanche de payloads pour faux positifs.  
- **Obfuscation avancée** : pas de traitement Unicode/homoglyphes ni de sandbox.  
- **Scalabilité** : un appel HTTP à l’API Flask par requête en zone grise ; sous charge, il faudrait du cache ou une file.  
- **Mise à jour du modèle ML** : manuelle, sans versioning ni A/B testing.  
- **Tables optionnelles** : ip_geo_cache et ip_access_rules en migrations ; si non appliquées, la géo et les règles IP sont ignorées sans erreur bloquante.

---

# 🔟 Complexité et performance

- **Temps d’analyse (WAF)** : calcul en mémoire (regex, entropie, comptages) ; typiquement < 1 ms par paramètre.  
- **Temps d’analyse (IA)** : appel HTTP à Flask (timeout 2 s) ; traitement côté Python (features + prédiction MLP) de l’ordre de quelques millisecondes à dizaines de ms ; métrique processing_time_ms exposée dans la réponse et loggée.  
- **Impact latence** : en cas de zone grise, la latence totale de la requête augmente du temps d’appel à l’API (réseau + calcul). En cas de blocage WAF, pas d’appel IA.  
- **Scalabilité** :  
  - PHP : stateless, scalable horizontalement derrière un load balancer si la session est externalisée.  
  - Flask : un processus par défaut ; pour plus de débit, déploiement multi-workers (Gunicorn/uWSGI) ou plusieurs instances.  
  - MySQL : index sur security_incidents (created_at, ip_address, blocked, risk_score, threat_level, type), rate_limits (window_start), ce qui permet des requêtes dashboard et des INSERT rapides.  
- **Tests de charge** : non présents dans le dépôt (pas de script k6, Apache Bench ou équivalent). Les métriques de performance réelles (temps moyen d’analyse, p99) sont à mesurer en environnement cible et à documenter dans le mémoire (ex. à partir des logs ou de metrics.json).

---

*Rapport généré à partir de l’analyse du code source du projet. À utiliser comme base factuelle pour la rédaction du mémoire et les diagrammes (séquence, composants, déploiement).*
