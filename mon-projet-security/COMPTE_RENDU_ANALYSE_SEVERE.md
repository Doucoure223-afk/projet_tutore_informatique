# Rapport d'analyse sévère — Protection automatique contre l'injection SQL

**Thème :** Protection automatique des applications web contre l'attaque par injection SQL  
**Périmètre :** Partie vulnérable (démo) — `projet_tutoré_inf` | Partie sécurisée — `mon-projet-security`  
**Date :** 18 février 2026

---

## 1. Synthèse exécutive

Vous avez scindé le sujet en **une application vulnérable (démo)** et **une application sécurisée**. L’idée est bonne pour la pédagogie, mais l’analyse montre des **incohérences architecturales**, des **erreurs de conception**, des **lacunes de sécurité** et des **parties inutilisées ou contradictoires** qui nuisent à la crédibilité technique du projet. Ce rapport est volontairement sévère et exhaustif.

---

## 2. Problèmes critiques (bloquants)

### 2.1 Partie vulnérable — Aucune intégration du module de sécurité

- **Constat :** Le dossier `projet_tutoré_inf/security/` contient un **détecteur SQL** (`detector.php`), un **ResponseHandler** et un **Logger**, mais **aucun fichier de l’application vulnérable** (`app/login.php`, `app/search.php`, `app/inscription.php`, `app/dashboard.php`) ne les inclut ni ne les utilise.
- **Conséquence :** La « partie sécurité » du projet vulnérable est **morte** : elle n’intercepte aucune requête. Un correcteur ou un client pourrait croire que la démo « vulnérable » est protégée par ce module ; en réalité, elle ne l’est pas.
- **Recommandation :** Soit documenter clairement que le détecteur est **hors flux** (ex. « module de démo à part, non branché sur l’app »), soit prévoir une variante (ex. `app/search_protected.php`) qui l’utilise pour montrer « vulnérable sans détecteur » vs « vulnérable avec détecteur ».

### 2.2 Partie vulnérable — Dashboard sans contrôle d’authentification

- **Fichier :** `projet_tutoré_inf/app/dashboard.php`
- **Constat :** Aucune vérification de session avant d’utiliser `$_SESSION['user_id']`. Un accès direct à `dashboard.php` sans être connecté donne :
  - `$user_id` non défini → requête `SELECT * FROM users WHERE id = ` (syntaxe SQL invalide)
  - Si `execute_query_vulnerable()` retourne `false`, `mysqli_fetch_assoc($user_result)` sur `false` provoque des erreurs PHP.
- **Recommandation :** En tout début de script : vérifier `isset($_SESSION['user_id'])` et rediriger vers `login.php` si absent.

### 2.3 Partie vulnérable — Mots de passe stockés en clair

- **Fichiers :** `projet_tutoré_inf/app/login.php`, `app/inscription.php`
- **Constat :** Login compare `password = '$password'` en clair ; inscription fait `INSERT ... VALUES(..., '$pass', ...)` sans aucun hash.
- **Problème :** Même en « démo », cela :
  - normalise une pratique **interdite** (stockage de mots de passe en clair) ;
  - rend la base immédiatement exploitable en cas de fuite (SQLi ou vol de BDD).
- **Recommandation :** En démo, au minimum utiliser `password_hash()` / `password_verify()` et documenter que la vulnérabilité ciblée est **uniquement** l’injection SQL, pas le stockage des mots de passe.

### 2.4 Partie vulnérable — Inscription : choix du rôle « admin »

- **Fichier :** `projet_tutoré_inf/app/inscription.php`
- **Constat :** Le formulaire propose `<option value="admin">Admin</option>`. N’importe qui peut s’inscrire comme administrateur.
- **Problème :** En plus des SQLi, vous introduisez une **faille de contrôle d’accès** (privilege escalation) sans lien avec le thème « injection SQL ».
- **Recommandation :** Forcer `role = 'user'` côté serveur et retirer le champ rôle du formulaire (ou le réserver à un back-office authentifié).

### 2.5 Partie vulnérable — XSS et fuite de requête dans le debug (dashboard)

- **Fichier :** `projet_tutoré_inf/app/dashboard.php` (l. 194)
- **Constat :**  
  `<?php echo $_GET['admin_search']; ?>` est affiché **sans** `htmlspecialchars()` dans la section « Débogage ». Un payload du type `admin_search=<script>...` ou une longue chaîne peut dégrader l’affichage ou ouvrir des vecteurs XSS.
- **Recommandation :** Toujours échapper les sorties : `htmlspecialchars($_GET['admin_search'], ENT_QUOTES, 'UTF-8')`.

### 2.6 Partie vulnérable — Erreur HTML (balise mal fermée)

- **Fichier :** `projet_tutoré_inf/app/inscription.php` (l. 65)
- **Constat :**  
  `<a href="login.php">Connectez-vous</Connectez-vous></a>` — balise de fermeture incorrecte.
- **Recommandation :** Remplacer par `</a>`.

### 2.7 Partie vulnérable — Variable `$conn` dans inscription

- **Fichier :** `projet_tutoré_inf/app/inscription.php`
- **Constat :** Le script utilise `$conn` et `mysqli_query($conn, $sql)` alors que `config.php` définit `$conn` dans le scope global. Si un jour `config.php` est inclus depuis un autre répertoire ou que l’ordre d’inclusion change, `$conn` peut être indisponible.
- **Recommandation :** Utiliser explicitement `getDatabaseConnection()` (déjà défini dans `config.php`) pour clarifier la dépendance.

### 2.8 Partie sécurisée — Schéma SQL vs code (security_incidents)

- **Fichiers :** `mon-projet-security/database/schema.sql` vs `SecurityResponseFactory.php`
- **Constat :** Le schéma de `security_incidents` contient notamment : `id`, `ip_address`, `country_code`, `threat_type`, `risk_score`, `status`, `payload_preview`, `parameter`, `context`, `created_at`.  
  Le code fait un **INSERT** avec des colonnes : `uuid`, `type`, `ip_address`, `payload_hash`, `payload_preview`, `risk_score`, `ai_confidence`, `ai_risk_factors`, `detection_method`, `threat_level`, `action_taken`, `blocked`, `country_code`, `threat_type`, `subtype`, `endpoint`.  
  Les migrations vues (`2026_fix_security_incidents_columns.sql`, `2026_add_ai_insights_columns.sql`) n’ajoutent pas `uuid`, `type`, `payload_hash`, `detection_method`, `threat_level`, `action_taken`, `blocked`, `subtype`, `endpoint`.
- **Conséquence :** Sur une base créée uniquement avec `schema.sql` + ces migrations, l’**INSERT échouera** (colonnes inconnues).
- **Recommandation :** Soit mettre à jour `schema.sql` pour qu’il reflète la structure attendue par le code, soit fournir une migration unique qui crée/altère `security_incidents` pour correspondre exactement à l’INSERT.

### 2.9 Partie sécurisée — Cookie `remember_token` avec `secure => true`

- **Fichier :** `mon-projet-security/public/login.php` (fonction `createSecureSession()`)
- **Constat :** `setcookie(..., 'secure' => true, ...)`. En développement sous HTTP (sans HTTPS), ce cookie **ne sera pas envoyé** par le navigateur.
- **Recommandation :** Rendre `secure` dépendant de l’environnement (HTTPS détecté ou config), pour éviter des comportements incompréhensibles en local.

---

## 3. Incohérences et confusions

### 3.1 Configuration sécurité (projet vulnérable) jamais utilisée

- **Fichier :** `projet_tutoré_inf/config/security.php`
- **Constat :** Définit `block_mode`, `threshold`, `whitelist_ips`, `rate_limiting`, etc. Aucun fichier du projet (app ou security) ne fait `require` de ce fichier ; le détecteur ne lit pas ce seuil.
- **Conséquence :** Fausse impression de « configuration centralisée » ; les valeurs (ex. threshold 70) n’ont **aucun effet**.
- **Recommandation :** Soit intégrer cette config dans le détecteur et les points d’entrée, soit supprimer le fichier et documenter que la démo vulnérable n’a pas de config centralisée.

### 3.2 Deux implémentations différentes du détecteur SQL

- **projet_tutoré_inf/security/detector.php :**  
  Méthode `analyzeWithScore()` retourne un tableau avec `block`, `score`, `patterns`, `needs_ai`, etc. Méthode `detect()` pour compatibilité.
- **mon-projet-security :**  
  `SqlInjectionDetector` (namespace) retourne un objet `DetectionResult` avec `shouldBlock`, `score`, `needsAiAnalysis`, `detectedPatterns`, `riskLevel`, etc.
- **Problème :** Noms et structures différents pour le même concept. La démo « vulnérable vs sécurisé » ne compare pas les mêmes API ; la partie vulnérable n’utilise de toute façon pas son détecteur.
- **Recommandation :** Documenter clairement la séparation (démo vs production) et, si possible, aligner les concepts (ex. même vocabulaire : blocage, score, niveau de risque).

### 3.3 Fonctions « sécurisées » dans la config vulnérable

- **Fichier :** `projet_tutoré_inf/app/config.php`
- **Constat :** Définit à la fois `execute_query_vulnerable()` et `execute_query_secure()` (requêtes préparées). L’application vulnérable n’utilise **que** `execute_query_vulnerable()`.
- **Problème :** Un lecteur peut croire que certaines pages utilisent la version sécurisée ; ce n’est pas le cas. Mélange des responsabilités dans un même fichier.
- **Recommandation :** Documenter que `execute_query_secure()` est fourni « pour comparaison » ou pour un futur branchement, et ne pas l’utiliser dans les pages démo sans le dire.

### 3.4 Référence à `user_logs` (dashboard vulnérable)

- **Fichier :** `projet_tutoré_inf/app/dashboard.php`
- **Constat :** Requête `SELECT * FROM user_logs WHERE user_id = $user_id ...`. Aucune migration ou script fourni dans `projet_tutoré_inf` ne crée la table `user_logs`.
- **Conséquence :** En environnement vierge, cette requête **échoue** ; le dashboard peut afficher des erreurs ou des pages vides.
- **Recommandation :** Fournir un script SQL (ou seed) qui crée `user_logs` dans la base `projet_sqli_vulnerable`, ou gérer le cas « table absente » (message clair, pas d’affichage de stack trace).

### 3.5 Incohérence des noms de base de données et chemins

- **Vulnérable :** BDD `projet_sqli_vulnerable` (config dans `app/config.php`).
- **Sécurisé :** BDD `mon_projet_securite` (config via `config/config.php` / `ApplicationConfig`).
- **DEMO_README / DEMO_CONCORDANCE :** Mentionnent bien les deux bases et les URLs, mais les chemins (ex. `projet_tutoré_inf/app/` vs `mon-projet-security/public/`) ne sont pas toujours cohérents selon la doc (ex. « Exécuter seed_products.sql dans la base projet_sqli_vulnerable » alors que le seed est sous `projet_tutoré_inf/database/`).
- **Recommandation :** Un seul fichier « Installation / Démo » qui liste : 1) création des BDD, 2) ordre d’exécution des scripts SQL (schema + migrations + seeds) pour chaque projet.

---

## 4. Erreurs et risques secondaires

### 4.1 Gestion d’erreur SQL en mode debug (projet vulnérable)

- **Fichier :** `projet_tutoré_inf/app/config.php` — `execute_query_vulnerable()`
- **Constat :** Si `$_GET['debug'] == '1'`, les messages d’erreur MySQL et la requête sont affichés dans la page. En production (ou si quelqu’un déploie sans désactiver), **fuite d’informations** (structure des tables, chemins, etc.).
- **Recommandation :** Ne jamais afficher les erreurs SQL selon un paramètre GET. Utiliser un fichier de config (ex. `APP_DEBUG`) ou des variables d’environnement, et en production toujours logger sans afficher.

### 4.2 Rate limiting et IP (projet sécurisé)

- **Fichier :** `mon-projet-security/public/login.php`
- **Constat :** Le rate limiting est basé sur un hash de l’IP. Derrière un reverse proxy ou un NAT, plusieurs utilisateurs peuvent partager la même clé et être limités ensemble (faux positifs).
- **Recommandation :** Documenter la limite (ex. « par IP ») et, si besoin, prévoir une option « par IP + User-Agent » ou « par session » pour affiner.

### 4.3 Validation côté client (login sécurisé)

- **Fichier :** `mon-projet-security/public/login.php` (script en bas de page)
- **Constat :** Vérification « mot de passe >= 8 caractères » uniquement en JavaScript. Désactiver JS ou envoyer une requête directe contourne cette règle.
- **Recommandation :** Répliquer la règle côté serveur (déjà partiellement fait via `validateAndSanitizeCredentials` pour la longueur max ; ajouter une longueur minimale côté serveur si c’est une exigence métier).

### 4.4 Typo dans le nom de fichier CSS (projet vulnérable)

- **Fichier :** `projet_tutoré_inf/app/style_dashborad.css` (référencé dans `dashboard.php`).
- **Constat :** « dashborad » au lieu de « dashboard ». Faute d’orthographe récurrente dans les projets.
- **Recommandation :** Renommer en `style_dashboard.css` et mettre à jour les références.

---

## 5. Bonnes pratiques non respectées ou partielles

### 5.1 Pas de protection CSRF sur la partie vulnérable

- **Fichiers :** `projet_tutoré_inf/app/login.php`, `inscription.php`
- **Constat :** Les formulaires n’ont pas de jeton CSRF. Même en démo, cela ne reflète pas les bonnes pratiques et peut être exploité (soumission de formulaires depuis un autre site).
- **Recommandation :** Ajouter un token CSRF (comme dans la partie sécurisée) et indiquer dans la doc que la « vulnérabilité démontrée » est limitée à la SQLi.

### 5.2 Logging des payloads en clair

- **projet_tutoré_inf/security/logger.php** et **mon-projet-security** (SecurityLogger, SecurityResponseFactory) : les payloads sont loggés (fichier ou BDD) avec des extraits en clair.
- **Risque :** En cas de vol de logs, des tentatives d’injection (parfois contenant des données sensibles) sont exposées.
- **Recommandation :** Pour les logs long terme, envisager de ne stocker que un hash du payload + préfixe tronqué, et de limiter la rétention.

### 5.3 Pas de Content-Security-Policy (CSP) sur la partie vulnérable

- **Constat :** La partie vulnérable n’envoie pas de en-têtes CSP. En cas de XSS (déjà possible sur le dashboard), la surface d’attaque est plus grande.
- **Recommandation :** Même en démo, ajouter au moins un en-tête CSP minimal (ou documenter que la démo ne couvre pas XSS/CSP).

---

## 6. Tableau récapitulatif des problèmes

| Gravité   | Catégorie              | Projet        | Résumé |
|-----------|------------------------|---------------|--------|
| Critique  | Architecture           | Vulnérable    | Détecteur / ResponseHandler jamais utilisés |
| Critique  | Sécurité               | Vulnérable    | Dashboard sans contrôle d’auth |
| Critique  | Sécurité               | Vulnérable    | Mots de passe en clair |
| Critique  | Sécurité               | Vulnérable    | Rôle admin choisi à l’inscription |
| Critique  | Sécurité / XSS         | Vulnérable    | `admin_search` affiché sans échappement (dashboard) |
| Critique  | Qualité                | Vulnérable    | Balise HTML mal fermée (inscription) |
| Critique  | Cohérence BDD/code      | Sécurisé      | INSERT `security_incidents` vs schema/migrations |
| Critique  | UX / config            | Sécurisé      | Cookie `secure => true` en HTTP |
| Majeur    | Config                 | Vulnérable    | `config/security.php` jamais chargé |
| Majeur    | Cohérence              | Les deux      | Deux API de détection différentes, non alignées |
| Majeur    | Données                | Vulnérable    | Table `user_logs` non fournie |
| Majeur    | Sécurité               | Vulnérable    | Debug SQL via `?debug=1` |
| Mineur    | Qualité                | Vulnérable    | Typo `style_dashborad.css` |
| Mineur    | Qualité                | Vulnérable    | Utilisation de `$conn` global (inscription) |

---

## 7. Recommandations prioritaires

1. **Partie vulnérable**  
   - Ajouter une vérification d’authentification en tête de `dashboard.php` et gérer le cas où les requêtes SQL échouent (table absente, `user_id` invalide).  
   - Créer la table `user_logs` (ou documenter qu’elle est optionnelle et adapter le code).  
   - Hash des mots de passe (password_hash/verify) et rôle forcé à `user` à l’inscription.  
   - Échapper toutes les sorties (dashboard, notamment `admin_search`).  
   - Corriger la balise HTML dans `inscription.php` et préférer `getDatabaseConnection()` à `$conn`.  
   - Soit brancher le détecteur sur au moins une page (avec documentation), soit indiquer clairement qu’il n’est pas dans le flux.

2. **Partie sécurisée**  
   - Aligner le schéma de `security_incidents` (schema.sql + migrations) avec l’INSERT de `SecurityResponseFactory`.  
   - Rendre le cookie `secure` conditionnel à l’usage de HTTPS.

3. **Documentation et cohérence**  
   - Un seul guide « Installation & Démo » : bases, migrations, seeds, URLs.  
   - Clarifier : vulnérable = « pas de détecteur dans le flux » ; sécurisé = « détection + requêtes préparées + gateway ».  
   - Mentionner les limites (rate limit par IP, logging des payloads, etc.).

4. **Config et code mort**  
   - Soit utiliser `config/security.php` dans le projet vulnérable (détecteur, seuils), soit le retirer et documenter.

---

## 8. Conclusion

Le découpage **vulnérable / sécurisé** est pertinent pour la démo, et la partie sécurisée (requêtes préparées, SecureDataGateway, détection + IA, rate limiting, CSRF) montre une vraie montée en maturité. En revanche, la partie vulnérable souffre de **module de sécurité inutilisé**, de **manque de contrôle d’accès et d’auth**, de **mots de passe en clair** et de **détails d’implémentation (BDD, schéma, config) incohérents**. Pour un rendu professionnel ou une soutenance, il est indispensable de corriger au minimum les points critiques et de clarifier par la documentation ce qui est « volontairement vulnérable pour la démo » et ce qui est « oubli ou erreur ».

---

## 9. Compatibilité et état de préparation — Le projet est-il prêt à 100 % ?

**Réponse courte : non.** Le projet n'est pas prêt à 100 % en l'état, à la fois pour la **compatibilité** entre les deux parties et pour un **déploiement / démo sans mauvaise surprise**. Voici ce qu'il faut avoir en tête.

### 9.1 Compatibilité technique

| Élément | Partie vulnérable | Partie sécurisée | Conseil |
|--------|--------------------|------------------|--------|
| **PHP** | Non précisé (mysqli) | **PHP 8.2+** (composer.json) | Partie vulnérable : préciser « PHP 7.4+ » ou « 8.x » dans un README ; partie sécurisée : vérifier que le serveur (WAMP) est bien en 8.2+ (sinon erreurs). |
| **Base de données** | `projet_sqli_vulnerable` (MySQL) | `mon_projet_securite` (MySQL) | **Deux bases distinctes** : pas de conflit, mais l'install doit créer les deux et exécuter les bons scripts (schema + migrations + seeds) pour chacune. |
| **Config** | `app/config.php` (direct) | `config/config.php` + optionnel `.env` (DB_HOST, DB_NAME, etc.) | La partie sécurisée lit `getenv()` pour la DB ; si `.env` n'est pas copié/rempli, les valeurs par défaut (localhost, root, mon_projet_securite) s'appliquent. Documenter clairement. |
| **Redis** | Non utilisé | Mentionné dans `.env.example` (CACHE_DRIVER, SESSION_DRIVER) | Le code métier lu n'utilise pas Redis pour la démo (sessions PHP, rate limit en BDD). Redis peut rester **optionnel** ; ne pas le rendre obligatoire sans le documenter. |
| **API Flask (IA)** | Non utilisée | Utilisée (FlaskAiClient) | Si l'API Flask n'est pas lancée (`python app.py`), le code fait un **fallback** (ThreatIntelligenceEngine PHP). Pour une démo « 100 % », lancer Flask ; sinon la démo tourne sans ML. |
| **Chemins / URLs** | `.../projet_tutoré_inf/app/` | `.../mon-projet-security/public/` | Les noms avec accents (`projet_tutoré_inf`) peuvent poser souci sur certains serveurs ou proxies. Préférer une URL sans accent pour la démo (ex. alias `demo-vulnerable`). |
| **Extensions PHP** | mysqli | PDO, json, mbstring, openssl, simplexml | Partie sécurisée : vérifier que toutes les extensions listées dans `composer.json` sont activées (souvent le cas sur WAMP 64). |

### 9.2 Ce qui manque pour être « prêt à 100 % »

1. **Install reproductible**  
   Un seul document (ex. `INSTALL_DEMO.md`) qui indique, dans l'ordre : création des 2 BDD → exécution de `schema.sql` (sécurisé) + toutes les migrations nécessaires → exécution des seeds (vulnérable : products, users ; sécurisé : products, users) → création éventuelle de `user_logs` (vulnérable) → `composer install` (sécurisé) → copie de `.env` et `config.php` → vérification des URLs.

2. **Schéma `security_incidents` aligné avec le code**  
   Tant que l'INSERT de `SecurityResponseFactory` utilise des colonnes absentes du schema/migrations, un nouvel install **échouera** au premier blocage (erreur SQL). Il faut une migration ou un schema à jour (voir section 2.8).

3. **Partie vulnérable « démo propre »**  
   Au minimum : auth sur le dashboard, table `user_logs` créée ou désactivée proprement, pas de crash si une requête échoue. Sans ça, la démo peut planter devant un jury.

4. **Clarification des options**  
   Documenter ce qui est **obligatoire** (PHP, MySQL, Composer, 2 BDD) et ce qui est **optionnel** (Flask, Redis, reCAPTCHA) pour « faire tourner la démo ».

### 9.3 Recommandation synthétique

- **Pour une démo / soutenance** : traiter en priorité les **bloquants** du rapport (auth dashboard vulnérable, schéma `security_incidents`, cookie `secure` en HTTP, création de `user_logs` ou gestion de son absence), puis rédiger **un seul guide d'installation et de démo** (compatibilité PHP/MySQL, ordre des scripts, URLs).
- **Pour considérer le projet « prêt à 100 % »** : en plus de ce qui précède, appliquer les recommandations de la section 7 (partie vulnérable : hash des mots de passe, rôle forcé, échappement XSS, correction HTML ; partie sécurisée : schéma cohérent ; documentation : config vivante ou supprimée).

En l'état actuel, le projet est **utilisable pour une démo** à condition de ne pas oublier les migrations et de connaître les écueils (dashboard sans auth, table manquante, schéma incidents). Il n'est **pas à 100 % prêt** pour un déploiement « clé en main » ou une remise sans accompagnement (README + INSTALL + corrections critiques).
