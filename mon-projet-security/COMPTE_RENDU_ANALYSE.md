# Compte rendu — Analyse approfondie des deux projets

**Date :** Février 2026  
**Projets :** projet_tutoré_inf (vulnérable) | mon-projet-security (sécurisé)

---

## 1. Vue d'ensemble

| Critère | projet_tutoré_inf | mon-projet-security |
|---------|-------------------|---------------------|
| **Objectif** | Démonstration des vulnérabilités SQLi | Référence sécurisée conforme OWASP |
| **Technologie** | PHP procédural, MySQLi | PHP 8.2+, PDO, Composer, architecture modulaire |
| **Base de données** | projet_sqli_vulnerable | mon_projet_securite |
| **Lignes de code (app)** | ~600 | ~3500+ (avec src/, api-ia-flask/) |
| **Dépendances** | Aucune (autoload manuel) | Composer + API Flask (Python) |

---

## 2. Architecture

### 2.1 projet_tutoré_inf (vulnérable)

```
projet_tutoré_inf/
├── app/                    # Point d'entrée (login, search, inscription, dashboard)
├── config/                 # Config IA, logger, security (non utilisés par l'app vulnérable)
├── security/               # Detector, IA, ResponseHandler (résiduels, non utilisés)
├── database/               # seed_products.sql
└── logs/                   # access, attaques, errors
```

**Caractéristiques :**
- Structure plate, sans framework
- Fichiers `app/*.php` incluent directement `config.php`
- Le dossier `security/` contient du code de protection qui n'est **pas** chargé par les pages vulnérables (Phase 1)
- Connexion MySQLi globale (`$conn`)

### 2.2 mon-projet-security (sécurisé)

```
mon-projet-security/
├── public/                 # Point d'entrée HTTP uniquement
├── src/App/
│   ├── Infrastructure/     # ApplicationConfig, Database
│   └── Security/           # Detector, AI, RateLimiter, SecureDataGateway, etc.
├── api-ia-flask/           # API Python (ML, analyse menaces)
├── database/migrations/    # Migrations versionnées
├── config/                 # Configuration centralisée
└── var/logs/               # Logs structurés JSON Lines
```

**Caractéristiques :**
- Séparation nette : `public/` (entrée) → `src/` (logique)
- Autoload PSR-4 via Composer
- Pas d'accès direct à la base depuis les contrôleurs ; tout passe par `SecureDataGateway`
- API Flask indépendante pour l'analyse IA (modèle ML ou règles de secours)

---

## 3. Analyse de sécurité

### 3.1 Injection SQL

| Page | projet_tutoré_inf | mon-projet-security |
|------|-------------------|---------------------|
| **Login** | `WHERE username = '$username' AND password = '$password'` — concaténation directe | Requête préparée via `SecureDataGateway`, `:username` lié |
| **Search** | `LIKE '%$search_query%'` — concaténation directe + `test_union` injectable | Requête préparée `:q`, `mb_substr` 100 caractères |
| **Inscription** | `VALUES('$user','$pass','$mail','$role','$createtime')` — concaténation | Requêtes préparées, `htmlspecialchars` sur sortie |
| **Dashboard** | `WHERE id = $user_id`, `admin_search` injectable | N/A (pas de dashboard équivalent) |

**Vecteurs d'attaque sur le projet vulnérable :**
- **Login :** `admin' --` → bypass mot de passe
- **Search :** `' OR '1'='1` → tous les produits ; `' UNION SELECT ... FROM users --` → exfiltration
- **Inscription :** Injection sur username, email, role (escalade admin possible)
- **Dashboard :** Injection numérique sur `user_id`, `admin_search` sur la recherche admin

### 3.2 Authentification et mots de passe

| Aspect | projet_tutoré_inf | mon-projet-security |
|--------|-------------------|---------------------|
| **Stockage** | Mot de passe en clair (colonne `password`) | Hash Argon2ID (colonne `password_hash`) |
| **Vérification** | Comparaison directe en SQL | `password_verify()` côté PHP |
| **Inscription** | Mot de passe stocké tel quel | `password_hash(PASSWORD_ARGON2ID)` |

### 3.3 Protections CSRF

| Projet | Login | Inscription |
|--------|-------|-------------|
| **projet_tutoré_inf** | ❌ Aucun token (supprimé en Phase 1) | ❌ Aucun |
| **mon-projet-security** | ✅ `_token` validé via `ApplicationConfig::validateCsrfToken()` | ✅ Idem |

### 3.4 Rate limiting

| Endpoint | projet_tutoré_inf | mon-projet-security |
|----------|-------------------|---------------------|
| **Login** | ❌ Aucun | ✅ 5 tentatives / 15 min par IP |
| **Inscription** | ❌ Aucun | ✅ 5 inscriptions / 24 h par IP |

### 3.5 Contrôle d'accès IP

| Projet | Liste noire/blanche |
|--------|---------------------|
| **projet_tutoré_inf** | ❌ Aucun |
| **mon-projet-security** | ✅ `IpAccessControl` (table `ip_access_rules`) |

### 3.6 Session et cookies

| Aspect | projet_tutoré_inf | mon-projet-security |
|--------|-------------------|---------------------|
| **Params session** | httponly, samesite (config.php) | Idem + régénération ID à la connexion |
| **Cookie remember** | ❌ Non | ✅ HttpOnly, Secure, SameSite=Strict |
| **Fixation session** | ✅ `session_regenerate_id` si `!initiated` | ✅ `session_regenerate_id(true)` à chaque login |

---

## 4. Détection des menaces (mon-projet-security)

### 4.1 SqlInjectionDetector (PHP)

- **Patterns :** Tautologies, UNION, DROP/DELETE, SLEEP, commentaires, blind, mots-clés SQL
- **Score :** Pondéré par contexte (login 1.3, admin 1.5, search 1.1)
- **Zones :** score ≥ 80 → blocage ; 30–80 → envoi à l'IA ; < 30 → passage
- **Échappement :** Décodage URL multi-niveau, normalisation

### 4.2 API Flask (Python)

- **Modèle :** MLP (Multi-Layer Perceptron) via `model.joblib` si présent
- **Fallback :** Règles basées sur features (union, tautology, time-based, entropy, etc.)
- **Seuil :** risk > 0.75 → blocage
- **Contexte :** login, registration, search, admin pondérés

### 4.3 SecureDataGateway

- **Responsabilités :** Requête préparée → DB → filtrage → données nettoyées
- **Filtrage :** Retourne uniquement `id`, `username`, `email`, `role` (jamais `password_hash`)
- **Verrouillage :** Gestion `locked_until`, `login_attempts`

---

## 5. Schéma des bases de données

### 5.1 projet_tutoré_inf (projet_sqli_vulnerable)

**Tables probables :** `users` (id, username, password, email, role, created_at), `products`, `user_logs`

- Colonne `password` en clair
- Pas de `deleted_at`, `login_attempts`, etc.
- Structure minimale

### 5.2 mon-projet-security (mon_projet_securite)

**Tables principales :**
- `users` : password_hash, login_attempts, locked_until, mfa_enabled, deleted_at, verification_token
- `user_profiles` : liaison 1-1
- `security_incidents` : incidents bloqués
- `ai_analysis_logs` : analyses IA
- `rate_limits` : rate limiting
- `ip_access_rules` : liste noire/blanche
- `products` : catalogue (concordance démo)

---

## 6. Points forts et faiblesses

### 6.1 projet_tutoré_inf

**Points forts :**
- Vulnérabilités clairement documentées et visibles (bandeau, payload tester)
- Utile pour la formation et les démonstrations
- Code simple à comprendre
- Config sessions correcte (httponly, samesite)
- Présence de `execute_query_secure()` (non utilisée dans les pages vulnérables)

**Faiblesses (volontaires pour la démo) :**
- Aucune requête préparée sur les flux critiques
- Mots de passe en clair
- Pas de CSRF, rate limiting, contrôle IP
- Risque d’élévation de privilèges (rôle admin modifiable à l’inscription)
- Affichage des requêtes SQL (debug) peut divulguer la structure

### 6.2 mon-projet-security

**Points forts :**
- Architecture alignée OWASP et Zero Trust
- Couches de défense (détection, IA, gateway, rate limiting, IP)
- Requêtes préparées systématiques
- Hash Argon2ID, pas de fuite de données sensibles
- Logs structurés (JSON Lines), prêts pour ELK/Splunk
- Tests unitaires sur le détecteur
- Documentation (README, DEMO_CONCORDANCE, DEMO_CHECKLIST)

**Faiblesses ou axes d’amélioration :**
- Dépendance à l’API Flask (fallback PHP si indisponible)
- Cookie `remember_token` avec `secure => true` peut poser problème en HTTP local
- Pas de logout dédié (lien vers login)
- Dashboard très volumineux (SecurityDashboard.php ~2400 lignes)

---

## 7. Comparatif fonctionnel

| Fonctionnalité | projet_tutoré_inf | mon-projet-security |
|----------------|-------------------|---------------------|
| Login | ✅ | ✅ |
| Inscription | ✅ | ✅ |
| Recherche produits | ✅ | ✅ |
| Dashboard | ✅ (utilisateur) | ✅ (sécurité + graphiques) |
| Logout | ✅ | Redirection login |
| Règles IP | ❌ | ✅ admin-ip-rules.php |
| Export incidents | ❌ | ✅ CSV |
| Rapport PDF | ❌ | ✅ |
| Vérification email | ❌ | ✅ (optionnel) |
| Politique confidentialité | ❌ | ✅ |
| CGU | ❌ | ✅ |

---

## 8. Alignement pédagogique

Les deux projets forment un dispositif cohérent pour :

1. **Montrer les risques** : exploitation SQLi sur login, search, inscription
2. **Montrer les bonnes pratiques** : requêtes préparées, filtrage, détection, rate limiting
3. **Comparer** : même scénario (recherche, payloads) avec des comportements opposés
4. **Documenter** : DEMO_CONCORDANCE.md, DEMO_CHECKLIST.md, payloads de test

---

## 9. Recommandations

### Projet vulnérable
- Conserver le statut « démo uniquement »
- Vérifier que la table `user_logs` existe (dashboard)
- Exécuter `seed_products.sql` avant chaque démo si nécessaire

### Projet sécurisé
- Créer un script/logique de déconnexion (destruction de session)
- Réduire ou extraire des blocs du SecurityDashboard si maintenance difficile
- Adapter la config `secure` du cookie pour les environnements HTTP locaux

---

## 10. Conclusion

Le **projet_tutoré_inf** remplit son rôle de plateforme vulnérable pour la formation : vulnérabilités explicites, bandeaux clairs, payloads de test intégrés.  

Le **mon-projet-security** présente une architecture solide, avec détection SQL, IA, rate limiting, contrôle IP et gateway d’accès aux données, conforme aux standards OWASP et adaptée à un usage type production.  

L’ensemble constitue un support pédagogique structuré pour illustrer les risques d’injection SQL et les contre-mesures associées.
