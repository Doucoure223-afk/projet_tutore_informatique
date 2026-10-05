# Guide de démonstration — Vulnérable vs Sécurisé

Ce document décrit comment réaliser une démonstration comparative des deux projets pour illustrer les risques d'injection SQL et les mesures de protection.

> **Phase 4** : Consulter `DEMO_CHECKLIST.md` pour la checklist de vérification avant la démo.

---

## URLs des projets

| Projet | Base URL | Base de données |
|--------|----------|-----------------|
| **Vulnérable** (projet_tutoré_inf) | `http://localhost/projet_tutoré_inf/app/` | `projet_sqli_vulnerable` |
| **Sécurisé** (mon-projet-security) | `http://localhost/mon-projet-security/public/` | `mon_projet_securite` |

*Ajustez `localhost` selon votre configuration (ex: `localhost:8000`, `127.0.0.1`).*

---

## Prérequis

1. **Base de données vulnérable** : exécuter `projet_tutoré_inf/database/seed_products.sql` pour créer la table `products` et les données de démo.
2. **Base de données sécurisée** : exécuter `mon-projet-security/database/migrations/2026_create_products_table.sql`.
3. **Compte de test** :
   - Vulnérable : créer via `inscription.php` (ex: `demo` / `demo123`) ou insérer manuellement.
   - Sécurisé : créer via `inscription.php` (mots de passe hashés avec Argon2ID).

---

## Scénario de démonstration

### Étape 1 — Vulnérabilité sur la recherche

1. Ouvrir **projet vulnérable** → `search.php`
2. Rechercher un terme normal : `Bluetooth` → affiche « Écouteurs Bluetooth »
3. Tester le payload **tautologie** : `' OR '1'='1`
   - **Résultat** : tous les produits s'affichent
4. Tester le payload **Union-based** : `' UNION SELECT id, username, password, email, role FROM users -- `
   - **Résultat** : exfiltration des utilisateurs (IDs, mots de passe, emails)
5. Montrer la **requête SQL exécutée** affichée en debug

### Étape 2 — Vulnérabilité sur le login

1. Aller sur **projet vulnérable** → `login.php`
2. Saisir : `admin' --` (username) et n'importe quel mot de passe
3. **Résultat** : connexion sans mot de passe valide (bypass)

### Étape 3 — Protection sur le projet sécurisé

1. Ouvrir **projet sécurisé** → `login.php` → se connecter avec un compte valide
2. Aller sur **Recherche** (menu du dashboard)
3. Tester le même payload : `' OR '1'='1`
   - **Résultat** : page 403 « Requête bloquée »
4. Vérifier le **dashboard** : l’incident est enregistré
5. Faire une recherche légitime : `Bluetooth` → résultats normaux

---

## Tableau comparatif

| Fonctionnalité | projet_tutoré_inf (vulnérable) | mon-projet-security (sécurisé) |
|----------------|--------------------------------|-------------------------------|
| **Recherche** | SQL concaténé, payloads exploitables | Requêtes préparées, détection SQL + IA, blocage 403 |
| **Login** | SQL concaténé, bypass possible | CSRF, rate limiting, SecureDataGateway, Argon2ID |
| **Inscription** | SQL concaténé, rôle modifiable | Rate limiting, rôle forcé `user`, détection IA |
| **Blocage attaques** | Aucun | Détection + logs + page 403 |
| **Données sensibles** | Exposées (ex: mot de passe en clair) | Filtrées (pas de password_hash retourné) |
| **Badge visuel** | 🔴 DÉMO VULNÉRABLE | 🟢 PROTÉGÉ |

---

## Payloads de test (recherche)

| Payload | Type | Effet attendu (vulnérable) |
|---------|------|----------------------------|
| `' OR '1'='1` | Tautologie | Affiche tous les produits |
| `' UNION SELECT id, username, password, email, role FROM users -- ` | Union-based | Exfiltre la table users |
| `'; DROP TABLE products -- ` | Stacked | ⚠️ Peut supprimer la table |
| `' AND (SELECT SLEEP(5)) -- ` | Time-based | Délai de 5 secondes |
| `admin' --` | Login bypass | Connexion sans mot de passe |

---

## Produits de démo (identique dans les deux bases)

| Nom | Catégorie | Prix |
|-----|-----------|------|
| Smartphone Pro | Électronique | 899 € |
| Écouteurs Bluetooth | Électronique | 149 € |
| Laptop Ultra | Électronique | 1299 € |
| Montre Connectée | Électronique | 299 € |
| Clavier Mécanique | Accessoires | 89 € |
| Souris Ergo | Accessoires | 59 € |
| Webcam HD | Accessoires | 79 € |
| Chargeur Sans Fil | Accessoires | 45 € |

---

## Structure des dossiers

```
C:\wamp64\www\
├── projet_tutoré_inf\          # Projet VULNÉRABLE (démo)
│   ├── app\
│   │   ├── login.php
│   │   ├── search.php
│   │   └── inscription.php
│   └── database\
│       └── seed_products.sql
│
└── mon-projet-security\        # Projet SÉCURISÉ (référence)
    ├── public\
    │   ├── login.php
    │   ├── search.php
    │   └── inscription.php
    └── database\
        └── migrations\
            └── 2026_create_products_table.sql
```

---

## Avertissement

⚠️ **Le projet vulnérable ne doit JAMAIS être déployé en production.**  
Il est destiné uniquement à la démonstration pédagogique dans un environnement isolé.
