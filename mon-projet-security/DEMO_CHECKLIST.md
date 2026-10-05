# Phase 4 — Checklist de vérification

Cochez chaque élément après l'avoir testé.

---

## Avant la démo

### Bases de données

- [ ] Base `projet_sqli_vulnerable` existe
- [ ] Script `projet_tutoré_inf/database/seed_products.sql` exécuté
- [ ] Table `products` créée avec 8 produits
- [ ] Base `mon_projet_securite` existe
- [ ] Script `mon-projet-security/database/migrations/2026_create_products_table.sql` exécuté
- [ ] Table `products` créée avec 8 produits

### Comptes de test

- [ ] Compte vulnérable : créé via `inscription.php` (ex: `demo` / `demo123`)
- [ ] Compte sécurisé : créé via `inscription.php`

---

## Tests projet vulnérable (projet_tutoré_inf)

| Test | Résultat attendu | ✓ |
|------|------------------|---|
| Login normal | Connexion réussie | |
| Login avec `admin' --` | Bypass mot de passe (connexion) | |
| Recherche `Bluetooth` | Affiche Écouteurs Bluetooth | |
| Recherche `' OR '1'='1` | Affiche tous les produits | |
| Recherche Union payload | Exfiltre la table users | |
| Bandeau rouge visible | « DÉMO VULNÉRABLE » en haut | |

---

## Tests projet sécurisé (mon-projet-security)

| Test | Résultat attendu | ✓ |
|------|------------------|---|
| Login normal | Connexion réussie | |
| Recherche `Bluetooth` | Affiche Écouteurs Bluetooth | |
| Recherche `' OR '1'='1` | Page 403 « Requête bloquée » | |
| Recherche Union payload | Page 403 « Requête bloquée » | |
| Dashboard après blocage | Incident enregistré dans la liste | |
| Bandeau vert visible | « PROTÉGÉ » en haut | |

---

## Vérification syntaxe PHP (optionnel)

```powershell
php -l chemin/vers/fichier.php
```

**mon-projet-security** : login.php, search.php, inscription.php → ✅ Pas d'erreur de syntaxe

---

## URLs à précharger (onglets)

1. `http://localhost/projet_tutoré_inf/app/search.php`
2. `http://localhost/mon-projet-security/public/login.php`
3. `http://localhost/mon-projet-security/public/search.php` (après connexion)

*Ajuster selon votre configuration (port, chemin).*
