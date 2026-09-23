DÉMO VULNÉRABLE - projet_tutoré_inf
===================================

Ce projet est intentionnellement VULNÉRABLE pour la démonstration des attaques SQL Injection.

⚠️ NE JAMAIS utiliser en production !

---

SCÉNARIO DÉMO (e-commerce + SQLi)
--------------------------------

1. Recherche
   - Aller sur app/search.php
   - Rechercher un produit (ex. "clavier"), ajouter au panier

2. Panier
   - app/panier.php : voir les articles, cliquer "Valider la commande"
   - Redirection vers la page de connexion avec redirect=paiement

3. Connexion SQLi (bypass authentification)
   - app/login.php
   - Payloads à utiliser (dans nom d'utilisateur ou mot de passe) :
     · ' OR '1'='1'-- 
     · ' OR 1=1#
     · admin' -- 
   - Après connexion : redirection vers paiement.php (si redirect=paiement)

4. Paiement
   - Connecté : récapitulatif, formulaire carte (simulé)
   - Si rôle admin (ex. connecté avec admin' --) : bloc "Valider sans payer" + option paiement simulé
   - Après validation : redirection panier.php?validated=1, message "Commande validée"

5. Dashboard
   - app/dashboard.php (après connexion) : profil, activités, thème clair/sombre
   - Si admin : section "Recherche Admin" (SQLi sur users), débogage requêtes SQL

---

DONNÉES DE TEST
---------------

Base : projet_sqli_vulnerable (config.php)
Tables : users, products, user_logs (optionnel)

Exécuter les scripts SQL de création/seed si besoin (ex. database/ ou seed_products.sql).

---

GUIDE COMPLET
-------------

Pour la concordance avec le projet sécurisé (mon-projet-security) :
→ Voir : mon-projet-security/DEMO_CONCORDANCE.md (si présent)
