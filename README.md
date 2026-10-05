# CyberShield AI

MVP local de détection d’injections SQL développé dans le cadre des Journées Nationales de la Cybersécurité, à Bamako. Il combine un moteur heuristique PHP, un modèle MLP local pour les saisies ambiguës, un journal d’incidents structuré et un laboratoire sans exécution SQL.

## Démarrer avec Docker Desktop

Docker fournit une deuxième installation reproductible, séparée de Wamp. Depuis PowerShell dans le dossier du projet :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\init-docker.ps1
docker compose up --build -d
```

Ouvrir ensuite `http://127.0.0.1:8080/app/setup.php`, créer l’administrateur et enrôler son MFA. Apache est publié uniquement sur la boucle locale; MariaDB et le MLP n’ont aucun port hôte. Le premier démarrage entraîne l’artefact MLP à partir du jeu versionné inclus. Le mode par défaut est `monitor` pour commencer le pilote; après revue des événements et des entrées légitimes, `CYBERSHIELD_MODE=block` peut être choisi dans `.env`. Le schéma et le seed ne s’exécutent qu’à la création d’un volume de base vide.

La base, les journaux, les sessions et la file SIEM utilisent des volumes distincts. La clé MFA se trouve avec les journaux dans `cybershield-runtime`; sauvegarder cette clé et le volume de base ensemble. `docker compose down` conserve les données. `docker compose down -v` les supprime et doit être réservé à une remise à zéro voulue.

### Transfert vers un SIEM

L’envoi est facultatif. Configurer dans `.env` une URL HTTPS de collecte sans paramètre de requête, puis remplacer `secrets/siem_token.txt` par un jeton Bearer émis par le collecteur. Démarrer le transfert avec :

```powershell
docker compose -f compose.yaml -f compose.siem.yaml up --build -d
```

Seuls les événements bloqués, observés comme SQLi ou à examiner (score heuristique d’au moins 30) sont mis en file. L’exporteur est sur un réseau de sortie séparé et ne peut pas joindre la base ni le MLP. Les événements sont déjà expurgés ou empreintés avant la file. Les erreurs d’envoi sont reprises avec temporisation; les requêtes de l’application ne les attendent pas. La livraison est « au moins une fois » : le collecteur devrait dédupliquer l’en-tête `Idempotency-Key`. La file conserve au plus 10 000 événements; même si elle est indisponible ou pleine, le journal local demeure la référence.

### Mesurer le pilote

Le journal ne conserve pas les requêtes brutes, donc ses seules étiquettes ne peuvent pas révéler les attaques manquées. Construire une feuille d’échantillonnage, vérifier les événements avec une source indépendante ou des essais contrôlés, puis remplir `truth` avec `attack` ou `benign` :

```powershell
& .\.runtime\python\python.exe scripts\pilot_metrics.py --events logs\events.jsonl --template tmp\pilot-review.csv --limit 250
& .\.runtime\python\python.exe scripts\pilot_metrics.py --events logs\events.jsonl --labels tmp\pilot-review.csv --report tmp\pilot-metrics.json
```

Le rapport calcule précision, rappel, F1 et matrice de confusion uniquement sur les décisions SQLi étiquetées; il exclut les refus opérationnels tels que limite de débit ou taille de requête. Il ne mesure ni les événements non revus ni les attaques que l’équipe n’a pas indépendamment identifiées. Examiner un mélange de décisions bloquées/observées et d’autorisations, et garder l’évaluation du pilote distincte des scores des corpus publics.

Avec Docker, les journaux restent dans un volume privé. Téléchargez d’abord l’export JSONL depuis la console administrateur (`Journal des incidents` → `JSONL / SIEM`), puis remplacez `logs\events.jsonl` dans les commandes ci-dessus par le chemin du fichier téléchargé.

## Démarrer sur Windows avec Wamp

1. Vérifier que Wamp Apache et MySQL/MariaDB sont démarrés et que le PHP de Wamp charge `mysqli` et `curl`.
2. Depuis le dossier du projet, exécuter une fois `powershell -ExecutionPolicy Bypass -File .\scripts\install-python.ps1`. Le script télécharge Python 3.13.15 depuis python.org dans `.runtime`, vérifie son empreinte SHA-256 et n’ajoute rien au PATH système.
3. Configurer la base selon `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` et `DB_NAME` si les valeurs Wamp par défaut ne conviennent pas. Pour une nouvelle installation, importer `database/schema.sql`, puis `database/seed_products.sql`. Le schéma crée la base si elle manque. Le seed ajoute uniquement des produits fictifs et ne crée aucun compte partagé.
4. Depuis le navigateur ouvert sur la machine elle-même, aller sur `http://localhost/projet_tutor%C3%A9_inf/app/setup.php`. Créer l’administrateur propre à cette installation et activer le code TOTP dans une application d’authentification. Cette page est inaccessible depuis les autres machines.
5. Exécuter `powershell -ExecutionPolicy Bypass -File .\scripts\start-ai.ps1`. Ce script installe les dépendances épinglées si nécessaire, entraîne le MLP sur le partage public d’apprentissage inclus au premier lancement, puis démarre Waitress en arrière-plan uniquement sur `127.0.0.1:5000`.
6. Ouvrir `http://localhost/projet_tutor%C3%A9_inf/`.

La console propose la [supervision](security/dashboard.php), le [laboratoire SQLi](security/lab.php), la [gestion des adresses IP bloquées](security/ip-rules.php) et la [boutique pédagogique](app/search.php). Le laboratoire ne lance aucune requête SQL. La boutique simule le paiement, sans collecter de carte ni créer de commande réelle.

Les comptes ne sont plus créés avec des mots de passe connus. La première configuration crée un administrateur unique et impose MFA avant sa première session. Sur une ancienne base qui contient les comptes de démonstration publiés par une version antérieure, la configuration locale les désactive après la création réussie du nouvel administrateur.

## Vérifications

```powershell
# Règles, événements JSONL, CSRF et réponses de blocage
& 'C:\wamp64\bin\php\php8.4.15\php.exe' -n tests\security_test.php

# Tests d’intégration de la boutique et du contrôle d’accès IP. Crée une base aléatoire propre au test,
# puis ne supprime que cette base.
& 'C:\wamp64\bin\php\php8.4.15\php.exe' -d xdebug.mode=off tests\application_test.php

# Caractéristiques, intégrité des données, protocole et appel du véritable modèle
& .\.runtime\python\python.exe -m unittest discover -s ia -p 'test_*.py' -v

# Transfert SIEM et mesure du pilote
& .\.runtime\python\python.exe -m unittest tests.test_siem_forwarder tests.test_pilot_metrics -v

# Évaluer le modèle inchangé sur le jeu public indépendant (10 355 lignes)
& .\.runtime\python\python.exe ia\evaluate_external.py

# Évaluer le modèle sur la capture HTTP honeypot SR-BH 2020 (téléchargement 436 Mo)
$data = Join-Path $env:TEMP 'data_capec_multilabel.csv'
Invoke-WebRequest 'https://dataverse.harvard.edu/api/access/datafile/6319496' -OutFile $data
(Get-FileHash $data -Algorithm MD5).Hash # attendu : 173EC515308BDCE5AEC19CFD5B792596
& .\.runtime\python\python.exe ia\evaluate_honeypot.py --dataset $data

# Réentraîner sur le partage public d’apprentissage versionné
& .\.runtime\python\python.exe ia\train.py
Get-Content ia\models\training_report.json
```

Pour arrêter le service, exécuter `powershell -ExecutionPolicy Bypass -File .\scripts\stop-ai.ps1`. L’adresse de contrôle de santé est `http://127.0.0.1:5000/health`.

## Configuration

- `CYBERSHIELD_MODE=monitor` active le mode d’observation; toute autre valeur laisse le blocage actif.
- `CYBERSHIELD_LOG_DIR` choisit le dossier privé des journaux JSONL.
- `CYBERSHIELD_AI_URL` peut changer le port, mais l’URL reste limitée à une adresse HTTP de boucle locale.
- La clé de chiffrement des secrets TOTP est créée dans `CYBERSHIELD_LOG_DIR/admin-mfa.key`, hors du webroot. Sauvegardez-la séparément et de façon sécurisée avec la base; sans elle, les administrateurs ne pourront pas vérifier leurs codes. Après perte de la clé, l’opérateur doit supprimer la ligne MFA du compte dans `admin_mfa`, puis refaire l’enrôlement.
- Les réglages des seuils, tailles et limites se trouvent dans `config/security.php` et `config/ai.php`.
- La console refuse les accès réseau non locaux sans session administrateur active. Les dossiers de configuration, modèle, données, journaux et tests sont bloqués par Apache.
- Les événements bruts sont purgés après 90 jours, au premier passage de la journée. Un fichier séparé sert de verrou au traitement.
- La connexion limite à cinq les tentatives par identifiant et adresse IP sur 15 minutes. Les identifiants ne sont pas écrits en clair dans ce compteur.

## Installer le filtre dans une autre application PHP

Inclure `security/bootstrap.php` depuis le point d’entrée de chaque requête, avant toute sortie HTML ou réponse JSON :

```php
<?php
require_once '/chemin/prive/CyberShield-AI/security/bootstrap.php';
// Le code normal de l’application commence après le contrôle.
```

Le bootstrap applique le filtre et ne dépend pas de la boutique de démonstration ni de MySQL. Il lit les valeurs GET, POST, JSON et cookies, limite le débit et écrit ses événements dans `CYBERSHIELD_LOG_DIR`. Ne définissez `CYBERSHIELD_SKIP_REQUEST` que pour un point d’entrée volontairement exclu du contrôle. Gardez le dossier des journaux hors du webroot, activez HTTPS devant l’application et conservez les requêtes SQL préparées : CyberShield couvre les injections SQL, pas les autres contrôles de sécurité applicatifs.

## Conduire un pilote

Commencez avec `CYBERSHIELD_MODE=monitor` sur une copie représentative de l’application. Le bandeau de supervision indique maintenant explicitement que les décisions SQLi sont observées sans bloquer les requêtes; les règles d’accès IP, la limite de débit et les limites de taille continuent de s’appliquer. Examinez chaque jour les événements et les faux positifs avec les propriétaires des routes concernées. Les exports CSV et JSONL respectent les filtres actifs. Un transfert automatique facultatif vers un collecteur SIEM HTTPS est disponible avec l’overlay `compose.siem.yaml`; sans cet overlay, l’export reste manuel.

Avant de passer en mode blocage, testez les routes importantes avec leurs entrées légitimes et les corpus de régression, puis définissez un responsable d’astreinte et une procédure de retour en mode observation. Mesurez les faux positifs sur votre propre trafic : les scores des jeux publics ne prédisent pas ceux de votre application. Sauvegardez ensemble la base et la clé `admin-mfa.key`, et vérifiez la restauration avant une mise en service.

## État des fonctionnalités

Le MVP couvre uniquement les injections SQL. Les autres catégories (XSS, CSRF, LFI, configuration serveur et audit de mots de passe) restent des perspectives. Les mutations de la boutique utilisent un jeton CSRF; les lectures SQL passent par `SecureDataGateway` et `mysqli` avec paramètres liés. Le gateway `mysqli` est l’adaptation de l’architecture prévue en PDO au socle déjà présent.

La fonction de gestion d’accès IP du projet `mon-projet-security` a été intégrée à la console principale comme une liste de blocage IPv4/IPv6 à correspondance exacte. Les formulaires d’ajout et de suppression exigent un jeton CSRF; les règles sont stockées dans `CYBERSHIELD_LOG_DIR/blocked-ips.json` hors des pages publiques, et les refus sont consignés dans les événements de sécurité. La console locale et une session administrateur gardent un accès de secours pour corriger une règle. Les listes blanches et les plages CIDR ne sont pas activées : elles nécessiteraient une politique d’exploitation distincte.

Les identifiants, cookies de session, jetons CSRF, données de paiement et codes TOTP sont exclus de l’analyse MLP et masqués dans les journaux. Le second facteur administrateur utilise TOTP; sa clé est chiffrée avec AES-256-GCM et protégée par un fichier distinct du stockage SQL.

Le dossier de référence décrit un jeu validé de 10 000 requêtes et un F1 de 0,988, mais ces fichiers ne sont pas fournis et ces performances ne sont pas revendiquées. Le MLP livré est maintenant entraîné sur le partage d’apprentissage MIT de [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset), avec 20 105 valeurs `norm`/`sqli`; les valeurs normales dérivent de CSIC 2010 et les SQLi ont été générées avec sqlmap et d’autres corpus publics. Sur le partage de test séparé, il obtient F1 0,999170. Sur les 775 506 lignes normales ou SQLi de la capture observée [SR-BH 2020](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/OGOIXX), le MLP seul obtient F1 0,862153. Le middleware conserve les règles immédiates et envoie désormais les quatre premières valeurs non bloquées au MLP, même si aucune signature n’a correspondu ; le pipeline combiné obtient F1 0,860560 et rappel 0,856075, contre rappel 0,188869 avec l’ancienne présélection par règles seules. La précision de 0,865092 et la spécificité de 0,936372 montrent qu’il reste des faux positifs. La présélection a été choisie après diagnostic sur cette même capture : son score combiné est une mesure de développement, pas une validation indépendante. Ces résultats ne certifient pas une protection autonome en production. Les rapports, matrices de confusion, empreintes et limites sont consignés dans `ia/models/` et `ia/README.md`. Les requêtes préparées restent indispensables.

L’explication dans la console est un guide local déterministe, et non un assistant LLM. Les journaux ne conservent pas les saisies brutes : les valeurs signalées sont empreintées en SHA-256, et les paramètres identifiés comme mots de passe, jetons ou données de paiement sont entièrement masqués. Le filtre en amont complète les requêtes préparées et ne prouve jamais à lui seul qu’une valeur est bénigne.

## Stack

PHP de Wamp, MySQL ou MariaDB, Python 3.13 local, scikit-learn `MLPClassifier`, NumPy, Flask et Waitress. Les dépendances Python sont épinglées dans `ia/requirements.txt`. Apache n’expose ni le modèle ni les fichiers internes du projet.
