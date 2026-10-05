# CyberShield AI

MVP local de détection d’injections SQL développé dans le cadre des Journées Nationales de la Cybersécurité, à Bamako. Il combine un moteur heuristique PHP, un modèle MLP local pour les saisies ambiguës, un journal d’incidents structuré et un laboratoire sans exécution SQL.

## Démarrer sur Windows avec Wamp

1. Vérifier que Wamp Apache et MySQL/MariaDB sont démarrés et que le PHP de Wamp charge `mysqli` et `curl`.
2. Depuis le dossier du projet, exécuter une fois `powershell -ExecutionPolicy Bypass -File .\scripts\install-python.ps1`. Le script télécharge Python 3.13.15 depuis python.org dans `.runtime`, vérifie son empreinte SHA-256 et n’ajoute rien au PATH système.
3. Configurer la base selon `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` et `DB_NAME` si les valeurs Wamp par défaut ne conviennent pas. Pour une nouvelle installation, importer `database/schema.sql`, puis `database/seed_products.sql`. Le schéma crée la base si elle manque. Le seed insère les exemples uniquement s’ils sont absents et ne supprime aucun produit ni compte.
4. Exécuter `powershell -ExecutionPolicy Bypass -File .\scripts\start-ai.ps1`. Ce script installe les dépendances épinglées si nécessaire, entraîne le MLP synthétique au premier lancement, puis démarre Waitress en arrière-plan uniquement sur `127.0.0.1:5000`.
5. Ouvrir `http://localhost/projet_tutor%C3%A9_inf/`.

La console propose la [supervision](security/dashboard.php), le [laboratoire SQLi](security/lab.php) et la [boutique pédagogique](app/search.php). Le laboratoire ne lance aucune requête SQL. La boutique simule le paiement, sans collecter de carte ni créer de commande réelle.

Les identifiants de démonstration, ajoutés uniquement sur une nouvelle base, sont `cybershield_admin` / `CyberShieldDemo!2026` et `cybershield_client` / `DemoClient!2026`. Une base déjà présente n’est jamais modifiée par le seed. La simulation d’achat est disponible aux deux comptes; l’option administrateur sans étape de paiement simulée est réservée au rôle administrateur.

## Vérifications

```powershell
# Règles, événements JSONL, CSRF et réponses de blocage
& 'C:\wamp64\bin\php\php8.4.15\php.exe' -n tests\security_test.php

# Test d’intégration de la boutique. Crée une base aléatoire propre au test,
# puis ne supprime que cette base.
& 'C:\wamp64\bin\php\php8.4.15\php.exe' -d xdebug.mode=off tests\application_test.php

# Caractéristiques, intégrité des données, protocole et appel du véritable modèle
& .\.runtime\python\python.exe -m unittest discover -s ia -p 'test_*.py' -v

# Évaluer le modèle inchangé sur le jeu public indépendant (10 355 lignes)
& .\.runtime\python\python.exe ia\evaluate_external.py

# Évaluer le modèle sur la capture HTTP honeypot SR-BH 2020 (téléchargement 436 Mo)
$data = Join-Path $env:TEMP 'data_capec_multilabel.csv'
Invoke-WebRequest 'https://dataverse.harvard.edu/api/access/datafile/6319496' -OutFile $data
(Get-FileHash $data -Algorithm MD5).Hash # attendu : 173EC515308BDCE5AEC19CFD5B792596
& .\.runtime\python\python.exe ia\evaluate_honeypot.py --dataset $data

# Réentraîner et consulter les métriques générées sur la validation synthétique
& .\.runtime\python\python.exe ia\train.py
Get-Content ia\models\training_report.json
```

Pour arrêter le service, exécuter `powershell -ExecutionPolicy Bypass -File .\scripts\stop-ai.ps1`. L’adresse de contrôle de santé est `http://127.0.0.1:5000/health`.

## Configuration

- `CYBERSHIELD_MODE=monitor` active le mode d’observation; toute autre valeur laisse le blocage actif.
- `CYBERSHIELD_LOG_DIR` choisit le dossier privé des journaux JSONL.
- `CYBERSHIELD_AI_URL` peut changer le port, mais l’URL reste limitée à une adresse HTTP de boucle locale.
- Les réglages des seuils, tailles et limites se trouvent dans `config/security.php` et `config/ai.php`.
- La console refuse les accès réseau non locaux sans session administrateur active. Les dossiers de configuration, modèle, données, journaux et tests sont bloqués par Apache.
- Les événements bruts sont purgés après 90 jours, au premier passage de la journée. Un fichier séparé sert de verrou au traitement.

## État des fonctionnalités

Le MVP couvre uniquement les injections SQL. Les autres catégories (XSS, CSRF, LFI, configuration serveur et audit de mots de passe) restent des perspectives. Les mutations de la boutique utilisent un jeton CSRF; les lectures SQL passent par `SecureDataGateway` et `mysqli` avec paramètres liés. Le gateway `mysqli` est l’adaptation de l’architecture prévue en PDO au socle déjà présent.

Le dossier de référence décrit un jeu validé de 10 000 requêtes et un F1 de 0,988. Ces fichiers de modèle et de données d’origine ne sont pas dans ce dépôt et ces performances ne sont pas revendiquées. Le **MLP réel** de structure 128→64→32 est entraîné sur un corpus synthétique de démonstration; il obtient F1 0,950820 sur 128 lignes synthétiques réservées. Sur le jeu public [HttpParamsDataset](https://github.com/Morzeux/HttpParamsDataset), il obtient F1 0,965843 sur 10 051 valeurs `norm`/`sqli` du test. Sur la capture [SR-BH 2020](https://dataverse.harvard.edu/dataset.xhtml?persistentId=doi:10.7910/DVN/OGOIXX), 907 815 requêtes observées sur un honeypot WordPress, le MLP seul obtient F1 0,492487 et rappel 0,330601 sur 775 506 requêtes annotées normales ou SQLi. Le middleware analyse désormais aussi le chemin URL; un test HTTP vérifie le blocage d'une SQLi dans ce chemin. Les rapports reproductibles se trouvent dans `ia/models/`. Le rappel observé montre que le MLP ne peut pas servir seul de protection de production; les requêtes préparées et les règles heuristiques restent indispensables.

L’explication dans la console est un guide local déterministe, et non un assistant LLM. Les journaux ne conservent pas les saisies brutes : les valeurs signalées sont empreintées en SHA-256, et les paramètres identifiés comme mots de passe, jetons ou données de paiement sont entièrement masqués. Le filtre en amont complète les requêtes préparées et ne prouve jamais à lui seul qu’une valeur est bénigne.

## Stack

PHP de Wamp, MySQL ou MariaDB, Python 3.13 local, scikit-learn `MLPClassifier`, NumPy, Flask et Waitress. Les dépendances Python sont épinglées dans `ia/requirements.txt`. Apache n’expose ni le modèle ni les fichiers internes du projet.
