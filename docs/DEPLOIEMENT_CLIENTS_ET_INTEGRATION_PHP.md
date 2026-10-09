# Déploiement indépendant chez plusieurs clients

## Architecture prise en charge

La version actuelle est **mono-client par installation**. Elle ne contient ni comptes de tenants ni serveur SaaS partagé. Pour deux clients, déployer deux instances CyberShield séparées : chacune possède son propre projet Compose, sa base, ses journaux, ses comptes administrateurs, ses secrets, ses sauvegardes et son adresse d'accès. Ne partagez jamais un `.env`, un dossier `secrets/`, un volume de journaux ou un volume de base entre clients.

Les noms de projet Compose isolent les réseaux, conteneurs et volumes nommés, mais ne séparent pas à eux seuls les fichiers locaux référencés par Compose. Il faut donc une copie de déploiement distincte par client, avec son propre `.env` et son propre `secrets/`. La même copie du modèle public Ollama peut être montée en lecture seule sur un même serveur; cela ne partage ni les requêtes ni les journaux.

```text
Client A : site PHP A ── filtre PHP A ── MLP A ── journaux A / console A
Client B : site PHP B ── filtre PHP B ── MLP B ── journaux B / console B
```

## Préparer les installations

Le générateur crée pour chaque client un paquet minimal issu de la version du dépôt, avec `.env` non secret, port réservé à la boucle locale et nom Compose préconfiguré. Il ignore les fichiers secrets, journaux, modèles locaux et données de développement du poste source. Exécutez-le séparément pour chaque identifiant et destination :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\new-client-deployment.ps1 -ClientId client-a -Destination C:\CyberShield\client-a -Port 8081
powershell -ExecutionPolicy Bypass -File .\scripts\new-client-deployment.ps1 -ClientId client-b -Destination C:\CyberShield\client-b -Port 8082
```

L'identifiant accepte jusqu'à 31 lettres minuscules, chiffres, tirets ou soulignements; la destination doit être absente et hors du dossier source; le port doit être libre lors de la préparation. Le script refuse d'écraser une destination. Il compose d'abord dans un dossier temporaire et finalise par déplacement atomique.

Remettez chaque dossier généré au client par le canal approuvé, puis, sur son hôte Windows avec Docker Desktop, ouvrez PowerShell dans le dossier et lancez :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\init-docker.ps1
docker compose --project-name cybershield-client-a up --build -d
```

Pour la seconde copie, utilisez son nom Compose et son port respectifs. `init-docker.ps1` crée les secrets propres à chaque installation sur l'hôte du client et applique des ACL au dossier secrets; ne copiez jamais les secrets du poste de développement. Garder `APP_BIND_ADDRESS=127.0.0.1`; ouvrir `app/setup.php` localement, créer un compte administrateur distinct et enrôler son MFA. Commencer avec `CYBERSHIELD_MODE=monitor`, mettre TLS et authentification en place devant tout accès distant, puis examiner les faux positifs avec le client avant d'envisager `block`.

Vérifier les deux URL, l'état des services, la séparation des volumes, les exports et une restauration. Le dossier généré contient aussi `DEPLOYMENT.md`, qui reprend les paramètres et commandes adaptés au client.

Les volumes nommés sont préfixés par le nom de projet Compose, ce qui sépare base, journaux, sessions et file SIEM dans ces deux copies. Sur un même hôte, chaque port applicatif doit rester privé derrière le reverse proxy; stocker également les deux répertoires sur un disque chiffré avec des ACL distinctes si des administrateurs différents les gèrent. Le modèle d'IA ne reçoit pas les données des sites; la connexion au MLP reste sur `127.0.0.1` ou un réseau Docker interne.

## Brancher une application PHP existante

CyberShield s'intègre au niveau PHP : il examine les valeurs de requête avant que l'application ne les utilise. Il faut disposer du code PHP ou de son point d'entrée; ce n'est pas un proxy réseau générique et il ne protège pas directement une application Node.js, Java ou un serveur où l'on ne peut pas charger le middleware.

Dans le point d'entrée PHP le plus tôt possible, avant toute sortie HTML et avant les traitements de route, inclure le bootstrap depuis l'installation privée :

```php
<?php
require_once '/opt/cybershield/security/bootstrap.php';
// Puis charger le framework / routeur de l'application cliente.
```

Le même dossier CyberShield doit conserver ensemble `security/`, `config/` et le service `ia/` attendu. L'extension cURL doit être activée dans PHP. Fournir à PHP les variables d'environnement depuis la configuration du serveur, jamais depuis une requête HTTP :

```text
CYBERSHIELD_MODE=monitor
CYBERSHIELD_AI_URL=http://127.0.0.1:5000
CYBERSHIELD_LOG_DIR=/var/lib/cybershield/client-a/logs
```

Le processus Python MLP doit écouter uniquement sur `127.0.0.1:5000` lorsque PHP tourne directement sur le même hôte. Dans un déploiement conteneurisé, joindre le service PHP et le service nommé `ai` au même réseau privé interne, puis utiliser `CYBERSHIELD_CONTAINERIZED=1` et `CYBERSHIELD_AI_URL=http://ai:5000`; ne pas publier le port du MLP. Attribuer le répertoire de journaux à l'utilisateur du processus PHP avec un accès privé et le sauvegarder séparément pour chaque client.

Les chemins `security/bootstrap.php`, `middleware.php`, `hybrid_analyzer.php`, `detector.php`, `ia_analyzer.php`, `logger.php`, `response_handler.php`, `ip_access.php`, `config/security.php`, `config/ai.php` et le service MLP doivent provenir de la même version CyberShield. Le middleware traite le chemin, GET, POST, les cookies et JSON; n'ajoutez pas de second filtre qui exécuterait ou modifierait ces valeurs avant l'inclusion.

Après branchement, conserver le mode observation pendant une période convenue, utiliser une copie ou un environnement de test autorisé, vérifier les erreurs PHP et la latence, faire examiner les alertes par le client et tester les routes légitimes comme les routes sensibles. Les requêtes préparées, l'autorisation applicative, CSRF et les autres contrôles restent indispensables. Le middleware ne remplace pas un audit du code.

## Relier les alertes au SIEM du client

Une instance peut transférer un sous-ensemble d'événements expurgés vers le collecteur du client avec `compose.siem.yaml`. Configurer une URL HTTPS et un jeton émis pour **ce seul client**, puis démarrer cette instance avec l'overlay SIEM décrit dans le README. La file et les secrets ont leurs propres volumes/fichiers dans la copie du client. Le transfert est au moins une fois : le collecteur doit traiter l'en-tête `Idempotency-Key` de façon idempotente. Le journal local reste la source de repli.

## Limites à lever avant une offre de service

- Le générateur prépare une copie autonome Docker et ses paramètres, mais n'installe pas le middleware dans le code d'une application PHP tierce, ne configure pas le reverse proxy du client et ne vérifie pas sa compatibilité. Ces opérations demandent l'accès au code et un pilote convenu avec le client.
- L'authentification de la console est liée au compte administrateur de l'application CyberShield. L'adaptation à l'identité (SSO/OIDC ou RBAC) propre au système du client n'est pas incluse.
- L'affichage des événements du site exige que sa console et le middleware lisent le même stockage privé; une instance qui n'a pas ce stockage commun ne voit pas les journaux de l'autre.
- Le mode proxy/WAF pour les applications non PHP, le plan de contrôle multi-tenant et la facturation par client ne sont pas implémentés.
- Aucun accord standard de licence, de support, de mise à jour ou de traitement des journaux n'est fourni. Définir ces responsabilités et les droits de redistribution avant toute remise commerciale.

Avant d'annoncer une compatibilité client, réaliser une installation propre sur une copie de leur application, définir les rôles d'administration, les sauvegardes et la rétention, convenir d'un plan de déploiement/retour arrière, puis obtenir l'autorisation écrite pour le pilote. Un déploiement client ne doit jamais commencer en mode blocage sans revue préalable.
