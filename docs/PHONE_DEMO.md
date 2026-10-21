# Démonstration avec un téléphone sur le réseau local

Le téléphone ouvre la boutique et produit ses propres requêtes HTTP. La console du PC permet de consulter les événements puis de bloquer l’adresse du téléphone. Les décisions affichées proviennent du filtre réellement exécuté ; une annotation de triage ne change pas ces décisions.

## Préparer l’accès

Connecter le PC et le téléphone au même réseau Wi-Fi. Le partage de connexion du téléphone convient aussi : dans ce cas, le PC rejoint son point d’accès et le partage doit rester actif. Éviter un réseau invité qui isole les appareils.

Depuis PowerShell, à la racine du projet :

```powershell
docker compose up -d --build
powershell -ExecutionPolicy Bypass -File .\scripts\start-phone-demo.ps1
```

Le script affiche l’adresse exacte à saisir sur le téléphone. Elle se termine par `:8082/app/client-ip.php`. Par exemple, si l’adresse affichée est `http://192.168.1.20:8082/app/client-ip.php`, saisir cette adresse complète dans le navigateur du téléphone. `127.0.0.1` sur le téléphone désigne le téléphone lui-même et ne permet pas de joindre le PC.

Le script de démarrage active le mode blocage et lance le relais. Si le pare-feu empêche le téléphone de se connecter, ouvrir un PowerShell administrateur, revenir à la racine du projet et exécuter :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\phone-demo-firewall.ps1
```

La règle de démonstration est limitée au port prévu, à l’interface choisie et au sous-réseau local. Aucun accès Internet public n’est nécessaire. L’accès HTTP prévu ici convient à cet essai local : ne pas y saisir de données sensibles. Si plusieurs interfaces sont actives, préciser l’adresse du PC avec `start-phone-demo.ps1 -ListenAddress 192.168.1.20` en remplaçant cette adresse d’exemple par celle du Wi-Fi partagé.

## Montrer un blocage par adresse IP

1. Sur le téléphone, ouvrir la page affichée par le script. Noter l’adresse reconnue, puis ouvrir le catalogue. Une adresse commençant par `172.` peut être celle du partage de connexion : utiliser exactement l’adresse affichée pour ce téléphone, sans la confondre avec la passerelle interne Docker.
2. Sur le PC, ouvrir [la supervision](http://127.0.0.1:8080/security/dashboard.php), actualiser et ouvrir les détails du nouvel événement. Vérifier que l’adresse correspond à celle affichée sur le téléphone.
3. Sur le PC, ouvrir [Accès par IP](http://127.0.0.1:8080/security/ip-rules.php), ajouter **cette adresse du téléphone uniquement** à la liste de blocage et indiquer un motif clair, par exemple « Essai JNC — téléphone ».
4. Actualiser la boutique sur le téléphone. La nouvelle requête doit recevoir un refus HTTP 403. Revenir au journal sur le PC : l’événement indique un blocage par la politique d’accès IP. Ce blocage reste distinct d’un blocage SQLi par les règles ou par le modèle MLP.
5. Retirer la règle et actualiser le téléphone. L’accès est rétabli. Garder la console ouverte sur le PC pendant toute la séquence.

Le blocage agit sur l’adresse réseau. Si plusieurs personnes partagent la même adresse de sortie, elles peuvent être affectées ensemble. Pour cette démonstration sur un même Wi-Fi, utiliser l’adresse locale propre au téléphone et éviter VPN et relais réseau.

## Arrêter l’accès au téléphone

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop-phone-demo.ps1
```

L’arrêt de l’accès LAN ne nécessite ni suppression de volume ni réinitialisation de la base. Il remet le profil Docker habituel ; passer `-KeepBlockMode` pour conserver explicitement le blocage SQLi. Supprimer aussi la règle de blocage du téléphone si elle n’est plus utile. L’accès habituel depuis le PC reste `http://127.0.0.1:8080/`. Si le retrait de la règle de pare-feu demande des droits administrateur, utiliser `phone-demo-firewall.ps1 -Action Close` depuis un PowerShell administrateur avant l’arrêt, ou suivre l’avertissement affiché.

## En cas de difficulté

**La page ne s’ouvre pas sur le téléphone.** Vérifier l’URL affichée, le Wi-Fi commun, l’absence d’isolation des clients sur le routeur et la règle de pare-feu Windows. Si le PC a changé de réseau ou d’adresse, arrêter puis relancer le script pour obtenir la bonne URL.

**Le journal affiche l’adresse de Docker.** Vérifier que le téléphone utilise bien le port `8082` du relais lancé par le script, puis que le service web a été recréé avec `compose.phone-demo.yaml`. Ne pas ajouter une confiance générale envers `X-Forwarded-For` ni envers toutes les adresses privées.

**Une identité de relais invalide est refusée.** Le PC et le conteneur doivent partager une heure correcte. Le relais signe l’adresse, l’horodatage, la méthode et l’URI exacte avec un secret local. Une signature incorrecte ou vieille de plus de 30 secondes est refusée. Relancer les scripts permet de recharger leur configuration ; ne pas publier le fichier de clé dans un message ou une capture.

**La console est réservée sur le téléphone.** C’est prévu : l’accès par le relais ne donne jamais les droits de la machine locale. Effectuer l’administration depuis le PC ou avec un compte administrateur authentifié.

## Identité réseau et vérifications techniques

Docker Desktop peut présenter au conteneur l’adresse de sa passerelle plutôt que celle du téléphone. Le relais Windows transmet donc une identité signée par HMAC SHA-256. Le service web accepte cette identité uniquement si la fonction est activée, si le pair réseau est explicitement autorisé et si la signature est valide. Les en-têtes `Forwarded` et `X-Forwarded-For` ordinaires ne sont jamais une preuve d’identité.

La clé privée du relais reste dans `docker-secrets/lan_proxy_key.txt` côté PC et est montée en lecture seule dans `/run/secrets/lan_proxy_key` côté web. Elle ne figure ni dans une URL ni dans la page client. Le relais remplace les en-têtes réservés reçus du navigateur avant d’ajouter les siens.

Le contrat de signature est `v1`, IP canonique, horodatage Unix, méthode HTTP et URI brute, séparés par des sauts de ligne. Les en-têtes sont `X-CyberShield-Client-IP`, `X-CyberShield-Timestamp` et `X-CyberShield-Signature`. Toute présence de ces en-têtes avec une configuration, une source ou une signature invalide entraîne un refus ; le serveur ne revient pas aux droits locaux de la passerelle.

Les contrôles unitaires utilisent une clé factice temporaire :

```powershell
php .\tests\client_identity_test.php
```

Ils vérifient notamment les signatures altérées, les expirations, les IP IPv4 et IPv6, l’absence de confiance dans les en-têtes ordinaires et le refus d’une confiance étendue à un sous-réseau Docker.
