# Des événements réels pour la démonstration

Le script `scripts/generate-demo-traffic.ps1` envoie **six requêtes HTTP contrôlées**, uniquement à `127.0.0.1`. Le middleware prend les décisions et écrit lui-même les événements habituels. Le script ne remplit pas le journal avec des données fabriquées et ne supprime aucune trace existante.

Il s'agit de **données de test de démonstration**, pas d'attaques provenant de vrais clients ni d'une mesure des performances générales du modèle.

## Avant l'envoi

Depuis la racine du projet, Docker doit être démarré et les services `web`, `ai` et `db` disponibles. Pour vérifier le modèle et les scénarios sans produire de trafic HTTP ni écrire d'événement de sécurité :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\generate-demo-traffic.ps1 -PreflightOnly
```

Le précontrôle utilise le véritable `HybridAnalyzer` de cette installation, son modèle et ses seuils actuels. Si le modèle est indisponible, si un scénario cesse d'être reconnu ou si la source devient `fail_safe`, le script s'arrête. Un blocage de précaution n'est jamais présenté comme une décision du MLP.

Pour produire des réponses HTTP 403, le service `web` doit fonctionner avec `CYBERSHIELD_MODE=block`. En mode observation, le script refuse d'envoyer les six requêtes. Le script ne modifie pas la configuration du site.

## Envoyer les six requêtes

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\generate-demo-traffic.ps1
```

Si le port local a changé, préciser par exemple `-Port 8081`. Une adresse distante ne peut pas être fournie au script.

Le scénario comprend une recherche ordinaire « casque », deux signatures explicites (condition booléenne et `UNION SELECT`), puis trois saisies ambiguës confirmées par le MLP : `admin'-- `, `information_schema.tables` et `SELECT name FROM users`. Ces valeurs sont envoyées comme paramètres de recherche. Le script n'exécute aucune instruction SQL et les signatures bloquées sont arrêtées avant l'application.

À chaque lancement, le risque MLP est mesuré de nouveau. Il n'est pas remplacé par un nombre prédéfini. Un score MLP est un score du modèle, pas la probabilité garantie qu'un client est malveillant.

Les six appels sont séquentiels, sans authentification, sans cookies et sans suivi des redirections. Le script n'effectue aucune création de compte, commande ou paiement. Le marqueur de requête `cybershield_demo` identifie le lancement côté client ; les chaînes de requête restent exclues du journal de sécurité habituel.

## Vérifier devant le jury

Ouvrir `http://127.0.0.1:8080/security/dashboard.php` avec le compte administrateur, puis actualiser. Les trois événements MLP doivent porter l'action `BLOCKED_BY_AI`, la source `mlp`, le modèle effectivement utilisé et un risque au-dessus du seuil de 0,75. Les deux autres blocages portent la source `heuristic` et l'action `BLOCKED`.

Le script rapproche chaque réponse HTTP avec son événement par `X-CyberShield-Request-ID`. Pour les réponses bloquées, il vérifie aussi la référence `incident_id` du corps JSON. Le rapport horodaté `tmp/demo-traffic-<identifiant>.json` contient les six références, statuts HTTP, scores et événements relus. Il ne contient aucune clé, aucun identifiant de session et aucune donnée de client.

Le résultat attendu d'un lancement réussi est **1 requête autorisée, 2 requêtes bloquées par les règles et 3 requêtes bloquées par le MLP**. Il s'ajoute aux événements existants : le total du tableau de bord peut donc être plus grand. Relancer le script crée six événements supplémentaires ; il n'efface pas les précédents.

Le blocage d'un téléphone par son adresse IP constitue un scénario distinct. Utiliser le navigateur du téléphone sur le même réseau local, puis choisir l'adresse observée par le système dans la page d'accès par IP. Ne pas utiliser l'adresse du PC ou celle d'une passerelle partagée pour représenter le téléphone.
