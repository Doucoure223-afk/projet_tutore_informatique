# Assistant de triage local avec LangGraph

## Rôle

L'assistant est une fonction facultative de la console administrateur. Il répond en français aux questions sur le mode du filtre et sur des compteurs ou événements récents. Il n'intervient jamais dans la décision SQLi, qui reste portée par les règles PHP et le MLP.

Les salutations, l'aide, le bilan des compteurs, le mode du filtre et l'explication d'une alerte sélectionnée ont une voie locale déterministe. Ces réponses utilisent uniquement les valeurs assainies transmises par PHP et ne lancent jamais Ollama. Elles restent disponibles pendant une inférence LLM. L'API les identifie avec `source: local` et `kind` ; l'interface ne doit pas les présenter comme du texte généré par le modèle. La reconnaissance est restrictive : une question libre qui contient simplement le mot « bilan » reste une demande au modèle.

Exemples exacts : « Bonjour », « Que peux-tu faire ? », « Fais le bilan de la supervision », « Quel est le mode de protection ? » et « Explique cette alerte ». Les formulations non reconnues passent au graphe LangGraph, volontairement simple et vérifiable :

1. `prepare` limite et assainit la question, conserve les compteurs et les métadonnées d'une règle sélectionnée, puis regroupe l'échantillon de huit événements au maximum par type/action/source (effectif et score maximal, sans dates ni latences). `recent_sample` reste explicitement un échantillon, distinct des compteurs totaux de la période;
2. `answer` appelle l'API Chat d'Ollama sur le modèle local configuré;
3. `validate` supprime les caractères de contrôle et borne la réponse;
4. le graphe se termine sans mémoire conversationnelle ni outil d'action.

Le service ne possède aucun connecteur de base de données, outil SQL, outil shell ni fonction de blocage ou de modification de configuration. Il ne lit aucun fichier de journal. PHP calcule localement les compteurs et lui envoie seulement un libellé de page fixe, des catégories en liste blanche, des horodatages, des scores bornés et l'état de quelques fonctions. Les IP, chemins, valeurs des formulaires et payloads des journaux ne sont pas ajoutés au contexte. Le texte de la question est toutefois transmis au modèle local; des secrets courants et numéros de carte sont expurgés, mais ne saisir aucune donnée confidentielle.

Le modèle peut produire des erreurs ou suivre imparfaitement les consignes. Une réponse n'est ni une décision de sécurité ni un audit. L'administrateur doit vérifier tout conseil dans le code et les journaux autorisés. Le modèle est distinct du MLP et son exactitude sur des questions de sécurité n'a pas encore été évaluée.

La génération locale sur CPU n'est pas instantanée. Le service borne une tentative à 10 secondes par défaut (`CYBERSHIELD_ASSISTANT_TIMEOUT_SECONDS`, valeur limitée entre 2 et 20 secondes) et ferme la connexion Ollama au dépassement. Il renvoie alors `504 assistant_timeout`, jamais une réponse inventée. Une seule inférence ou opération de préchargement peut tourner à la fois ; les demandes concurrentes sont refusées immédiatement, sans file d'attente. Le verrou n'est relâché qu'une fois le travail réellement terminé, même après une expiration côté client. Les réponses rapides restent indépendantes de ce verrou. Aucun historique ou cache de conversation n'est conservé.

## Installation locale avec Wamp

Pré-requis : Ollama pour Windows, Python du projet installé sous `.runtime` par `scripts/install-python.ps1`, PHP cURL activé, compte administrateur déjà configuré et MFA enrôlé. Installer le modèle explicitement :

```powershell
ollama pull llama3.2:latest
powershell -ExecutionPolicy Bypass -File .\scripts\start-assistant.ps1
```

Depuis la console authentifiée, cliquer sur « Poser une question » dans la supervision, le laboratoire ou les règles IP, ou ouvrir la page complète `security/assistant.php`. L'URL locale habituelle est `http://localhost/projet_tutor%C3%A9_inf/security/assistant.php`. Le panneau envoie le contexte sûr de la page (un libellé fixe autorisé et les mêmes compteurs expurgés); il ne transmet aucun champ de formulaire de la page. Le service Python écoute uniquement sur `127.0.0.1:5100`, séparément de l'API MLP sur le port 5000.

Le modèle par défaut est `llama3.2:latest`, choisi pour réduire la latence sur CPU. Qwen 7B reste disponible pour privilégier la qualité : télécharge-le avec `ollama pull qwen2.5:7b-instruct`, puis lance `powershell -ExecutionPolicy Bypass -File .\scripts\start-assistant.ps1 -Model qwen2.5:7b-instruct`. Pour arrêter le processus local :

Dans Docker, après `scripts/init-docker.ps1`, le modèle léger est configuré par défaut. Le réglage peut être modifié dans `.env` avec `CYBERSHIELD_ASSISTANT_MODEL=qwen2.5:7b-instruct` pour privilégier la qualité, puis en recréant le service assistant.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop-assistant.ps1
```

Le script de démarrage vérifie la présence d'Ollama, du modèle et des versions épinglées de Flask, Waitress et LangGraph. Il n'installe pas ni ne télécharge le modèle automatiquement. Les journaux techniques de démarrage vont dans `%TEMP%\cybershield-assistant`; les questions et réponses ne sont pas écrites dans ces journaux.

## Option Docker

Installer Ollama sur l'hôte, télécharger le modèle puis initialiser le dossier et le jeton local :

```powershell
ollama pull llama3.2:latest
powershell -ExecutionPolicy Bypass -File .\scripts\init-docker.ps1
docker compose --profile assistant up --build -d
```

Le script initialise `OLLAMA_MODELS_PATH` dans `.env` avec `%USERPROFILE%\.ollama\models`, ou avec le chemin défini par `OLLAMA_MODELS`. Si Ollama a été configuré vers un autre cache, vérifier cette variable dans `.env` avant le démarrage. Ollama et l'assistant sont isolés du MLP et de la base sur un réseau Docker interne dédié; seul le service web rejoint ce réseau et celui du MLP. Le cache est monté en lecture seule et aucun service du profil n'a de route de sortie Internet. Les images et bibliothèques nécessaires doivent être téléchargées pendant la construction initiale. Un modèle absent ne sera jamais récupéré en tâche de fond.

La clef d'API aléatoire de 48 octets est créée dans `secrets/assistant_token.txt`; elle est partagée entre PHP et le service via un secret Docker. Ne la committer ni ne la communiquer. `docker compose down` conserve le modèle et les données; `docker compose down -v` supprime les volumes persistants de la base et de l'application.

## Contrat API interne

- `GET /health` répond immédiatement avec la disponibilité du service (`service_available`) et un cache de métadonnées : modèle installé (`model_installed`, inventaire `/api/tags`) et résident en mémoire (`model_loaded`, inventaire `/api/ps`). Une valeur `null` signifie « inconnu », et non « absent ». `inventory_checked`, `inventory_age_seconds` et `inventory_refreshing` indiquent l'état de cette vérification. L'ancien champ `model_ready` signifie désormais « chargé ». Le handler ne contacte jamais Ollama : un seul daemon de rafraîchissement est autorisé, avec une durée de validité de cinq secondes et deux secondes maximum par endpoint d'inventaire. Aucun appel d'inférence n'est lancé. Le service renvoie 200 si son jeton est disponible, même si Ollama ou le modèle sont absents : les réponses locales restent utilisables. Un jeton manquant renvoie 503.
- `POST /chat` exige `Authorization: Bearer ...`, JSON, une question de 1 200 caractères maximum et un corps total de 16 Kio maximum. Limite glissante : 20 demandes par adresse et par minute; l'adresse n'est pas envoyée au modèle.
- Une réponse `/chat` réussie contient `status: ok`, `answer`, `source: local|llm`, `model`, `elapsed_ms` et `storage: stateless`. La voie locale ajoute `kind: greeting|help|summary|mode|mode_definition|selected_event`. `mode_definition` explique seulement le fonctionnement du mode observation, sans prétendre connaître le réglage actif. Authentification, limitation de débit et nettoyage de réponse s'appliquent aux deux voies.
- `POST /warmup` est réservé aux scripts de préparation, avec le même jeton, la même limite de débit et le même verrou. Son budget est indépendant du chat : 60 secondes par défaut (`CYBERSHIELD_ASSISTANT_WARMUP_TIMEOUT_SECONDS`, valeur limitée entre 2 et 90 secondes). Il charge le modèle et préchauffe le préfixe système fixe en un seul appel `/api/chat` avec une salutation neutre, `num_ctx: 2048` identique aux questions libres, `num_predict: 1` et `keep_alive: 30m`. Cela évite de charger une première fois le modèle avec une autre taille de contexte puis de devoir le recharger. Aucune conversation utilisateur n'est utilisée ou conservée. Le service ne confirme `status: ready`, `loaded: true`, `model` et `elapsed_ms` qu'après réception de `done: true` et vérification du modèle résident via `/api/ps` dans le même budget total. Il met alors le cache de santé à jour ; un ancien rafraîchissement en cours ne peut pas écraser cette confirmation. Il renvoie `504 assistant_timeout` après expiration ou une erreur explicite. Il n'est pas exposé au navigateur.
- L'API se lie à la boucle locale en mode Wamp. Compose n'expose pas le port 5100 à l'hôte et ne le rend accessible qu'à PHP sur `inference`.
- Les réponses ont `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`. Les erreurs applicatives ne journalisent que le type d'exception, jamais le texte de la question.

## Développement et vérification

```powershell
& .\.runtime\python\python.exe -m pip install -r ia/assistant-requirements.txt
& .\.runtime\python\python.exe -m unittest discover -s ia -p 'test_assistant.py' -v
& .\.runtime\python\python.exe -m py_compile ia\assistant_core.py ia\assistant_graph.py ia\assistant_service.py
```

Les tests couvrent les bornes, la réduction du contexte, la redaction de secrets, l'authentification, la limitation de débit, les réponses locales sans modèle même pendant une inférence, le refus d'une seconde génération, les délais et la fermeture réelle du transport, la distinction installé/chargé et le préchargement authentifié. La disponibilité de l'API ne mesure pas la qualité du modèle. Avant une démonstration, précharger le modèle puis vérifier une question libre et les réponses locales sur les données affichées. Un préchargement à froid peut dépasser le budget : attendre la fin de l'annulation avant une nouvelle tentative ou ajuster explicitement le délai de préchargement dans la borne autorisée, sans allonger celui du chat.

Références primaires : [LangGraph Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api), [API Chat Ollama](https://docs.ollama.com/api/chat) et [bibliothèque Qwen2.5](https://ollama.com/library/qwen2.5).
