# Assistant de triage local avec LangGraph

## Rôle

L'assistant est une fonction facultative de la console administrateur. Il répond en français aux questions sur le mode du filtre et sur des compteurs ou événements récents. Il n'intervient jamais dans la décision SQLi, qui reste portée par les règles PHP et le MLP.

Le graphe LangGraph est volontairement simple et vérifiable :

1. `prepare` limite et assainit la question et réduit le contexte aux compteurs ainsi qu'à huit événements au maximum;
2. `answer` appelle l'API Chat d'Ollama sur le modèle local configuré;
3. `validate` supprime les caractères de contrôle et borne la réponse;
4. le graphe se termine sans mémoire conversationnelle ni outil d'action.

Le service ne possède aucun connecteur de base de données, outil SQL, outil shell ni fonction de blocage ou de modification de configuration. Il ne lit aucun fichier de journal. PHP calcule localement les compteurs et lui envoie seulement un libellé de page fixe, des catégories en liste blanche, des horodatages, des scores bornés et l'état de quelques fonctions. Les IP, chemins, valeurs des formulaires et payloads des journaux ne sont pas ajoutés au contexte. Le texte de la question est toutefois transmis au modèle local; des secrets courants et numéros de carte sont expurgés, mais ne saisir aucune donnée confidentielle.

Le modèle peut produire des erreurs ou suivre imparfaitement les consignes. Une réponse n'est ni une décision de sécurité ni un audit. L'administrateur doit vérifier tout conseil dans le code et les journaux autorisés. Le modèle est distinct du MLP et son exactitude sur des questions de sécurité n'a pas encore été évaluée.

## Installation locale avec Wamp

Pré-requis : Ollama pour Windows, Python du projet installé sous `.runtime` par `scripts/install-python.ps1`, PHP cURL activé, compte administrateur déjà configuré et MFA enrôlé. Installer le modèle explicitement :

```powershell
ollama pull qwen2.5:7b-instruct
powershell -ExecutionPolicy Bypass -File .\scripts\start-assistant.ps1
```

Depuis la console authentifiée, cliquer sur « Poser une question » dans la supervision, le laboratoire ou les règles IP, ou ouvrir la page complète `security/assistant.php`. L'URL locale habituelle est `http://localhost/projet_tutor%C3%A9_inf/security/assistant.php`. Le panneau envoie le contexte sûr de la page (un libellé fixe autorisé et les mêmes compteurs expurgés); il ne transmet aucun champ de formulaire de la page. Le service Python écoute uniquement sur `127.0.0.1:5100`, séparément de l'API MLP sur le port 5000.

Modèle moins gourmand : `ollama pull qwen2.5:1.5b`, puis `powershell -ExecutionPolicy Bypass -File .\scripts\start-assistant.ps1 -Model qwen2.5:1.5b`. Pour arrêter le processus local :

Dans Docker, après `scripts/init-docker.ps1`, le même modèle léger s'utilise en remplaçant `CYBERSHIELD_ASSISTANT_MODEL` par `qwen2.5:1.5b` dans `.env`, puis en lançant `docker compose --profile assistant up --build -d`.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop-assistant.ps1
```

Le script de démarrage vérifie la présence d'Ollama, du modèle et des versions épinglées de Flask, Waitress et LangGraph. Il n'installe pas ni ne télécharge le modèle automatiquement. Les journaux techniques de démarrage vont dans `%TEMP%\cybershield-assistant`; les questions et réponses ne sont pas écrites dans ces journaux.

## Option Docker

Installer Ollama sur l'hôte, télécharger le modèle puis initialiser le dossier et le jeton local :

```powershell
ollama pull qwen2.5:7b-instruct
powershell -ExecutionPolicy Bypass -File .\scripts\init-docker.ps1
docker compose --profile assistant up --build -d
```

Le script initialise `OLLAMA_MODELS_PATH` dans `.env` avec `%USERPROFILE%\.ollama\models`, ou avec le chemin défini par `OLLAMA_MODELS`. Si Ollama a été configuré vers un autre cache, vérifier cette variable dans `.env` avant le démarrage. Ollama et l'assistant sont isolés du MLP et de la base sur un réseau Docker interne dédié; seul le service web rejoint ce réseau et celui du MLP. Le cache est monté en lecture seule et aucun service du profil n'a de route de sortie Internet. Les images et bibliothèques nécessaires doivent être téléchargées pendant la construction initiale. Un modèle absent ne sera jamais récupéré en tâche de fond.

La clef d'API aléatoire de 48 octets est créée dans `secrets/assistant_token.txt`; elle est partagée entre PHP et le service via un secret Docker. Ne la committer ni ne la communiquer. `docker compose down` conserve le modèle et les données; `docker compose down -v` supprime les volumes persistants de la base et de l'application.

## Contrat API interne

- `GET /health` expose uniquement le nom/version du modèle configuré, sa disponibilité et l'état stateless. Il renvoie 503 si le jeton manque ou si le modèle n'est pas chargé.
- `POST /chat` exige `Authorization: Bearer ...`, JSON, une question de 1 200 caractères maximum et un corps total de 16 Kio maximum. Limite glissante : 20 demandes par adresse et par minute; l'adresse n'est pas envoyée au modèle.
- L'API se lie à la boucle locale en mode Wamp. Compose n'expose pas le port 5100 à l'hôte et ne le rend accessible qu'à PHP sur `inference`.
- Les réponses ont `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` et `Referrer-Policy: no-referrer`. Les erreurs applicatives ne journalisent que le type d'exception, jamais le texte de la question.

## Développement et vérification

```powershell
& .\.runtime\python\python.exe -m pip install -r ia/assistant-requirements.txt
& .\.runtime\python\python.exe -m unittest discover -s ia -p 'test_assistant.py' -v
& .\.runtime\python\python.exe -m py_compile ia\assistant_core.py ia\assistant_graph.py ia\assistant_service.py
```

Les tests couvrent les bornes, la réduction du contexte, la redaction de secrets, l'authentification, la limitation de débit et l'absence d'historique. La disponibilité de l'API ne mesure pas la qualité du modèle. Avant une démonstration, envoyer une question neutre et vérifier que la réponse correspond aux données affichées.

Références primaires : [LangGraph Graph API](https://docs.langchain.com/oss/python/langgraph/graph-api), [API Chat Ollama](https://docs.ollama.com/api/chat) et [bibliothèque Qwen2.5](https://ollama.com/library/qwen2.5).
