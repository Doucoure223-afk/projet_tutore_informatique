# Service MLP local — CyberShield AI

Ce service remplace les réponses simulées par une inférence réellement calculée par un réseau dense scikit-learn : caractéristiques → **128 → 64 → 32 → 1**, couches cachées ReLU, sortie sigmoïde, Adam et taux d'apprentissage `0.001`. La normalisation `StandardScaler` est ajustée uniquement sur la partition d'apprentissage. Graine aléatoire : `42`. Seuil de blocage : **risk ≥ 0.75**.

## Installation et exécution

Depuis la racine du projet, avec Python 3.11 à 3.13 :

```powershell
python -m pip install -r ia/requirements.txt
python ia/train.py
python -m unittest discover -s ia -p "test_*.py" -v
python ia/service.py
```

Si Python portable est installé dans le projet, remplacer `python` par `.\.runtime\python\python.exe`. L'installation des paquets demande un accès réseau initial ; l'entraînement et le service fonctionnent ensuite hors ligne. Les modèles et rapports sont créés dans `ia/models/`. Relancer le service après chaque entraînement. `--model`, `--port` et `--rate-limit` sont disponibles ; l'adresse d'écoute reste limitée à `127.0.0.1`.

## Contrat HTTP

- `GET http://127.0.0.1:5000/health` : `model_loaded`, `model_version`, `version`, `status`, `threshold`. Code 503 si le modèle manque ou est incompatible.
- `POST http://127.0.0.1:5000/analyse`, `Content-Type: application/json`, corps `{"sql":"valeur à vérifier","context":"login"}` : `risk`, `confidence`, `type`, `decision`, `analysis_method: "MLP"`, `model_version`, `features`, `dataset_source` et `threshold`.
- `risk` est le score de la classe SQLi ; `confidence = max(risk, 1-risk)` est un score **non calibré** de la classe la plus probable. Ce n'est ni une garantie ni la probabilité empirique que la décision soit correcte. La décision utilise le seuil `risk >= 0.75`, jamais la confiance.
- `type` est une explication par caractéristiques (`type_method: "FEATURE_HEURISTIC"`). Le réseau apprend une classification binaire ; il n'est pas présenté comme un classifieur entraîné des familles d'attaques.
- `context` est retourné comme métadonnée ; il ne modifie pas artificiellement le score du modèle.

## Données et résultats

`dataset.py` génère un **petit corpus synthétique de démonstration**, explicitement étiqueté `synthetic_demo`. Des groupes de templates entiers sont réservés à la validation, sans doublon de texte normalisé entre les partitions. `train.py` produit le corpus, son empreinte SHA-256, le nombre réel de lignes, les groupes, la matrice de confusion, précision, rappel, F1 et résultats par famille dans `training_report.json`.

Une évaluation externe reproductible est disponible avec `python ia/evaluate_external.py`. Elle utilise le fichier public `tests/fixtures/HttpParamsDataset/payload_test.csv`, qui comporte 10 355 valeurs de paramètres HTTP. Le protocole garde uniquement `norm` et `sqli` (10 051 valeurs évaluées), laisse de côté XSS, commande et traversée de répertoires, et mesure le modèle existant au seuil 0,75 sans l'entraîner ni régler ce seuil sur ces données. Le rapport, avec empreintes du jeu et du modèle, est écrit dans `ia/models/external_evaluation.json`.

Avec le modèle fourni actuellement, cette évaluation donne F1 **0,965843**, précision **0,999704**, rappel **0,934200**, 6 433 vrais négatifs, 1 faux positif, 238 faux négatifs et 3 379 vrais positifs. L'évaluation initiale sur le petit corpus synthétique reste documentée séparément dans `training_report.json` (F1 0,950820 sur 128 lignes).

Une deuxième évaluation utilise SR-BH 2020, une capture CC0 de 907 815 requêtes HTTP observées pendant 12 jours sur un honeypot WordPress exposé à Internet. Pour la tâche SQLi, 525 195 requêtes strictement normales et 250 311 requêtes étiquetées SQLi sont évaluées; 132 309 autres ou ambiguës sont exclues. Le modèle est appliqué à chaque chemin URL et valeur GET, POST, JSON ou cookie inspectée par le middleware. Sans réentraînement ni réglage du seuil, le MLP seul obtient F1 **0,492487**, rappel **0,330601**, précision **0,965038** et spécificité **0,994292** sur 775 506 requêtes. Il manque donc beaucoup d'attaques sur ce jeu et ne doit pas être utilisé seul en production. Le rapport avec empreintes officielles est `ia/models/honeypot_evaluation.json`; le fichier source de 436 Mo n'est pas inclus dans le dépôt.

Pour reproduire cette seconde mesure, télécharger la version publiée par Harvard Dataverse, vérifier son MD5 officiel, puis lancer l'évaluateur :

```powershell
$data = Join-Path $env:TEMP 'data_capec_multilabel.csv'
Invoke-WebRequest 'https://dataverse.harvard.edu/api/access/datafile/6319496' -OutFile $data
(Get-FileHash $data -Algorithm MD5).Hash # 173EC515308BDCE5AEC19CFD5B792596
& .\.runtime\python\python.exe ia\evaluate_honeypot.py --dataset $data
```

Le jeu original de 10 000 requêtes et le F1 de 0,988 cités dans le dossier ne sont pas fournis et **ne sont pas revendiqués**. SR-BH 2020 utilise des étiquettes CAPEC issues de ModSecurity, révisées par les auteurs, et reste une capture limitée à un honeypot et à une période. Ces résultats apportent une mesure sur trafic observé, sans certifier d'autres applications ou environnements. Aucun score n'est inventé lorsque le modèle est absent : l'API renvoie 503 et l'application PHP doit indiquer son mode de protection local.

## Limites et fonctionnement local

Waitress limite le corps HTTP à 32 Kio, les en-têtes à 8 Kio, les connexions à 32 et les connexions inactives à 5 secondes. Flask valide le type JSON, la taille de `sql` (8 192 caractères) et celle de `context` (64 caractères). Une fenêtre glissante limite `/analyse` à 120 appels/minute par adresse de l'appelant HTTP ; les en-têtes proxy sont ignorés. Puisque les appels passent par PHP local, cette limite est globale au client PHP ; la limitation par visiteur doit aussi être appliquée dans PHP. Aucun payload SQL n'est exécuté ou journalisé par ce service.

Le décodage URL est limité à trois passes, comme dans le prétraitement PHP. Les commentaires SQL et les commentaires exécutables MySQL sont pris en compte. Ce modèle n'est ni un parseur SQL exhaustif ni une protection XSS ; les requêtes préparées restent indispensables côté application.

Charger uniquement les fichiers Joblib produits localement : le format peut exécuter du code au chargement. Le service refuse les versions scikit-learn et schémas de caractéristiques incompatibles. Conserver `ia/`, son corpus et ses artefacts hors de l'accès HTTP Apache public.

Références techniques : [MLPClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.neural_network.MLPClassifier.html), [persistance des modèles](https://scikit-learn.org/stable/model_persistence.html), [paramètres Waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/arguments.html).
