# Service MLP local — CyberShield AI

L'assistant conversationnel LangGraph est une fonction facultative distincte du filtre MLP; son architecture, son installation et ses limites sont décrites dans [ASSISTANT_LANGGRAPH.md](ASSISTANT_LANGGRAPH.md).

Le service exécute un vrai réseau scikit-learn **37 → 128 → 64 → 32 → 1**, avec ReLU, Adam et StandardScaler. Le seuil de blocage du score SQLi reste fixé à **0,75**. Le modèle livré est versionné et son rapport conserve l'empreinte des données utilisées.

## Installation et exécution

Depuis la racine du projet, avec Python 3.11 à 3.13 :

```powershell
python -m pip install -r ia/requirements.txt
python ia/train.py
python -m unittest discover -s ia -p "test_*.py" -v
python ia/service.py
```

L'entraînement utilise par défaut `tests/fixtures/HttpParamsDataset/payload_train.csv`, déjà inclus sous licence MIT avec attribution et empreinte SHA-256. Il fonctionne hors ligne une fois les dépendances installées. Les rapports et le modèle sont écrits dans `ia/models/`. Relancer le service après un réentraînement. `--model`, `--port` et `--rate-limit` sont disponibles ; l'adresse d'écoute reste limitée à `127.0.0.1`.

## Contrat HTTP

- `GET http://127.0.0.1:5000/health` : `model_loaded`, `model_version`, `version`, `status`, `threshold`. Code 503 si le modèle manque ou est incompatible.
- `POST http://127.0.0.1:5000/analyse`, avec `Content-Type: application/json` et `{"sql":"valeur à vérifier","context":"login"}` : `risk`, `confidence`, `type`, `decision`, `analysis_method: "MLP"`, `model_version`, `features`, `dataset_source` et `threshold`.
- `risk` est le score de la classe SQLi ; `confidence = max(risk, 1-risk)` est un score **non calibré**. Ce n'est pas une probabilité empirique de justesse. La décision utilise seulement `risk >= 0.75`.
- `type` est une explication heuristique par caractéristiques ; le réseau est un classifieur binaire, pas un modèle entraîné aux familles d'attaques. `context` ne modifie pas artificiellement le score.

## Données et résultats

`train.py` sélectionne les lignes `norm` et `sqli` du jeu d'entraînement public, soit **20 105 exemples** (12 870 normaux, 7 235 SQLi). Les exemples XSS, commande et traversée de répertoires sont laissés de côté. L'entraînement utilise une validation interne de 10 % pour l'arrêt anticipé ; le seuil reste fixé à 0,75.

Le jeu public indique que ses valeurs normales viennent de CSIC 2010 et que ses attaques SQLi ont été générées avec sqlmap et d'autres corpus publics. C'est un benchmark reproductible, pas du trafic réel. Le jeu source, la sélection des étiquettes, les hyperparamètres, les versions et l'empreinte SHA-256 sont inscrits dans `ia/models/training_report.json`.

L'évaluation externe utilise `tests/fixtures/HttpParamsDataset/payload_test.csv`, un partage distinct de test, jamais utilisé pour entraîner ou régler le seuil. Sur ses 10 051 valeurs `norm`/`sqli`, le modèle v2 obtient F1 **0,999170**, précision **0,999723**, rappel **0,998618**, avec 6 433 vrais négatifs, 1 faux positif, 5 faux négatifs et 3 612 vrais positifs. XSS, commandes, traversées et entrées trop longues sont exclues. Ce chiffre mesure la séparation sur cette famille de données, pas une efficacité garantie en production. Le rapport porte les empreintes des données et du modèle dans `ia/models/external_evaluation.json`.

L'évaluation observée utilise SR-BH 2020, capture CC0 de requêtes HTTP étiquetées pendant 12 jours sur un honeypot WordPress. Sur les 775 506 lignes strictement normales ou SQLi, le MLP v2 seul obtient F1 **0,862153**, rappel **0,859167**, précision **0,865160** et spécificité **0,936180**. Cela améliore le rappel et le F1 par rapport au modèle synthétique précédent, mais entraîne plus de faux positifs et ne démontre pas une protection autonome de production. Le middleware conserve le blocage immédiat par signature puis présélectionne jusqu’aux quatre premières valeurs de la requête par le MLP, y compris quand aucune règle PHP n’a reconnu la valeur. Une fois ce budget consommé, les autres valeurs de la zone grise restent bloquées par précaution et les valeurs sans signature sont ignorées. Cette correction évite que les injections sans signature connue contournent entièrement le MLP. Sur la capture, le pipeline ainsi mesuré obtient F1 **0,860560**, rappel **0,856075**, précision **0,865092** et spécificité **0,936372**. La sélection précédente limitée aux seules valeurs déjà signalées par les règles n’obtenait qu’un rappel de 0,188869. Le rapport `honeypot_evaluation.json` conserve les deux résultats et les matrices de confusion. Le service IA local est plafonné globalement à 420 appels/minute. Cela couvre quatre appels pour 100 requêtes/minute d’un même client PHP ; plusieurs visiteurs partagent ce plafond global. La politique de présélection a été choisie après la première relecture de cette même capture ; son score combiné est donc une mesure de développement, pas une confirmation indépendante après ce choix. Cette relecture reproduit les décisions, sans mesurer le délai HTTP en charge. La spécificité de 0,936372 implique encore des faux positifs sur cette capture ; le modèle reste une défense en profondeur, pas une protection autonome certifiée.

La capture complète de 436 Mo n'est pas versionnée. Pour la télécharger et reproduire l'évaluation :

```powershell
$data = Join-Path $env:TEMP 'data_capec_multilabel.csv'
Invoke-WebRequest 'https://dataverse.harvard.edu/api/access/datafile/6319496' -OutFile $data
(Get-FileHash $data -Algorithm MD5).Hash # 173EC515308BDCE5AEC19CFD5B792596
& .\.runtime\python\python.exe ia\evaluate_honeypot.py --dataset $data
```

Le jeu de 10 000 requêtes et le F1 de 0,988 cités dans le dossier initial ne sont pas fournis et **ne sont pas revendiqués**. La capture SR-BH dépend d'un seul honeypot et d'étiquettes CAPEC révisées par ses auteurs ; elle ne couvre pas toutes les applications. Les requêtes préparées restent nécessaires, et le filtre PHP demeure une couche de défense en profondeur.

## Limites et fonctionnement local

Waitress limite le corps HTTP à 32 Kio, les en-têtes à 8 Kio, les connexions à 32 et les connexions inactives à 5 secondes. Flask valide le type JSON, la taille de `sql` (8 192 caractères) et celle de `context` (64 caractères). Une fenêtre glissante limite `/analyse` à 420 appels/minute par adresse de l'appelant HTTP ; ce plafond couvre les quatre valeurs examinées pour les 100 requêtes/minute autorisées par PHP. Les en-têtes proxy sont ignorés. Aucun payload SQL n'est exécuté ou journalisé par le service.

Le modèle n'est ni un parseur SQL exhaustif ni une protection XSS. Les commentaires SQL, les commentaires exécutables MySQL et trois décodages URL sont pris en compte. Charger uniquement des artefacts Joblib produits localement, car leur format peut exécuter du code au chargement. Le service refuse les versions scikit-learn et schémas de caractéristiques incompatibles. Garder `ia/`, le jeu de données et le modèle hors de l'accès HTTP Apache public.

Références : [MLPClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.neural_network.MLPClassifier.html), [persistance des modèles](https://scikit-learn.org/stable/model_persistence.html), [paramètres Waitress](https://docs.pylonsproject.org/projects/waitress/en/latest/arguments.html).
