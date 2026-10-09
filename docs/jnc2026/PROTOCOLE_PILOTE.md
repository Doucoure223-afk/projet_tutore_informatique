# Protocole de pilote CyberShield AI

## Statut

Ce protocole est un plan d'évaluation. Aucun pilote réel n'est déclaré terminé dans ce dossier. Le pilote ne commence qu'avec l'autorisation écrite du propriétaire du système, un périmètre défini et un contact responsable de l'arrêt.

## Question d'évaluation

Sur une application PHP autorisée et représentative, CyberShield AI peut-il produire des alertes utiles sans perturber les parcours légitimes, à un coût de déploiement et de calcul acceptable pour l'équipe qui l'exploite ? L'étude sépare les faux positifs sur les requêtes bénignes et le rappel sur les sondes de test contrôlées. Elle ne doit pas prétendre mesurer toutes les attaques réelles présentes sur Internet.

## Périmètre et règles de sécurité

1. Commencer sur une copie de préproduction ou un environnement de test. Si un hôte réel est ensuite envisagé, obtenir son autorisation écrite, les routes incluses, la période, les personnes responsables et la procédure de retour arrière.
2. Ne tester aucun site tiers, service partagé, compte réel ou donnée réelle sans autorisation explicite. Ne pas exécuter de requête SQL destructive, d'exfiltration, de test de charge agressif ni de scan externe.
3. Garder le mode SQLi en observation pendant la collecte. Dans ce mode, les décisions SQLi ne bloquent pas; les règles d'accès IP, de taille et de débit restent néanmoins actives et peuvent encore refuser une requête.
4. Conserver les requêtes préparées et les contrôles de sécurité existants. Le filtre n'est jamais une raison pour retirer ces protections.
5. Définir un responsable d'astreinte, un seuil d'arrêt convenu avec l'hôte et un moyen testé de désactiver CyberShield ou de revenir au mode observation.

## Préparation

- Documenter l'application, la version, les routes critiques, la machine et les composants installés.
- Vérifier les sauvegardes et la restauration avant le test.
- Noter le mode, les seuils, la version du code, l'empreinte du modèle et les versions Python/PHP.
- Capturer une période de référence avant l'installation : requêtes totales, erreurs HTTP, latence p50/p95, CPU, mémoire et disponibilité, si ces mesures sont déjà accessibles à l'hôte.
- Définir avec l'hôte les critères de réussite, les fenêtres de collecte, les personnes autorisées à examiner les preuves et la durée de conservation.
- Mettre à disposition une source indépendante d'évidence (par exemple les journaux applicatifs du site dans un espace restreint ou les sondes contrôlées). Ne pas copier la valeur des requêtes, les cookies, les identifiants ou les données personnelles dans le rapport de pilote.

## Collecte proposée

1. Installer CyberShield sur la copie autorisée et exécuter les contrôles fonctionnels sans requêtes destructives.
2. Rejouer une suite contrôlée d'entrées bénignes et de chaînes de test SQLi sur des routes sans accès à une base de production. La suite et les attentes sont figées avant le run; conserver son empreinte.
3. Observer les parcours légitimes en mode monitor pendant une période convenue, idéalement au moins sept jours pour inclure les variations de calendrier. Noter toute gêne signalée par l'exploitant.
4. Générer une feuille de revue avec échantillonnage aléatoire simple, graine publiée, et sans score ni verdict du modèle. Demander à un réviseur autorisé de consulter l'évidence indépendante et de renseigner `truth`, `reviewer_code`, `evidence_ref` et `label_confidence`.
5. Conserver séparément et sous accès restreint les correspondances entre identifiants d'événement et journaux sources. Le CSV de revue ne doit contenir aucune donnée brute, IP, URL complète ou identifiant personnel.
6. Faire relire les cas incertains par un second réviseur. Les étiquettes à faible confiance ou les désaccords sont consignés et exclus des métriques principales jusqu'à adjudication.
7. Exécuter le calcul sur les étiquettes finalisées; produire aussi le nombre de requêtes totales, les événements admissibles, le taux d'échantillonnage, les valeurs manquantes, les décisions par type, les erreurs de l'application et les latences p50/p95.

## Mesures et interprétation

- Pour la revue des événements observés : précision, taux de faux positifs parmi les événements bénins étiquetés, matrice de confusion, taille de l'échantillon et intervalles de confiance de Wilson à 95 %.
- Pour les sondes contrôlées : rappel par catégorie de sonde, en précisant que ce résultat dépend de la suite de test et de l'environnement.
- Pour l'intégration : latence ajoutée p50/p95, taux d'erreurs, CPU/mémoire et comportement si le service IA est arrêté.
- Les métriques de précision/rappel/F1 décrivent uniquement les événements qui ont une étiquette indépendante. Elles ne démontrent pas que les journaux contiennent toutes les attaques. Une capture de honeypot ou un jeu public ne représente pas le site pilote.
- Toute mesure sans dénominateur, période, version, méthode d'étiquetage et origine des données est exclue des résultats à présenter.

## Critères de passage en blocage

Les seuils de passage sont définis et signés par le propriétaire avant la collecte; ils ne sont pas des performances atteintes. À défaut d'exigences du site, les seuils provisoires à discuter sont : au moins 1 000 requêtes bénignes revues, aucune interruption d'un parcours critique, un rappel d'au moins 95 % sur la suite contrôlée, un taux de faux positifs au plus égal à 1 % sur l'échantillon bénin, et une latence p95 sous le budget accepté par le propriétaire. Un succès sur ces seuils autorise seulement une nouvelle décision conjointe; il n'autorise pas automatiquement le blocage en production.

## Commandes de revue

Depuis la racine du dépôt :

```powershell
& .\.runtime\python\python.exe scripts\pilot_metrics.py --events logs\events.jsonl --template tmp\pilot-review.csv --limit 250 --seed 20261009
```

La commande crée `tmp\pilot-review.csv` et son manifeste `tmp\pilot-review.csv.meta.json`. Le réviseur remplit uniquement les champs de vérité terrain et de provenance. Après la revue :

```powershell
& .\.runtime\python\python.exe scripts\pilot_metrics.py --events logs\events.jsonl --labels tmp\pilot-review.csv --report tmp\pilot-metrics.json
```

Avec Docker, exporter le journal depuis la console administrateur vers un répertoire local privé et utiliser ce fichier comme argument `--events`. La feuille et le rapport restent eux aussi privés; ne les joindre au dossier public qu'après revue de confidentialité et agrégation.

## Livrable à produire après le pilote

Un rapport daté comprenant l'accord et le périmètre, l'application et les versions testées, la fenêtre de collecte, les sources d'évidence, la méthode d'échantillonnage, la matrice de confusion, les intervalles, les mesures de latence/ressources, les faux positifs analysés, les changements exécutés et les limites. Le propriétaire du site approuve avant toute publication.

## Lettre d'accueil à faire compléter par un vrai partenaire

> Je soussigné(e), [nom et fonction], représentant [organisation], autorise CyberShield AI à être évalué sur [application/environnement explicitement défini] du [date] au [date], selon le protocole validé par nos responsables. Les accès aux journaux seront limités à [personnes], les données seront conservées jusqu'au [date] et aucun test ne portera sur les systèmes hors périmètre. Cette autorisation ne constitue pas une approbation commerciale ni une garantie de sécurité du produit.

Nom, signature et coordonnées du responsable : à compléter par le partenaire lui-même.

