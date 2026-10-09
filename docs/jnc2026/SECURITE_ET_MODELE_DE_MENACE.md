# Revue de sécurité et modèle de menace CyberShield AI

## Portée de cette note

Cette note est une revue interne fondée sur le dépôt et ses tests automatisés. Elle ne constitue pas un audit indépendant, une certification, un test d'intrusion externe ni une preuve d'absence de vulnérabilité. Aucun test n'est effectué contre une cible publique ou un tiers.

## Actifs et frontières de confiance

- Application PHP protégée, base MariaDB, sessions et secrets d'administrateur.
- Entrées HTTP traitées par le middleware, scores du MLP et décisions de filtrage; question d'administration et synthèse transmise au LLM local.
- Journaux locaux, clé MFA, export SIEM facultatif, modèle Joblib et jeu d'entraînement.
- Frontières : navigateur vers application; PHP vers MLP local; application vers base; console vers assistant LangGraph/Ollama local; collecteur SIEM facultatif; accès administrateur à la console.

## Contrôles présents dans le dépôt

- Requêtes de base préparées avec `mysqli`; protection SQLi présentée comme défense en profondeur.
- Moteur de règles PHP et modèle MLP servi localement; accès réseau du service IA limité à la boucle locale dans les modes documentés.
- Limites d'entrée, de taille et de débit; décisions opérationnelles séparées des décisions SQLi.
- Mode observation configurable; refus de cas ambigus si le service IA indisponible, suivant la politique du code.
- MFA TOTP administrateur, protections de formulaire CSRF et limitation des essais de connexion décrites dans le dépôt.
- Journaux JSONL expurgés : les valeurs brutes ne sont pas enregistrées comme payload; des empreintes sont utilisées et certains noms sensibles sont masqués. Les journaux peuvent toutefois contenir des adresses IP, chemins et métadonnées; ils doivent rester privés et leur accès/retention doivent être gouvernés.
- Compose sépare les services; le port HTTP hôte est lié à la boucle locale par configuration par défaut. Toute modification de cette configuration doit être revue avant exposition réseau.
- Export SIEM optionnel avec jeton secret et file locale; les événements exportés restent des données de sécurité à protéger.
- Assistant LLM facultatif et séparé du moteur de décision; contexte ajouté automatiquement limité aux compteurs et catégories autorisées, sans payload de journal ni adresse IP. Le texte de la question est transmis au modèle local et peut contenir ce que l'administrateur y saisit; jeton interne, réponse sans mémoire et sans outils. Sous Compose, Ollama et LangGraph sont sur un réseau interne séparé du MLP et de la base; le cache modèle est monté en lecture seule.

## Risques résiduels à présenter

| Risque | Conséquence possible | Mesure ou étape suivante |
|---|---|---|
| Faux positif ou attaque manquée | Interruption légitime ou SQLi non signalée | Mode observation, revue humaine, requêtes préparées, pilote et tests de régression |
| Domaine de données limité | Mauvaise généralisation aux applications et usages réels | Évaluation sur un pilote distinct, étiquettes indépendantes et seuils convenus avant le test |
| MLP peu performant sur la capture observée | Alertes incorrectes si utilisé seul | Le présenter comme triage/défense en profondeur; ne pas le vendre comme protection autonome |
| Panne ou surcharge du service IA | Refus de requêtes ambiguës ou latence | Test de défaillance, limites opérationnelles, supervision et procédure de retour arrière |
| Secrets/logs mal protégés | Fuite de clés, métadonnées ou événements | Volumes privés, accès minimal, sauvegarde/rotation des secrets, politique de conservation |
| Dépendance et provenance du modèle | Chargement d'un artefact non fiable ou licence mal attribuée | Charger seulement l'artefact local construit par le projet; conserver empreintes, versions et attribution de licence |
| Réponse incorrecte ou injection de consigne visant l'assistant | Un administrateur pourrait suivre une explication fausse ou exposer un renseignement | Assistant sans outils ni autorité, contexte minimal, secrets usuels retirés; contrôler manuellement les conseils et éviter toute donnée confidentielle |
| Modèle LLM ou dépendances indisponibles | L'explication conversationnelle est absente ou lente | Fonction facultative, MLP indépendant, délais bornés, état visible; télécharger le modèle explicitement et n'activer Compose qu'après vérification |
| Couverture SQLi seulement | XSS, CSRF, LFI, erreurs de configuration et autres failles restent possibles | Documenter le périmètre et garder les contrôles dédiés de l'application |

## État des preuves expérimentales

- Le split public HttpParamsDataset contient 10 051 exemples `norm`/`sqli` de test et donne F1 0,999170 : 6 433 vrais négatifs, 1 faux positif, 5 faux négatifs et 3 612 vrais positifs. Il vient de la même famille publique que l'entraînement; c'est un résultat de test en domaine, pas une validation de production.
- La capture SR-BH 2020 provient d'un honeypot WordPress unique sur douze jours. Le MLP seul obtient F1 0,862153, précision 0,865160, rappel 0,859167 et spécificité 0,936180. Cette spécificité correspond à environ 6,4 % de faux positifs parmi les lignes normales de cette capture, pas à une mesure de site client.
- Le rejeu de la politique hybride sur la même capture donne F1 0,860560, rappel 0,856075 et spécificité 0,936372. La politique de présélection a été retenue après examen de cette capture; ce résultat est une mesure de développement, pas une confirmation indépendante.
- Aucun des deux jeux n'établit le délai HTTP p50/p95 du produit sous charge. Aucune mesure de pilote réel n'est disponible.
- L'assistant LangGraph/Ollama est une extension expérimentale distincte; ses tests vérifient les frontières d'entrée et de confidentialité, pas l'exactitude, la robustesse aux attaques de prompt, la latence ni les performances du modèle en français.
- Les affirmations du dossier initial sur un jeu de 10 000 requêtes, F1 0,988, faux positifs 0,5 %, faux négatifs 0,1 %, 98 % sous 100 ms et validation par SQLmap/Burp/Apache Benchmark ne sont pas soutenues par les artefacts du dépôt et ne doivent pas être revendiquées.

## Résultats des suites rejouées sur la révision préparée

- 99 contrôles de sécurité PHP réussis.
- 42 contrôles d'intégration applicative réussis avec PHP Wamp 8.4.15 et ses extensions `mysqli`/`curl`.
- 7 contrôles de première configuration et d'accès réussis.
- 16 tests Python du service et du modèle réussis.
- 9 tests de l'API et du noyau d'assistant réussis; ils couvrent les entrées, l'authentification, la confidentialité et le caractère stateless, sans évaluer la qualité du LLM.
- 10 tests de l'outil pilote et du transfert SIEM réussis.
- Syntaxe PHP vérifiée; `docker compose config --quiet` accepte la configuration Compose. L'accès au moteur Docker a été refusé dans cette session : aucune nouvelle construction ou exécution de conteneurs n'est revendiquée.

## Vérification indépendante à commander

Pour une évaluation externe, fournir à un évaluateur un clone de test, des comptes non sensibles, les versions et empreintes des composants, une autorisation écrite limitée à cette instance, les limites de charge, un contact d'arrêt et une procédure de signalement. Demander au minimum : revue des chemins d'accès et des secrets, contrôle d'authentification/autorisation/CSRF, injection SQL non destructive en laboratoire, vérification des frontières réseau/Compose, dépendances, gestion des logs et test des scénarios de panne. Les conclusions doivent nommer le périmètre, les exclusions, la date, les versions, chaque constat et sa correction.

## Conclusion d'exploitation

Le dépôt montre des mesures défensives et des tests automatisés, mais l'outil reste un MVP local spécialisé. L'évaluation indépendante, le pilote et la mesure sous charge sont des travaux à effectuer; ils ne sont pas présentés comme réalisés.

