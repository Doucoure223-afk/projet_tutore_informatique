# Pitch et démonstration CyberShield AI

## Démonstration locale de trois minutes

Préparer une installation locale, vérifier l'état du MLP, ouvrir la console administrateur avec MFA et lancer le laboratoire SQLi. L'assistant LangGraph/Ollama est facultatif : télécharger le modèle à l'avance et tester sa disponibilité. Utiliser exclusivement l'environnement de démonstration et les chaînes du laboratoire, qui n'exécute pas de requête SQL. Ne montrer aucune base de données de production ni information personnelle.

1. **0:00–0:25 — Besoin.** Expliquer que le projet teste une couche de visibilité et de défense locale pour applications PHP. Décrire le besoin comme une hypothèse à valider auprès des exploitants.
2. **0:25–0:55 — Entrée bénigne.** Dans le laboratoire, soumettre une recherche normale; montrer que l'application reste utilisable et qu'aucune requête de laboratoire n'est exécutée.
3. **0:55–1:25 — Tentative de test.** Soumettre une chaîne de test SQLi inoffensive dans le laboratoire; expliquer le signal heuristique/MLP et l'événement consigné. Ne présenter la simulation comme une attaque réelle.
4. **1:25–1:55 — Explication.** Ouvrir le détail dans le tableau de bord et montrer l'explication locale déterministe, puis le mode observation. Si le modèle local est prêt, ouvrir le panneau « Poser une question » sans quitter le tableau de bord, questionner les seuls compteurs de démonstration et rappeler qu'il ne décide pas et peut se tromper; sinon, expliquer cette extension facultative sans simuler de réponse.
5. **1:55–2:20 — Défense en profondeur.** Montrer que les opérations de la boutique utilisent des requêtes préparées et préciser que le filtre ne remplace pas cette protection.
6. **2:20–2:45 — Preuves.** Donner les deux benchmarks publics et leurs limites : F1 0,999170 sur le split de test public de même famille, F1 0,862153 du MLP seul sur une capture honeypot unique; aucun pilote réel ni délai sous charge n'est revendiqué.
7. **2:45–3:00 — Demande.** Demander un accès à un partenaire de pilote autorisé, des retours d'intégrateurs PHP et un accompagnement pour l'évaluation indépendante.

## Texte oral indicatif

« CyberShield AI est un prototype conçu à Bamako pour examiner les injections SQL dans les applications PHP, en gardant l'analyse sur l'environnement local. Nous combinons des règles faciles à auditer avec un petit modèle MLP local pour certaines entrées. Le tableau de bord donne à l'administrateur les événements à examiner, et le mode observation sert à comprendre le comportement avant d'envisager un blocage.

Aujourd'hui, le périmètre est volontairement limité aux injections SQL. Les requêtes préparées restent la protection de base et notre filtre vient en complément. Un assistant optionnel LangGraph/Ollama peut résumer les compteurs locaux, sans accès à la base ni action automatique; la qualité de ses réponses reste à évaluer. Nos tests publics du MLP donnent des résultats différents selon la source : le split de test HttpParamsDataset donne un F1 de 0,999170, tandis que le MLP seul obtient 0,862153 sur une capture de honeypot WordPress unique. Ces résultats ne prouvent pas l'efficacité sur un site en production. Nous n'avons pas encore de pilote client ni de mesure de latence sous charge.

Notre prochaine étape est de travailler avec un propriétaire d'application PHP sur une copie autorisée, en observation, avec une revue indépendante des entrées et des mesures de faux positifs, de sondes contrôlées et de latence. Nous cherchons des partenaires de terrain et un regard externe pour établir où le produit est utile et ce qu'il faut corriger. »

## Questions du jury à préparer

- **Pourquoi ne pas se limiter aux requêtes préparées ?** Elles restent essentielles. CyberShield apporte une couche d'observation et d'alerte; il ne remplace pas la correction des requêtes vulnérables.
- **Pourquoi les résultats publics varient-ils ?** Les sources ont des origines et distributions différentes. Le split HttpParamsDataset partage la famille de données d'entraînement; SR-BH est une capture d'un honeypot et montre des faux positifs non négligeables. Le pilote doit tester la généralisation.
- **Le produit protège-t-il contre tout l'OWASP Top 10 ?** Non. Le MVP traite les injections SQL seulement.
- **Disposez-vous d'un partenaire ou d'un audit externe ?** Répondre exactement à l'état réel; ne jamais présenter un contact envisagé comme un partenaire engagé.
- **Quel est le modèle économique ?** Installation et accompagnement local d'abord; le prix et l'offre récurrente sont à valider par entretiens.
- **Qu'est-ce qui est nouveau ?** Le projet revendique une intégration locale PHP combinant règles, triage MLP borné, journalisation expurgée et démarrage en observation. Sa supériorité face aux autres solutions n'est pas encore démontrée.

