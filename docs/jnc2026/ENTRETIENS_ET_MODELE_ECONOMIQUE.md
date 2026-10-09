# Découverte utilisateur et modèle économique à valider

## Hypothèses de départ

Le public initial envisagé est constitué d'organisations maliennes qui maintiennent une application PHP/MySQL sans équipe de sécurité dédiée : établissements de formation, petites entreprises numériques, agences web et organisations publiques. Ce ciblage est une hypothèse produit, pas le résultat d'une étude représentative ni la preuve d'une demande solvable.

## Entretiens de découverte

Interroger au moins cinq personnes aux rôles différents (responsable technique, agence/intégrateur, direction d'une petite structure, administrateur applicatif). Ne pas vendre la solution pendant l'entretien; demander des exemples et noter les réponses sans données sensibles.

1. Quelle application web critique votre organisation maintient-elle, avec quelle stack et qui en est responsable ?
2. Comment repérez-vous aujourd'hui les tentatives d'injection SQL ou les incidents applicatifs ?
3. Que faites-vous lorsqu'une alerte arrive, et qui peut l'interpréter ?
4. Quelles contraintes empêchent l'adoption d'un WAF ou d'un service externe : coût, connectivité, confidentialité, compétences, intégration ?
5. Quelles routes ou opérations seraient inacceptables à interrompre à cause d'un faux positif ?
6. Accepteriez-vous un pilote en observation sur une copie de test ? Quelles validations internes sont nécessaires ?
7. Quel résultat observable vous ferait envisager une installation durable : temps d'intégration, réduction de bruit, temps de réponse, accompagnement ?
8. Qui décide du budget, quel mode de facturation est acceptable, et quel service d'installation/support attendez-vous ?

## Mesures à consigner

Pour chaque entretien : date, rôle, type d'organisation, stack confirmée, problème cité avec exemple anonymisé, solution actuelle, contrainte la plus forte, intérêt pour un pilote, intérêt budgétaire exprimé sans pousser le répondant, prochaine action autorisée. Séparer citation de l'interviewé, observation et interprétation. Un petit nombre d'entretiens explore des besoins; il ne représente pas le marché entier.

## Stratégie commerciale provisoire

1. **Pilote accompagné :** déploiement en observation sur une application que le partenaire contrôle, avec revue et rapport de résultats.
2. **Première offre :** installation locale et accompagnement d'intégration pour une application PHP; frais d'installation et de support à définir après entretiens.
3. **Distribution :** travailler avec des agences web/intégrateurs qui maintiennent plusieurs applications PHP et peuvent assurer l'installation.
4. **Élargissement :** évaluer ensuite les contrats de maintenance annuels ou une offre hébergée uniquement si les clients le demandent et si la confidentialité, la disponibilité et le support sont maîtrisés.

Les prix, marges, taille de marché, coûts d'acquisition et revenus ne sont pas établis. Ne pas en inventer dans le dossier; annoncer un plan d'étude et les critères qui permettront de les fixer.

## Proposition de pilote à envoyer par le porteur

> Nous développons CyberShield AI, un prototype local de détection des injections SQL pour applications PHP. Nous cherchons un partenaire disposant d'une application de test ou d'une copie de préproduction afin d'évaluer l'intégration en mode observation. Le pilote est limité au périmètre convenu, ne lance pas de requêtes SQL destructives et garde l'analyse sur le site. Il vise à mesurer les faux positifs, le comportement sur une suite de sondes contrôlées et le coût d'intégration. Souhaitez-vous un entretien de 20 minutes pour vérifier si ce test répond à un besoin chez vous ?

Ce texte est un modèle; il ne constitue pas une invitation déjà envoyée ou un accord obtenu.

