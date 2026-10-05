CyberShield AI — MVP local
=========================

Ce dépôt contient une démonstration locale de protection contre les injections SQL.
La boutique est protégée par l'analyse CyberShield, des requêtes préparées et des jetons CSRF.
Le laboratoire analyse le texte reçu sans exécuter de SQL.

Pour installer et lancer le projet, lire README.md.

Points d'entrée :
  index.php                 accueil
  security/dashboard.php   supervision et incidents
  security/lab.php         analyse pédagogique isolée
  app/search.php            boutique simulée

Le service Python écoute uniquement sur 127.0.0.1. La base et les journaux restent locaux.
La commande /health indique si le modèle est prêt. Si le MLP est indisponible, une entrée
ambigüe est bloquée par précaution.

Le jeu de 10 000 requêtes et les résultats expérimentaux décrits dans le dossier de
candidature ne sont pas présents dans ce dépôt. Le MLP utilise un corpus synthétique
de démonstration. Les rapports incluent aussi des évaluations publiques distinctes, dont une
capture observée sur honeypot; le rappel du MLP seul y reste limité. Les métriques ne prouvent
pas les performances annoncées dans les documents de référence ni ne certifient la production.
