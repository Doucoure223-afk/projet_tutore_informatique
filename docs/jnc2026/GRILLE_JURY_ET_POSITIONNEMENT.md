# Grille de candidature et positionnement vérifiable

Préparée le 9 octobre 2026 à partir des critères affichés sur le [formulaire public du Concours Innovation JNC](https://www.jnc-mali.com/index.php/concours/concours-innovation). La page ne publie pas de pondération chiffrée; cette grille ne fabrique donc ni note sur 10, ni promesse de classement.

## Lecture des critères du jury

| Critère affiché | Preuve que nous pouvons montrer | Lacune qui reste | Action et condition de clôture |
|---|---|---|---|
| Innovation et originalité | Middleware PHP local qui combine règles heuristiques, analyse MLP bornée, revue locale et mode observation. Le pitch présente cela comme une hypothèse de différenciation, pas comme une invention sans équivalent. | Aucun avantage mesuré face à un WAF établi; aucun entretien utilisateur réalisé dans le dossier. | Comparer, sur une suite figée et sûre, règles seules, MLP, combinaison et OWASP CRS; faire au moins cinq entretiens de rôles distincts et consigner les verbatims anonymisés. |
| Impact potentiel | Public envisagé : petites équipes et intégrateurs qui maintiennent des applications PHP; l’analyse locale peut répondre à une contrainte de confidentialité ou de connectivité si les utilisateurs la confirment. | Besoin, adoption et effet local non quantifiés. | Obtenir des entretiens et, avec un partenaire volontaire, mesurer le temps d’intégration, les alertes utiles, les faux positifs et les contraintes d’exploitation. |
| Faisabilité et mise en œuvre | Démonstrateur PHP/MariaDB/Python, Wamp et Compose décrits; scripts de démarrage, tests automatiques, laboratoire sans exécution SQL et parcours de démonstration documentés. | La construction/démarrage Docker doit être rejouée sur un moteur Docker accessible; les noms/rôles et le temps d’installation cible restent à confirmer. | Répéter l’installation propre sur l’ordinateur de démo, chronométrer les étapes, archiver les commandes et les résultats, et fournir un retour arrière démontré. |
| Conformité aux enjeux de cybersécurité | Périmètre clairement borné aux injections SQL, requêtes préparées conservées, journal expurgé, MFA, CSRF, limites opérationnelles et preuves reproductibles sur jeux publics. | Le résultat sur un corpus public n’établit pas l’efficacité ni la couverture d’une application réelle. | Montrer les limites, conserver les contrôles applicatifs, utiliser une suite de sondes non destructives et faire étiqueter les résultats indépendamment. |
| Scalabilité | Services séparés, inférence locale, journaux locaux et possibilité d’export SIEM facultatif. | Aucun débit, consommation ou délai p50/p95 mesuré; pas de test multi-application ou haute disponibilité. | Mesurer sur matériel déclaré la latence de bout en bout p50/p95, erreurs, débit, CPU et mémoire; ne parler d’échelle qu’après ces mesures. |
| Sécurité et robustesse | 99 contrôles de sécurité PHP, tests d’intégration et du modèle consignés; modèle de menace, risques résiduels et protocole de pilote fournis. | Pas d’audit indépendant ni de test d’intrusion tiers; exécution Docker finale non vérifiée dans la session de préparation. | Mandater un réviseur avec autorisation et périmètre isolé; corriger les constats puis publier la portée, la date et les résultats. |
| Expérience de l’équipe | Le dossier source nomme Sékou Doucouré et Adama Nakoun Fané. | Rôles détaillés, consentement à être inscrits, disponibilité et preuves de réalisation ne sont pas validés dans le dépôt. | Faire confirmer chaque nom, rôle et accord; joindre de courtes biographies et présenter les contributions réelles à la démo. |
| Responsabilité éthique et conformité légale | Pilote limité à une copie autorisée, mode observation, revue aveugle, minimisation des données, licences des jeux et interdiction des scans tiers documentés. | Aucun partenaire, consentement écrit ni plan de conservation propre à un site pilote n’est versé au dossier. | Ne collecter qu’après accord écrit; définir responsable, données, durée de conservation, procédure d’arrêt et partage du rapport avec l’hôte. |

## Positionnement face aux options existantes

Le [OWASP Core Rule Set (CRS)](https://coreruleset.org/docs/3-about-rules/rules/) est un ensemble de règles utilisé avec ModSecurity ou d’autres WAF compatibles. Sa documentation décrit des familles de règles SQLi, XSS, LFI et d’autres catégories. ModSecurity/CRS et Coraza/CRS constituent donc des références établies et plus larges en couverture que le périmètre SQLi actuel de CyberShield AI.

| Option | Portée établie | Place de CyberShield AI |
|---|---|---|
| Requêtes préparées | Prévention côté application de la construction dangereuse des requêtes SQL. | Protection fondamentale à conserver; le middleware n’en est jamais un substitut. |
| ModSecurity ou Coraza avec OWASP CRS | Moteur WAF et règles génériques couvrant plusieurs familles d’attaques. | Référence de comparaison et option complémentaire possible; aucun test comparatif n’a encore été conduit. |
| CyberShield AI | Couche PHP locale de triage SQLi combinant règles et MLP borné, journal local et démarrage en observation. | MVP spécialisé à évaluer pour sa facilité d’intégration et son utilité opérationnelle auprès de petites équipes PHP. Aucune supériorité de détection, coût ou performance n’est démontrée. |

La différenciation défendable aujourd’hui est une **combinaison de choix d’architecture et de parcours d’exploitation** : installation locale ciblant PHP, explication déterministe, mode observation et journaux expurgés. Ces éléments caractérisent le produit; ils ne prouvent ni originalité absolue ni adéquation au marché. La bonne comparaison doit être réalisée sur le même corpus, avec des versions consignées et une séparation des données qui évite la fuite entre entraînement et test.

## Plan de comparaison reproductible

1. Figer avant l’évaluation les versions, l’empreinte des corpus, la liste d’entrées bénignes et de sondes SQLi non destructives, les règles de notation et les exclusions.
2. Séparer les données par source ou période, puis mesurer règles seules, MLP seul, mode combiné et OWASP CRS si l’installation de référence est disponible.
3. Faire établir la vérité terrain par un évaluateur qui ne voit ni score ni décision du filtre; conserver une référence de preuve autorisée et minimale.
4. Rapporter précision, rappel, F1, faux positifs pour 1 000 entrées bénignes, faux négatifs sur sondes contrôlées, p50/p95 bout en bout, erreurs, CPU, mémoire et durée d’intégration.
5. Publier les résultats défavorables et les limites. Ne pas agréger les résultats d’une capture de honeypot avec ceux d’un site pilote; ne pas appeler une revue interne « audit indépendant ».

## Séquence de clôture réaliste

**Avant soumission :** ouvrir et contrôler visuellement les PDF; faire confirmer la date limite officielle, les coordonnées, les rôles et les consentements; répéter la démo sur l’installation qui sera présentée.

**Avant tout pilote :** obtenir le propriétaire et l’accord écrit, la copie de test, le responsable d’arrêt, les critères préétablis, les sauvegardes, la suite de sondes et une période d’observation.

**Avant toute promesse de production :** faire une revue indépendante, corriger les constats, mesurer charge et latence sur matériel connu, et valider le positionnement avec des intégrateurs ou clients.

Sources consultées le 9 octobre 2026 : [Critères et formulaire Concours Innovation JNC](https://www.jnc-mali.com/index.php/concours/concours-innovation); [OWASP CRS — contenu des règles](https://coreruleset.org/docs/3-about-rules/rules/); [OWASP CRS — documentation](https://coreruleset.org/docs/); [OWASP CRS — FAQ (rôle respectif du moteur et des règles)](https://coreruleset.org/faq/).
