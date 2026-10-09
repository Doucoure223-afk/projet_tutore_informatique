# Réponses au formulaire du Concours Innovation JNC 2026

Ces propositions sont prêtes à adapter au formulaire de l'AMRTP. Les champs d'identité et les rôles d'équipe doivent être confirmés par le porteur avant soumission.

## Informations générales

- **Nom du projet :** CyberShield AI
- **Ville :** Bamako, Mali
- **Établissement :** École Nationale d'Ingénieurs Abderhamane Baba Touré (ENI-ABT), selon le dossier initial.
- **Porteur indiqué dans le dossier initial :** Sékou Doucouré.
- **Collaborateur indiqué :** Adama Nakoun Fané.
- **Rôle précis de chaque membre :** à confirmer par l'équipe avant envoi; ne pas attribuer une fonction technique sans validation de la personne.

## Informations sur le projet

### Stade de développement

**MVP fonctionnel et démonstrateur local. Aucun déploiement pilote auprès d'une organisation réelle n'est documenté à ce jour.**

### Description du projet

CyberShield AI est un middleware local de défense en profondeur contre les injections SQL pour les applications web PHP. Il analyse les entrées HTTP à l'aide de règles heuristiques et d'un modèle MLP exécuté sur la même machine ou dans le réseau local. Les décisions et événements sont présentés dans une console d'administration, sans conserver les valeurs brutes des requêtes. Un mode observation permet d'étudier le comportement avant d'envisager le blocage. Une extension facultative LangGraph/Ollama aide l'administrateur à interpréter des compteurs et des événements expurgés; elle n'accède ni à la base ni aux payloads des journaux et ne prend aucune décision. Le texte saisi par l'administrateur est transmis au modèle local; il doit exclure les secrets et renseignements personnels. La qualité des réponses reste à évaluer. Le MVP reste spécialisé sur les injections SQL; il ne couvre pas toutes les vulnérabilités web et ne remplace ni les requêtes préparées ni les autres pratiques de sécurité applicative.

### Quelle est l'innovation distinctive du projet ?

Le projet réunit, dans un déploiement local ciblant les applications PHP, des règles déterministes, un MLP local pour une part bornée des saisies, un mode observation avant blocage et un journal de sécurité expurgé. Un assistant facultatif LangGraph/Ollama explique les tendances des événements à partir de données assainies, sans agir sur le filtre. L'inférence reste sur le site; l'export SIEM est facultatif. Notre hypothèse de valeur distinctive est un parcours de mise en place et de revue local, simple à évaluer pour une petite équipe PHP. Des solutions établies comme ModSecurity/Coraza avec OWASP CRS couvrent déjà plusieurs familles d'attaques; CyberShield AI est actuellement limité aux injections SQL et ne prétend pas les remplacer ni les surpasser. L'intégration, les faux positifs, la qualité de l'assistant et l'intérêt utilisateur doivent encore être comparés et validés sur un même protocole.

### Objectif principal

Permettre à une petite équipe responsable d'une application PHP de repérer et d'examiner des tentatives d'injection SQL au moyen d'un outil installable localement, avec des décisions consultables et un démarrage prudent en mode observation.

### Besoin ou problème visé

Les petites organisations qui exploitent une application PHP peuvent avoir besoin d'une visibilité supplémentaire sur les entrées suspectes sans envoyer leurs requêtes vers un service d'analyse tiers. CyberShield AI teste l'intérêt d'une couche locale de détection et de revue. Ce besoin et la volonté de payer restent à confirmer par des entretiens et un pilote; le dossier ne prétend pas qu'une étude représentative du marché a déjà été menée.

### Stratégie de mise en marché

**Oui, stratégie préliminaire à valider.** Commencer par des pilotes limités avec des propriétaires d'applications PHP et des intégrateurs locaux. Après mesure de l'intégration, des faux positifs, des délais et des besoins d'assistance, proposer une installation accompagnée et une maintenance locale; maintenir une version de démonstration et une documentation ouvertes afin de faciliter l'adoption par les petites structures. Un service hébergé, un abonnement et une intégration en marque blanche restent des options futures à valider avec des clients. Aucun partenaire pilote ni revenu n'est actuellement revendiqué.

### Composition de l'équipe

Le dossier initial nomme Sékou Doucouré comme porteur et Adama Nakoun Fané comme collaborateur. Faire confirmer par chacun son accord, son orthographe et son rôle avant d'inscrire ces personnes au formulaire. Le dossier initial mentionne également un encadrement scientifique; l'inscrire comme membre de l'équipe uniquement avec son accord explicite et si le rôle convient aux règles du concours. Le règlement public autorise les candidatures individuelles ou les équipes jusqu'à quatre membres.

### Document joint et vidéo

Après validation des noms et rôles, imprimer `dossier.html` et `fiche-technique.html` en PDF A4 depuis Edge (activer les arrière-plans, désactiver les en-têtes/pieds du navigateur, puis vérifier toutes les pages). La vidéo est facultative sur le formulaire public; utiliser `PITCH_ET_DEMONSTRATION.md` comme conducteur et enregistrer une démonstration réellement exécutée sur l'installation locale.

## Avant de soumettre

- Vérifier auprès de l'AMRTP que le formulaire 2026 est encore ouvert et demander sa date limite; la page publique décrit un formulaire 2026 sans afficher clairement de date de clôture.
- Lire les conditions de partage avec les jurys et ne soumettre que des informations dont l'équipe autorise la communication.
- Remplacer toute mention de métrique terrain par « non mesurée » tant qu'un pilote n'a pas produit de données étiquetées de manière indépendante.

