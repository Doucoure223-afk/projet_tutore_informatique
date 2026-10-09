# Dossier de candidature CyberShield AI pour les JNC 2026

Ce dossier rassemble une candidature alignée sur le logiciel réellement présent dans ce dépôt. Les anciens PDF sont conservés à la racine comme archives. Les sources éditables sont `dossier.html` et `fiche-technique.html`; les exports A4 générés sont dans `pdf/`. Le contrôle de pagination est automatisé, mais vérifiez encore les PDF dans l’aperçu d’impression de votre poste avant de les soumettre.

## État à la date de préparation

CyberShield AI est un démonstrateur local : middleware PHP spécialisé sur les injections SQL, règles heuristiques, service MLP local, journal d'événements expurgés, console d'administration, boutique de démonstration et assistant LangGraph/Ollama facultatif en lecture seule. L'assistant est configuré pour une installation locale, mais son exécution avec le modèle téléchargé et la qualité de ses réponses restent à vérifier sur le poste de démonstration. Il n'y a pas de pilote avec une organisation réelle documenté dans le dépôt. Aucun résultat de latence en charge, audit externe ou test d'intrusion indépendant n'est revendiqué.

Les seules performances citées sont des mesures reproductibles sur deux sources publiques : le partage de test HttpParamsDataset, issu de la même famille de données que l'entraînement, et une capture d'un honeypot WordPress unique (SR-BH 2020). Elles ne prédisent pas la performance sur un site malien en production.

Les sources HTML prennent maintenant en compte l'assistant LangGraph/Ollama facultatif. Les PDF actuellement présents dans `pdf/` sont les exports antérieurs et ne reflètent pas cette extension. Réimprimez les deux sources et vérifiez les dix pages avant de soumettre; le moteur d'export visuel n'était pas disponible dans l'environnement de préparation.

## Pièces du dossier

- `pdf/CyberShield_AI_Dossier_JNC_2026.pdf` : dossier de candidature révisé, 7 pages A4.
- `pdf/CyberShield_AI_Fiche_Technique_JNC_2026.pdf` : fiche technique révisée, 3 pages A4.
- `dossier.html` et `fiche-technique.html` : sources éditables de ces PDF.
- `verify_pdf_exports.py` : vérificateur local des signatures PDF, du nombre de pages et du format A4.
- `CANDIDATURE_FORMULAIRE.md` : réponses prêtes à copier dans le formulaire officiel.
- `PROTOCOLE_PILOTE.md` : protocole autorisé, en observation et avec revue aveugle.
- `SECURITE_ET_MODELE_DE_MENACE.md` : contrôles, limites, risques résiduels et plan de revue indépendante.
- `ENTRETIENS_ET_MODELE_ECONOMIQUE.md` : plan de découverte utilisateur et stratégie commerciale à valider.
- `PITCH_ET_DEMONSTRATION.md` : déroulé de démonstration et pitch de trois minutes.
- `GRILLE_JURY_ET_POSITIONNEMENT.md` : critères officiels, preuves disponibles, comparaison de portée avec OWASP CRS et seuils de validation à obtenir.

## Vérifications avant envoi

1. Confirmer l'orthographe des noms, les rôles, l'accord de chaque membre et la composition de l'équipe (maximum quatre personnes selon le concours).
2. Compléter les coordonnées dans le formulaire; elles ne sont pas reproduites dans les documents joints.
3. Ouvrir les deux PDF du sous-dossier `pdf/` et inspecter les dix pages à l’écran ou sur papier; les exports ont été générés automatiquement mais n’ont pas pu être rendus en images dans l’environnement de préparation.
4. Ne présenter aucun pilote, partenaire, audit externe, test d'intrusion ou indicateur terrain comme déjà réalisé.
5. Vérifier les consignes et la date de clôture directement auprès de l'AMRTP. Le programme public indique les JNC du 26 au 30 octobre 2026, mais ne suffit pas à établir la date limite de candidature.
6. Joindre une vidéo réelle et une lettre d'accueil d'un site pilote uniquement si elles ont été effectivement obtenues.

## État de préparation

Les documents corrigent et livrent le travail réalisable sans tiers : preuves et limites réconciliées, exports PDF, formulaire prérempli, protocole pilote, grille de jury, comparaison de portée et conducteur de démonstration. Ils ne remplacent pas les validations externes : rôles/consentements de l’équipe, date limite confirmée auprès de l’AMRTP, entretiens conduits, autorisation/partenaire pilote, audit indépendant, mesure de charge et vidéo réellement enregistrée.

## Sources de preuve du dépôt

- `README.md` : déploiement, contrôles de sécurité, périmètre et précautions de pilote.
- `ia/README.md` : architecture du MLP, jeux, protocole d'évaluation et limites.
- `ia/models/training_report.json`, `ia/models/external_evaluation.json` et `ia/models/honeypot_evaluation.json` : empreintes, matrices de confusion et métriques calculées.
- `scripts/pilot_metrics.py` : création d'un échantillon aléatoire aveugle et calcul des métriques de revue.

