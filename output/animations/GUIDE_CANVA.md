# Intégrer les animations dans Canva et PowerPoint

Quatre vidéos muettes sont disponibles en 1920 × 1080, à 20 images par seconde. Leur fond crème et leur accent vert reprennent l’identité visuelle de CyberShield AI. Elles décrivent un mécanisme pédagogique et des décisions de filtre, sans exécuter de SQL.

## Parcours conseillé pour la présentation de cinq minutes

1. Dans Canva, ouvrez la diapositive « Démonstration » du diaporama de sept diapositives.
2. Depuis « Importer », ajoutez `00_comparaison_complete_56s.mp4`, puis placez-la sur la diapositive. Préservez le ratio 16:9 et une taille permettant de lire les étiquettes en projection.
3. Gardez les 56 secondes complètes. Préparez une lecture manuelle, lancée au moment où vous introduisez le scénario. Répétez ce démarrage dans le mode Présenter utilisé le jour du jury ; ne supposez pas que le passage sur la diapositive déclenchera automatiquement la vidéo.
4. Commentez la vidéo avec `NARRATION_56S.txt`. Pendant ces 56 secondes, évitez d’ajouter un autre discours technique. À la fin, reprenez la présentation avec la diapositive suivante.
5. Comptez cette minute dans les cinq minutes du pitch. Faites une répétition chronométrée avec les transitions et les actions de souris.

La vidéo complète contient, dans cet ordre : `01_site_vulnerable.mp4` (16 s), `02_blocage_regles.mp4` (18 s), puis `03_decision_mlp.mp4` (22 s). Les trois fichiers séparés permettent aussi de lancer chaque scène manuellement. Si vous préférez cette option, prévoyez trois étapes de démonstration et comptabilisez les clics dans le minutage. Il n’est pas nécessaire d’augmenter le nombre de diapositives de la présentation principale.

## Ce que représente chaque scène

Le navigateur transmet une saisie dans un paramètre HTTP. C’est ensuite le code PHP qui choisit comment construire et exécuter une requête SQL. Il faut conserver cette distinction à l’oral : une entrée utilisateur n’est pas, à elle seule, une requête SQL envoyée directement à la base.

La première vidéo illustre une application volontairement vulnérable qui concatène la saisie dans une instruction de ce type : `SELECT id, username FROM users WHERE username = '<saisie>';`. La valeur fictive `' OR 1=1 -- ` peut modifier la condition lorsque le moteur SQL interprète le texte concaténé. Le schéma `users/username` est pédagogique : aucune instruction SQL n’est exécutée par ces vidéos et le scénario ne prouve ni un contournement d’authentification ni une compromission générale.

La deuxième vidéo reprend la même valeur. Les règles reconnaissent `NUMERIC_BOOLEAN` avec un score heuristique vérifié de 90 sur 100, pour un seuil de blocage de 80. En mode blocage, le middleware arrête le traitement et répond HTTP 403 avant l’accès SQL de l’application. Pour cette valeur, le MLP n’est pas demandé. Le score des règles n’est pas une probabilité.

La troisième vidéo montre un cas ambigu vérifié par les règles, avec la valeur fictive `' OR 'b' > 'a' -- `. Son score heuristique est 60 et requiert une analyse. Elle représente ensuite le fonctionnement conditionnel du MLP : si le score retourné atteint 0,75, CyberShield bloque ; sinon, le traitement peut continuer avec une requête préparée. Aucune prédiction du MLP n’a été mesurée pour cette valeur. Le seuil 0,75 est une configuration réelle du projet, pas une précision ni un taux de détection. Le score du MLP n’est pas calibré ; un verdict positif demeure un signal à examiner.

Les requêtes préparées restent la défense essentielle contre la modification de la structure SQL par une saisie. Elles séparent le texte de la requête et ses valeurs, y compris quand un filtre laisse passer une entrée. L’assistant LLM est consultatif et reste hors du chemin de décision : il ne décide pas de bloquer et n’exécute pas de SQL.

## Mode blocage et mode observation

Les vidéos de CyberShield présentent explicitement un scénario en mode blocage. Lors de l’audit préparatoire, le fichier `.env` local indiquait `CYBERSHIELD_MODE=monitor` ; l’état du service actif n’a pas été vérifié. En mode observation, une entrée signalée par le filtre SQLi est consignée mais l’application poursuit son traitement avec ses requêtes préparées. Ne présentez donc pas une animation de blocage comme la preuve du comportement d’une instance configurée en observation. Pour une démonstration en direct, vérifiez le mode affiché dans la console avant de commencer.

## Si le support final est un PowerPoint

Le guide officiel Canva précise les limites du format PPTX concernant les animations et les vidéos intégrées : [Types de fichiers disponibles au téléchargement](https://www.canva.com/help/download-file-types/). Ne comptez pas sur leur conservation automatique lors de l’exportation.

Exportez le diaporama Canva au format PPTX, ouvrez-le dans PowerPoint, puis insérez les MP4 depuis votre ordinateur, dans la diapositive de démonstration. Choisissez un démarrage au clic pour conserver la maîtrise du discours et testez la lecture dans le mode Diaporama. Enregistrez le PPTX après l’insertion. La procédure est documentée par Microsoft : [Insérer et lire un fichier vidéo à partir de votre ordinateur](https://support.microsoft.com/fr-fr/powerpoint/insert-and-play-a-video-file-from-your-computer). Gardez aussi les MP4 dans le dossier de présentation pour pouvoir les lire directement si nécessaire.

Aucune modification du diaporama Canva ou PowerPoint existant n’est effectuée par ces fichiers. La présence de ces animations ne constitue aucune certification ou preuve de conformité ISO.

## Consigne à copier dans Canva IA

« Dans la diapositive Démonstration de mon diaporama CyberShield AI, prévois une grande zone vidéo 16:9 pour le fichier importé `00_comparaison_complete_56s.mp4`. Conserve les 56 secondes et prévois un lancement manuel à vérifier dans le mode Présenter. Garde une page aérée, fond crème, accent vert forêt, sans puces ni dégradés. Utilise le titre “De la saisie HTTP à la décision de sécurité” et une mention lisible “Simulation pédagogique — scénario en mode blocage”. Les trois séquences montrent un site vulnérable, un arrêt par les règles, puis une décision MLP conditionnelle. N’invente aucune prédiction, statistique ou preuve d’attaque. Le seuil MLP de 0,75 est un seuil de décision. Les requêtes préparées restent essentielles et l’assistant LLM demeure hors du chemin de blocage. Réserve dans les notes orales la narration fournie. N’ajoute pas de certification ISO. »

