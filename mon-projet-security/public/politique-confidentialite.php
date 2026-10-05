<?php
declare(strict_types=1);

$baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
$title = 'Politique de confidentialité';
?>
<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($title); ?> • SHIELD CORE 2026</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --sc-bg: #060b12;
            --sc-surface: rgba(15, 23, 42, 0.92);
            --sc-border: rgba(148, 163, 184, 0.15);
            --sc-text: #f1f5f9;
            --sc-muted: #94a3b8;
            --sc-primary: #0ea5e9;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Space Grotesk', system-ui, sans-serif;
            background: var(--sc-bg);
            min-height: 100vh;
            color: var(--sc-text);
            line-height: 1.7;
            padding: clamp(24px, 5vw, 48px);
        }
        .wrap {
            max-width: 720px;
            margin: 0 auto;
        }
        .card {
            background: var(--sc-surface);
            border: 1px solid var(--sc-border);
            border-radius: 24px;
            padding: clamp(28px, 5vw, 48px);
            margin-bottom: 24px;
        }
        h1 {
            font-size: clamp(1.5rem, 4vw, 2rem);
            margin-bottom: 8px;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .subtitle { color: var(--sc-muted); font-size: 0.9375rem; margin-bottom: 28px; }
        .card h2 { font-size: 1.125rem; margin: 24px 0 12px; color: var(--sc-text); }
        .card p, .card ul { color: var(--sc-muted); font-size: 0.9375rem; margin-bottom: 12px; }
        .card ul { padding-left: 1.5rem; }
        .back {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--sc-primary);
            text-decoration: none;
            font-weight: 600;
            margin-top: 24px;
        }
        .back:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="card">
            <h1><?php echo htmlspecialchars($title); ?></h1>
            <p class="subtitle">Dernière mise à jour : <?php echo date('d/m/Y'); ?></p>

            <p>Cette politique décrit comment SHIELD CORE 2026 collecte et traite vos données personnelles.</p>

            <h2>1. Données collectées</h2>
            <p>Nous collectons les données nécessaires à la création et à la gestion de votre compte : identifiant, adresse email, mot de passe (stocké de manière sécurisée par hachage), et les informations de connexion (adresse IP, horodatage) à des fins de sécurité.</p>

            <h2>2. Finalités</h2>
            <p>Les données sont utilisées pour l'authentification, la prévention des abus, l'amélioration de la sécurité et le respect des obligations légales.</p>

            <h2>3. Conservation</h2>
            <p>Les données de compte sont conservées tant que le compte est actif. Les logs de sécurité sont conservés selon la durée prévue par notre politique interne (par ex. 90 jours).</p>

            <h2>4. Vos droits</h2>
            <p>Vous pouvez demander l'accès, la rectification ou l'effacement de vos données, dans le respect de la réglementation en vigueur (RGPD le cas échéant). Contactez le support pour toute demande.</p>

            <h2>5. Sécurité</h2>
            <p>Nous mettons en œuvre des mesures techniques et organisationnelles pour protéger vos données (chiffrement, contrôle d'accès, détection d'intrusion).</p>

            <a href="<?php echo htmlspecialchars($baseUrl); ?>/inscription.php" class="back">← Retour à l'inscription</a>
        </div>
    </div>
</body>
</html>
