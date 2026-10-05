<?php
declare(strict_types=1);

$baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
$title = 'Conditions d\'utilisation';
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

            <p>En utilisant la plateforme SHIELD CORE 2026, vous acceptez les présentes conditions.</p>

            <h2>1. Objet</h2>
            <p>Ces conditions régissent l'accès et l'utilisation du système de sécurité et des services associés.</p>

            <h2>2. Compte utilisateur</h2>
            <p>Vous êtes responsable de la confidentialité de vos identifiants et de toutes les activités réalisées depuis votre compte.</p>

            <h2>3. Usage autorisé</h2>
            <p>L'utilisation du service doit rester conforme à la loi et ne pas porter atteinte aux droits des tiers. Toute tentative d'intrusion, d'abus ou d'exploitation de vulnérabilités est interdite.</p>

            <h2>4. Données et confidentialité</h2>
            <p>Le traitement des données personnelles est décrit dans la <a href="<?php echo htmlspecialchars($baseUrl); ?>/politique-confidentialite.php" style="color: var(--sc-primary);">politique de confidentialité</a>.</p>

            <h2>5. Contact</h2>
            <p>Pour toute question : contactez le support avec l'identifiant de votre demande.</p>

            <a href="<?php echo htmlspecialchars($baseUrl); ?>/inscription.php" class="back">← Retour à l'inscription</a>
        </div>
    </div>
</body>
</html>
