<?php
declare(strict_types=1);

$baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
$dashboardUrl = $baseUrl ? $baseUrl . '/dashboard.php' : 'dashboard.php';
$loginUrl = $baseUrl ? $baseUrl . '/login.php' : 'login.php';
?>
<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>À propos • Security 2026</title>
    <script>(function(){var t=localStorage.getItem('theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);})();</script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root, [data-theme="dark"] {
            --ap-bg: #0f172a;
            --ap-card: rgba(30, 41, 59, 0.8);
            --ap-border: #334155;
            --ap-text: #f8fafc;
            --ap-muted: #94a3b8;
            --ap-primary: #2563eb;
        }
        [data-theme="light"] {
            --ap-bg: #f1f5f9;
            --ap-card: rgba(255, 255, 255, 0.95);
            --ap-border: #cbd5e1;
            --ap-text: #0f172a;
            --ap-muted: #64748b;
            --ap-primary: #1d4ed8;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--ap-bg);
            color: var(--ap-text);
            min-height: 100vh;
            line-height: 1.6;
            padding: clamp(20px, 5vw, 40px);
        }
        .wrap { max-width: 720px; margin: 0 auto; }
        .card {
            background: var(--ap-card);
            border: 1px solid var(--ap-border);
            border-radius: 16px;
            padding: clamp(24px, 5vw, 40px);
            margin-bottom: 24px;
        }
        h1 {
            font-size: clamp(1.5rem, 4vw, 2rem);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        h1 i { color: var(--ap-primary); }
        .subtitle { color: var(--ap-muted); font-size: 0.9375rem; margin-bottom: 24px; }
        .card h2 { font-size: 1.125rem; margin: 20px 0 10px; color: var(--ap-text); }
        .card h2:first-of-type { margin-top: 0; }
        .card p, .card ul { color: var(--ap-muted); font-size: 0.9375rem; margin-bottom: 10px; }
        .card ul { padding-left: 1.5rem; }
        .back {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--ap-primary);
            text-decoration: none;
            font-size: 0.9rem;
            margin-bottom: 20px;
        }
        .back:hover { text-decoration: underline; }
        .theme-btn {
            position: absolute;
            top: 20px;
            right: 20px;
            width: 44px;
            height: 44px;
            border-radius: 10px;
            border: 1px solid var(--ap-border);
            background: var(--ap-card);
            color: var(--ap-text);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
        }
        .theme-btn:hover { border-color: var(--ap-primary); }
        .header-wrap { position: relative; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="header-wrap">
            <button type="button" class="theme-btn" id="themeBtn" title="Changer de thème" aria-label="Thème">
                <i class="fas fa-moon" id="themeIconAp"></i>
            </button>
            <a href="<?php echo htmlspecialchars($loginUrl); ?>" class="back"><i class="fas fa-arrow-left"></i> Connexion</a>
            <a href="<?php echo htmlspecialchars($dashboardUrl); ?>" class="back" style="margin-left: 12px;"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
        </div>
        <div class="card">
            <h1><i class="fas fa-shield-alt"></i> À propos</h1>
            <p class="subtitle">Système de sécurité SQL Injection • Standard 2026</p>

            <h2>Présentation</h2>
            <p>Ce module protège les applications web contre les injections SQL en analysant les entrées utilisateur, en attribuant un score de risque et en bloquant les requêtes malveillantes. Les incidents sont enregistrés et visibles sur le tableau de bord.</p>

            <h2>Fonctionnalités principales</h2>
            <ul>
                <li><strong>Détection</strong> : patterns OWASP, analyse statistique et par contexte (login, recherche, API, admin).</li>
                <li><strong>Scoring et blocage</strong> : niveaux de risque (NONE à CRITICAL), blocage automatique, analyse IA optionnelle.</li>
                <li><strong>Dashboard</strong> : statistiques, graphiques (24 h / 7 j / 30 j), dernières attaques, Top pays (géolocalisation), export CSV, rapport PDF.</li>
                <li><strong>Rate limiting</strong> : limitation des tentatives de connexion par IP.</li>
                <li><strong>Liste noire / blanche d’IP</strong> : gestion des accès par adresse IP.</li>
                <li><strong>Géolocalisation</strong> : affichage du lieu (pays/ville) pour les IP des incidents.</li>
            </ul>

            <h2>Technologies</h2>
            <p>PHP 8.2+, PDO (requêtes préparées), Monolog, base MySQL/MariaDB. Tests unitaires avec PHPUnit.</p>

            <p style="margin-top: 24px; font-size: 0.85rem; color: var(--ap-muted);">© 2026 – Sécurité de niveau entreprise</p>
        </div>
    </div>
    <script>
        (function() {
            var theme = document.documentElement.getAttribute('data-theme') || 'dark';
            var btn = document.getElementById('themeBtn');
            var icon = document.getElementById('themeIconAp');
            if (btn && icon) {
                icon.className = theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
                btn.addEventListener('click', function() {
                    var next = theme === 'light' ? 'dark' : 'light';
                    theme = next;
                    localStorage.setItem('theme', next);
                    document.documentElement.setAttribute('data-theme', next);
                    icon.className = next === 'light' ? 'fas fa-sun' : 'fas fa-moon';
                });
            }
        })();
    </script>
</body>
</html>
