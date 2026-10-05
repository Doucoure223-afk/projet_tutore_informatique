<?php
/** Shared access control for the local demonstration console. */
function console_require_access(): void
{
    if (!defined('CYBERSHIELD_SKIP_REQUEST')) { define('CYBERSHIELD_SKIP_REQUEST', true); }
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        session_set_cookie_params(['lifetime' => 0, 'path' => '/',
            'secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
            'httponly' => true, 'samesite' => 'Lax']);
        session_start();
    }
    if (!empty($_SESSION['last_activity']) && time() - (int) $_SESSION['last_activity'] > 1800) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    if (empty($_SESSION['initiated'])) {
        session_regenerate_id(true);
        $_SESSION['initiated'] = true;
    }
    $_SESSION['last_activity'] = time();
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: same-origin');
    header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'; img-src 'self' data:; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (PHP_SAPI === 'cli' || in_array($ip, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true)) {
        return;
    }
    if (!empty($_SESSION['logged_in']) && !empty($_SESSION['user_id'])) {
        require_once __DIR__ . '/../app/config.php';
        $user = current_user();
        if ($user && ($user['role'] ?? '') === 'admin') { return; }
    }
    http_response_code(403);
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="fr"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Accès réservé · CyberShield AI</title><link rel="stylesheet" href="console.css"><body><main class="access-card"><p class="eyebrow">CYBERSHIELD AI</p><h1>Console réservée</h1><p class="muted">Ouvrez la console depuis cette machine ou connectez-vous avec un compte administrateur autorisé.</p><a class="button" href="../app/login.php">Se connecter</a></main></body></html>';
    exit;
}

function console_csrf(): string
{
    if (empty($_SESSION['console_csrf_token'])) {
        $_SESSION['console_csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['console_csrf_token'];
}

function console_check_csrf(): void
{
    $token = $_POST['csrf_token'] ?? '';
    if (!is_string($token) || !hash_equals(console_csrf(), $token)) {
        http_response_code(403);
        exit('Formulaire expiré ou invalide. Rechargez la page avant de réessayer.');
    }
}

function console_escape($value): string
{
    return htmlspecialchars(is_scalar($value) || $value === null ? (string) $value : '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function console_logger(): SecurityLogger
{
    $directory = getenv('CYBERSHIELD_LOG_DIR') ?: __DIR__ . '/../logs';
    return new SecurityLogger(rtrim($directory, '/\\') . '/events.jsonl');
}

function console_health(): array
{
    try {
        $status = (new AIAnalyzer())->health();
        return is_array($status) ? $status : ['status' => 'unavailable', 'model_loaded' => false];
    } catch (Throwable $error) {
        return ['status' => 'unavailable', 'model_loaded' => false];
    }
}

function console_sidebar(string $active): void
{
    ?>
    <aside class="sidebar">
        <a class="brand" href="../index.php"><span class="brand-mark">C<span>◆</span></span><span>CyberShield <b>AI</b><small>CONSOLE DE PROTECTION</small></span></a>
        <div class="nav-label">ESPACE SÉCURITÉ</div>
        <nav aria-label="Navigation principale">
            <a class="<?= $active === 'dashboard' ? 'active' : '' ?>" <?= $active === 'dashboard' ? 'aria-current="page"' : '' ?> href="dashboard.php"><span class="nav-symbol">▦</span> Vue d’ensemble</a>
            <a class="<?= $active === 'lab' ? 'active' : '' ?>" <?= $active === 'lab' ? 'aria-current="page"' : '' ?> href="lab.php"><span class="nav-symbol">⌁</span> Laboratoire</a>
            <a href="../app/search.php"><span class="nav-symbol">▤</span> Boutique de démonstration</a>
            <a href="../index.php"><span class="nav-symbol">↗</span> Accueil du projet</a>
        </nav>
        <div class="sidebar-note"><span class="dot"></span> Démonstration locale<p>SQLi · règles + modèle MLP<br>Décisions et traces vérifiables</p></div>
    </aside>
    <?php
}
