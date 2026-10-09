<?php
require_once __DIR__ . '/config.php';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    validate_csrf_token();
    if (!empty($_SESSION['user_id'])) {
        log_user_action((int) $_SESSION['user_id'], 'Déconnexion');
    }
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 42000, 'path' => $params['path'], 'domain' => $params['domain'],
            'secure' => $params['secure'], 'httponly' => $params['httponly'], 'samesite' => $params['samesite'] ?? 'Lax',
        ]);
    }
    session_destroy();
    header('Location: login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Déconnexion — CyberShield AI</title><link rel="stylesheet" href="theme.css?v=<?= (int) filemtime(__DIR__ . '/theme.css') ?>"></head>
<body><main class="container"><div class="form-container">
<h1>Se déconnecter</h1>
<p>Votre session et votre panier de démonstration seront fermés.</p>
<form method="post" action="logout.php">
<input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
<button class="submit-btn" type="submit">Confirmer la déconnexion</button>
</form>
<div class="footer-links"><a href="dashboard.php">Retour à mon espace</a><a href="search.php">Catalogue</a></div>
</div></main></body></html>
