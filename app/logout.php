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
require_once __DIR__ . '/store_layout.php';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f5f4f0">
    <title>Déconnexion · CyberShield AI</title>
    <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
    <link rel="stylesheet" href="auth.css?v=<?= (int) filemtime(__DIR__ . '/auth.css') ?>">
</head>
<body class="store-page auth-page">
    <?php store_header('login', current_user()); ?>
    <main class="auth-main auth-main--compact" id="main-content">
        <section class="auth-intro" aria-labelledby="logout-title">
            <p class="store-eyebrow">FIN DE SESSION</p>
            <h1 id="logout-title">À bientôt.</h1>
            <p class="auth-lead">Vous pourrez revenir à votre compte avec vos identifiants habituels.</p>
            <a class="auth-back-link" href="dashboard.php"><span aria-hidden="true">←</span> Retour à mon compte</a>
        </section>
        <section class="auth-panel" aria-labelledby="logout-form-title">
            <div class="auth-state-icon" aria-hidden="true">↗</div>
            <div class="auth-panel-heading"><h2 id="logout-form-title">Se déconnecter ?</h2><p>Votre session sera fermée et le contenu de votre panier sera effacé.</p></div>
            <form method="post" action="logout.php" class="auth-form">
                <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                <button class="store-button store-button--primary auth-submit" type="submit">Confirmer la déconnexion</button>
            </form>
            <a class="store-button store-button--secondary auth-submit auth-cancel" href="dashboard.php">Rester connecté</a>
        </section>
    </main>
    <?php store_footer(); ?>
</body>
</html>
