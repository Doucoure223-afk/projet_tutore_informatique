<?php
require_once __DIR__ . '/config.php';
$error = null;
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    validate_csrf_token();
    $user = trim(input_text($_POST, 'username'));
    $pass = input_text($_POST, 'password');
    $mail = trim(input_text($_POST, 'mail'));
    if (mb_strlen($user) < 3 || mb_strlen($user) > 50 || !filter_var($mail, FILTER_VALIDATE_EMAIL) || strlen($mail) > 100) {
        $error = "Indiquez un nom de 3 à 50 caractères et une adresse e-mail valide.";
    } elseif (strlen($pass) < 8 || strlen($pass) > 72) {
        $error = 'Le mot de passe doit contenir entre 8 et 72 caractères.';
    } else {
        $result = execute_query_secure('SELECT id FROM users WHERE username = ? OR email = ?', [$user, $mail]);
        if (!$result) {
            $error = 'Inscription indisponible pour le moment.';
        } elseif ($result->num_rows > 0) {
            $error = "Ce nom d'utilisateur ou cette adresse e-mail existe déjà.";
        } elseif (execute_query_secure("INSERT INTO users (username, password, email, role, created_at) VALUES (?, ?, ?, 'user', NOW())",
            [$user, password_hash($pass, PASSWORD_DEFAULT), $mail])) {
            header('Location: login.php?registered=1');
            exit;
        } else {
            $error = 'Inscription impossible. Vérifiez les informations saisies.';
        }
    }
}
require_once __DIR__ . '/store_layout.php';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f5f4f0">
    <title>Créer mon compte · CyberShield AI</title>
    <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
    <link rel="stylesheet" href="auth.css?v=<?= (int) filemtime(__DIR__ . '/auth.css') ?>">
</head>
<body class="store-page auth-page">
    <?php store_header('login', null); ?>
    <main class="auth-main" id="main-content">
        <section class="auth-intro" aria-labelledby="register-title">
            <p class="store-eyebrow">FAITES COMME CHEZ VOUS</p>
            <h1 id="register-title">Un compte, votre espace.</h1>
            <p class="auth-lead">Quelques informations suffisent pour créer votre compte et préparer votre commande.</p>
            <div class="auth-intro-divider" aria-hidden="true"></div>
            <div class="auth-reference"><span class="auth-reference-number" aria-hidden="true">01</span><div><strong>Choisissez vos identifiants</strong><p>Votre nom d’utilisateur servira lors de chaque connexion.</p></div></div>
            <div class="auth-reference"><span class="auth-reference-number" aria-hidden="true">02</span><div><strong>Poursuivez à votre rythme</strong><p>Retrouvez le catalogue et vérifiez votre sélection dans le panier.</p></div></div>
            <a class="auth-back-link" href="search.php"><span aria-hidden="true">←</span> Retour au catalogue</a>
        </section>
        <section class="auth-panel" aria-labelledby="register-form-title">
            <div class="auth-panel-heading"><p class="store-eyebrow">INSCRIPTION</p><h2 id="register-form-title">Créer mon compte</h2><p>Tous les champs sont nécessaires.</p></div>
            <?php if (isset($error)): ?><div class="auth-notice auth-notice--error" role="alert"><strong>Vérifiez vos informations</strong><p><?= escape_output($error) ?></p></div><?php endif; ?>
            <form action="" method="post" class="auth-form">
                <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                <div class="auth-field">
                    <label for="username">Nom d’utilisateur</label>
                    <input type="text" name="username" autocomplete="username" minlength="3" maxlength="50" required id="username" aria-describedby="username-help" value="<?= escape_output(input_text($_POST, 'username')) ?>">
                    <small class="auth-hint" id="username-help">De 3 à 50 caractères.</small>
                </div>
                <div class="auth-field">
                    <label for="email">Adresse e-mail</label>
                    <input type="email" name="mail" autocomplete="email" maxlength="100" required placeholder="vous@exemple.com" id="email" value="<?= escape_output(input_text($_POST, 'mail')) ?>">
                </div>
                <div class="auth-field">
                    <label for="password">Mot de passe</label>
                    <input type="password" name="password" autocomplete="new-password" minlength="8" maxlength="72" required id="password" aria-describedby="password-help">
                    <small class="auth-hint" id="password-help">De 8 à 72 caractères. Choisissez un mot de passe que vous n’utilisez pas ailleurs.</small>
                </div>
                <button type="submit" name="Envoyer" class="store-button store-button--primary auth-submit">Créer mon compte <span aria-hidden="true">→</span></button>
            </form>
            <p class="auth-switch">Déjà un compte ? <a href="login.php">Se connecter</a></p>
        </section>
    </main>
    <?php store_footer(); ?>
</body>
</html>
