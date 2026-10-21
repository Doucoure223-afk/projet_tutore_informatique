<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/AdminTotp.php';
require_once __DIR__ . '/LoginThrottle.php';
$error = '';
$success = isset($_GET['registered']) ? 'Compte créé. Vous pouvez vous connecter.' : '';
if (isset($_GET['mfa_expired'])) { $success = 'La configuration MFA a expiré. Reconnectez-vous pour recommencer.'; }
if (isset($_GET['mfa_already_set'])) { $success = 'Le second facteur est déjà actif. Saisissez votre code pour vous connecter.'; }
$redirect = input_text($_POST, 'redirect', input_text($_GET, 'redirect'));
$target = match ($redirect) {
    'paiement' => 'paiement.php',
    'console' => '../security/dashboard.php',
    default => 'dashboard.php',
};
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST' && current_user()) {
    header('Location: ' . $target);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    validate_csrf_token();
    $username = trim(input_text($_POST, 'username'));
    $password = input_text($_POST, 'password');
    $clientIp = cybershield_client_ip();
    $loginThrottle = null;
    $attemptAllowed = false;
    try {
        $loginThrottle = new LoginThrottle(rtrim(getenv('CYBERSHIELD_LOG_DIR') ?: __DIR__ . '/../logs', '/\\'));
        $attemptAllowed = $loginThrottle->beginAttempt($username, $clientIp);
    } catch (Throwable $exception) {
        $error = 'Connexion indisponible. Réessayez dans quelques instants.';
    }
    if (!$attemptAllowed) {
        if ($error === '') { $error = 'Trop de tentatives. Réessayez dans 15 minutes.'; }
    } else {
    $result = execute_query_secure('SELECT id, username, email, role, password FROM users WHERE username = ? AND active = 1 LIMIT 1', [$username]);
    $user = $result ? $result->fetch_assoc() : null;
    $valid = false;
    if ($user && $password !== '') {
        $stored = (string) $user['password'];
        $isHash = password_get_info($stored)['algo'] !== null;
        $valid = $isHash ? password_verify($password, $stored) : hash_equals($stored, $password);
        $isLegacyDemo = ($user['username'] === 'cybershield_admin' && $user['email'] === 'admin@cybershield.test')
            || ($user['username'] === 'cybershield_client' && $user['email'] === 'client@cybershield.test');
        if ($isLegacyDemo) {
            $valid = false;
        }
    }
    if ($valid) {
        if (!$isHash && password_get_info($stored)['algo'] === null) {
            $replacement = password_hash($password, PASSWORD_DEFAULT);
            execute_query_secure('UPDATE users SET password = ? WHERE id = ?', [$replacement, (int) $user['id']]);
        }
        if (strtolower((string) $user['role']) === 'admin') {
            try {
                $mfa = execute_query_secure('SELECT encrypted_secret FROM admin_mfa WHERE user_id = ? LIMIT 1', [(int) $user['id']]);
                if (!$mfa) {
                    throw new RuntimeException('Schéma MFA indisponible.');
                }
                $mfaRecord = $mfa->fetch_assoc();
                if (!$mfaRecord) {
                    $_SESSION['pending_admin_mfa_id'] = (int) $user['id'];
                    $_SESSION['pending_admin_mfa_started'] = time();
                    unset($_SESSION['pending_admin_mfa_secret']);
                    $loginThrottle->clear($username, $clientIp);
                    header('Location: mfa-enroll.php', true, 303);
                    exit;
                }
                $secret = AdminTotp::decrypt((string) $mfaRecord['encrypted_secret']);
                if (!AdminTotp::verify($secret, input_text($_POST, 'totp_code'))) {
                    throw new RuntimeException('Code de vérification incorrect.');
                }
            } catch (Throwable $exception) {
                $error = $exception instanceof RuntimeException && $exception->getMessage() === 'Code de vérification incorrect.'
                    ? 'Identifiants ou code de vérification incorrects.'
                    : 'Connexion administrateur indisponible. Vérifiez la configuration MFA et réessayez.';
            }
            if ($error === '') {
                $loginThrottle->clear($username, $clientIp);
                establish_user_session($user);
                header('Location: ' . $target);
                exit;
            }
        } else {
            $loginThrottle->clear($username, $clientIp);
            establish_user_session($user);
            header('Location: ' . $target);
            exit;
        }
    }
    $error = 'Identifiants incorrects ou compte inactif.';
    }
}
require_once __DIR__ . '/store_layout.php';
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion — CyberShield AI</title>
    <meta name="theme-color" content="#f5f4f0">
    <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
    <link rel="stylesheet" href="auth.css?v=<?= (int) filemtime(__DIR__ . '/auth.css') ?>">
</head>
<body class="store-page auth-page">
    <?php store_header('login', null); ?>
    <main class="auth-main" id="main-content">
        <section class="auth-intro" aria-labelledby="login-title">
            <p class="store-eyebrow">VOTRE ESPACE PERSONNEL</p>
            <h1 id="login-title">Le plaisir de vous retrouver.</h1>
            <p class="auth-lead">Connectez-vous pour accéder à votre compte et poursuivre votre commande.</p>
            <div class="auth-intro-divider" aria-hidden="true"></div>
            <div class="auth-reference">
                <span class="auth-reference-number" aria-hidden="true">01</span>
                <div><strong>Votre compte</strong><p>Vos informations et vos dernières activités, réunies au même endroit.</p></div>
            </div>
            <div class="auth-reference">
                <span class="auth-reference-number" aria-hidden="true">02</span>
                <div><strong>Votre sélection</strong><p>Consultez le panier avant de passer au paiement.</p></div>
            </div>
            <a class="auth-back-link" href="search.php"><span aria-hidden="true">←</span> Retour au catalogue</a>
        </section>
        <section class="auth-panel" aria-labelledby="login-form-title">
            <div class="auth-panel-heading"><p class="store-eyebrow">BIENVENUE</p><h2 id="login-form-title">Se connecter</h2><p>Entrez vos identifiants pour continuer.</p></div>
            <?php if ($error): ?>
                <div class="auth-notice auth-notice--error" role="alert">
                    <strong>Connexion impossible</strong><p><?= escape_output($error) ?></p>
                </div>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <div class="auth-notice" role="status"><?= escape_output($success) ?></div>
            <?php endif; ?>
            <form method="POST" action="" class="auth-form">
                <input type="hidden" name="csrf_token" value="<?php echo escape_output($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="redirect" value="<?php echo escape_output($redirect); ?>">
                <div class="auth-field">
                    <label for="username">Nom d'utilisateur</label>
                    <input type="text" id="username" name="username" autocomplete="username"
                           value="<?php echo escape_output(input_text($_POST, 'username')); ?>"
                           required>
                </div>
                <div class="auth-field">
                    <label for="password">Mot de passe</label>
                    <input type="password" id="password" name="password" autocomplete="current-password" required>
                </div>
                <details class="auth-details auth-admin-details" <?= input_text($_POST, 'totp_code') !== '' ? 'open' : '' ?>>
                    <summary>Connexion administrateur</summary>
                    <div class="auth-field">
                        <label for="totp_code">Code de votre application</label>
                        <input type="text" id="totp_code" name="totp_code" inputmode="numeric" autocomplete="one-time-code"
                               pattern="[0-9]{6}" maxlength="6" aria-describedby="totp-help" placeholder="000000">
                        <small id="totp-help" class="auth-hint">Le code à six chiffres est nécessaire si le second facteur est activé sur votre compte administrateur.</small>
                    </div>
                </details>
                <button type="submit" name="Envoyer" class="store-button store-button--primary auth-submit">Se connecter <span aria-hidden="true">→</span></button>
            </form>
            <p class="auth-switch">Pas encore de compte ? <a href="inscription.php">Créer mon compte</a></p>
            <a class="auth-install-link" href="setup.php">Première installation administrateur</a>
        </section>
    </main>
    <?php store_footer(); ?>
</body>
</html>
