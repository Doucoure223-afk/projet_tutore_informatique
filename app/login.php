<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/AdminTotp.php';
require_once __DIR__ . '/LoginThrottle.php';
$error = '';
$success = isset($_GET['registered']) ? 'Compte créé. Vous pouvez vous connecter.' : '';
if (isset($_GET['mfa_expired'])) { $success = 'La configuration MFA a expiré. Reconnectez-vous pour recommencer.'; }
if (isset($_GET['mfa_already_set'])) { $success = 'Le second facteur est déjà actif. Saisissez votre code pour vous connecter.'; }
$redirect = input_text($_POST, 'redirect', input_text($_GET, 'redirect'));
$target = $redirect === 'paiement' ? 'paiement.php' : 'dashboard.php';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST' && current_user()) {
    header('Location: ' . $target);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    validate_csrf_token();
    $username = trim(input_text($_POST, 'username'));
    $password = input_text($_POST, 'password');
    $clientIp = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
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
?>
<!DOCTYPE html>
<html lang="fr" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion — CyberShield AI</title>
    <script>(function(){var t=localStorage.getItem('theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);})();</script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="style_login.css">
</head>
<body>
    <div class="container">
        <button type="button" class="theme-toggle-login" id="themeToggleLogin" title="Changer de thème" aria-label="Changer de thème">
            <i class="fas fa-moon" id="themeIconLogin"></i>
        </button>
        <div class="header">
            <div class="shield-icon">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="#818cf8" xmlns="http://www.w3.org/2000/svg">
                    <path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6l-8-4zm0 2.18l6 3v5.82c0 4.35-2.78 8.43-6 9.82-3.22-1.39-6-5.47-6-9.82V7.18l6-3z"/>
                </svg>
            </div>
            <h1>Connexion</h1>
            <p class="subtitle">Connectez-vous pour retrouver votre espace et tester un achat simulé.</p>
           
        </div>
        
        <div class="form-container">
            <?php if ($error): ?>
                <div class="error">
                    <strong>Erreur:</strong> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?php echo escape_output($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="redirect" value="<?php echo escape_output($redirect); ?>">
                <div class="form-group">
                    <label for="username">Nom d'utilisateur</label>
                    <input type="text" id="username" name="username" 
                           placeholder="Entrez votre nom d'utilisateur"
                           value="<?php echo escape_output(input_text($_POST, 'username')); ?>"
                           required>
                </div>
                <div class="form-group">
                    <label for="password">Mot de passe</label>
                    <input type="password" id="password" name="password" 
                           placeholder="Entrez votre mot de passe"
                           required>
                </div>
                <div class="form-group">
                    <label for="totp_code">Code d’authentification</label>
                    <input type="text" id="totp_code" name="totp_code" inputmode="numeric" autocomplete="one-time-code"
                           pattern="[0-9]{6}" maxlength="6" placeholder="Requis pour un administrateur">
                </div>
                <input type="submit" name="Envoyer" class="submit-btn" value="Se connecter">
            </form>
            
            <div class="footer-links">
                <a href="search.php">Recherche</a>
                <a href="panier.php">Panier</a>
                <a href="inscription.php">Créer un compte</a>
                <a href="setup.php">Première installation</a>
            </div>
        </div>
    </div>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var theme = document.documentElement.getAttribute('data-theme') || 'light';
            var btn = document.getElementById('themeToggleLogin');
            var icon = document.getElementById('themeIconLogin');
            if (btn && icon) {
                icon.className = theme === 'light' ? 'fas fa-moon' : 'fas fa-sun';
                btn.addEventListener('click', function() {
                    var next = theme === 'light' ? 'dark' : 'light';
                    theme = next;
                    localStorage.setItem('theme', next);
                    document.documentElement.setAttribute('data-theme', next);
                    icon.className = next === 'light' ? 'fas fa-moon' : 'fas fa-sun';
                });
            }
        });
    </script>
</body>
</html>
