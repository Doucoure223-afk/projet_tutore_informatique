<?php
require_once __DIR__ . '/config.php';
$error = '';
$success = isset($_GET['registered']) ? 'Compte créé. Vous pouvez vous connecter.' : '';
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
    $result = execute_query_secure('SELECT id, username, email, role, password FROM users WHERE username = ? AND active = 1 LIMIT 1', [$username]);
    $user = $result ? $result->fetch_assoc() : null;
    $valid = false;
    if ($user && $password !== '') {
        $stored = (string) $user['password'];
        $isHash = password_get_info($stored)['algo'] !== null;
        $valid = $isHash ? password_verify($password, $stored) : hash_equals($stored, $password);
    }
    if ($valid) {
        if (!$isHash && password_get_info($stored)['algo'] === null) {
            $replacement = password_hash($password, PASSWORD_DEFAULT);
            execute_query_secure('UPDATE users SET password = ? WHERE id = ?', [$replacement, (int) $user['id']]);
        }
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['login_time'] = time();
        $_SESSION['logged_in'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        log_user_action((int) $user['id'], 'Connexion réussie');
        header('Location: ' . $target);
        exit;
    }
    $error = 'Identifiants incorrects ou compte inactif.';
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
    <link rel="stylesheet" href="theme.css">
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
                <input type="submit" name="Envoyer" class="submit-btn" value="Se connecter">
            </form>
            
            <div class="footer-links">
                <a href="search.php">Recherche</a>
                <a href="panier.php">Panier</a>
                <a href="inscription.php">Créer un compte</a>
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
