<?php
/**
 * LOGIN VULNÉRABLE - Démonstration SQL Injection
 * Contexte : connexion pour accéder au paiement (e-commerce)
 */
require_once 'config.php';

$conn = getDatabaseConnection();
$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // VULNÉRABILITÉ : concaténation directe, aucune protection
    $sql = "SELECT id, username, email, role FROM users WHERE username = '$username' AND password = '$password'";
    try {
        $result = mysqli_query($conn, $sql);
    } catch (mysqli_sql_exception $e) {
        $result = false;
    }

    // Accepter dès qu'au moins 1 ligne (SQLi OR 1=1, UNION, etc.)
    if ($result && mysqli_num_rows($result) >= 1) {
        $user = mysqli_fetch_assoc($result);
        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['email'] = $user['email'] ?? '';
        $_SESSION['role'] = $user['role'] ?? 'user';
        $_SESSION['login_time'] = time();
        $_SESSION['logged_in'] = true;
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $redirect = $_POST['redirect'] ?? $_GET['redirect'] ?? '';
        $target = ($redirect === 'paiement') ? 'paiement.php' : 'dashboard.php';
        header('Location: ' . $target);
        exit;
    }

    $error = "Identifiants incorrects ou compte inactif.";
}
?>
<!DOCTYPE html>
<html lang="fr" data-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - Application Vulnérable</title>
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
            <p class="subtitle">Connectez-vous pour accéder au paiement (utilisez les payloads dans les champs ci-dessous)</p>
           
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
                <input type="hidden" name="redirect" value="<?php echo htmlspecialchars($_GET['redirect'] ?? ''); ?>">
                <div class="form-group">
                    <label for="username">Nom d'utilisateur</label>
                    <input type="text" id="username" name="username" 
                           placeholder="Entrez votre nom d'utilisateur"
                           value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
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
