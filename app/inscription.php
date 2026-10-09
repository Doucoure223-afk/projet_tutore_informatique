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
?>



<!DOCTYPE html>
<html lang="fr">
        <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                 <link rel="stylesheet" href="theme.css?v=<?= (int) filemtime(__DIR__ . '/theme.css') ?>">
                <title>Inscription — CyberShield AI</title>
        </head>
        <body>
            <div class="container">   
                        <div class="header">
                            <h1><span class="vulnerability-badge">Créer un compte</span></h1>
                            <p class="subtitle">Un compte permet d’accéder à l’espace de démonstration et au parcours d’achat simulé.</p>
                        </div>

                        <div class="form-container">
                            <?= (isset($error)) ? '<div class="error"><strong>'.escape_output($error).'</strong> </div>' :'' ?>
                            <form action="" method="post">
                                    <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                                    <div class="form-group">
                                        <label for="username">Nom d'utilisateur</label>
                                        <input type="text" name="username" autocomplete="username" minlength="3" maxlength="50" required placeholder="3 à 50 caractères" id="username">
                                    </div>

                                    <div class="form-group">
                                        <label for="password">Mot de passe</label>
                                        <input type="password" name="password" autocomplete="new-password" minlength="8" maxlength="72" required placeholder="8 caractères minimum" id="password">
                                    </div>
                                    <div  class="form-group">
                                        <label for="email">Adresse mail</label>
                                        <input type="email" name="mail" autocomplete="email" maxlength="100" required placeholder="nom@exemple.com" id="email">
                                    </div>

                                    <input type="submit" name="Envoyer" class="submit-btn" value="Créer mon compte">
                            </form>
                            <div class="footer">
                                <p>Vous avez déjà un compte&nbsp;? <a href="login.php">Se connecter</a></p>
                            </div>
                        </div>
                        

            </div> 
        </body>
</html>
