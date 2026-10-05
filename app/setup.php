<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
header('Cache-Control: no-store');

$remoteIp = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
$packedIp = @inet_pton($remoteIp);
$isLocal = PHP_SAPI === 'cli'
    || in_array($remoteIp, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true)
    || (is_string($packedIp) && strlen($packedIp) === 4 && ord($packedIp[0]) === 127);
if (!$isLocal) {
    http_response_code(404);
    exit('Cette page de première configuration est disponible uniquement sur la machine locale.');
}

function setup_admin_exists(mysqli $connection): bool
{
    $result = $connection->query("SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = 1
        AND NOT (username = 'cybershield_admin' AND email = 'admin@cybershield.test')");
    return (int) $result->fetch_row()[0] > 0;
}

$error = '';
$complete = false;
try {
    $complete = setup_admin_exists($conn);
} catch (Throwable $exception) {
    $error = 'Configuration de base indisponible. Importez le schéma SQL à jour puis rechargez cette page.';
}

if (!$complete && $error === '' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    validate_csrf_token();
    $username = trim(input_text($_POST, 'username'));
    $email = trim(input_text($_POST, 'email'));
    $password = input_text($_POST, 'password');
    $confirmation = input_text($_POST, 'password_confirmation');

    if (mb_strlen($username) < 3 || mb_strlen($username) > 50 || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 100) {
        $error = 'Indiquez un nom de 3 à 50 caractères et une adresse e-mail valide.';
    } elseif (strlen($password) < 12 || strlen($password) > 72) {
        $error = 'Choisissez un mot de passe d’au moins 12 caractères (72 au maximum).';
    } elseif (!hash_equals($password, $confirmation)) {
        $error = 'Les deux mots de passe ne correspondent pas.';
    } else {
        $lockAcquired = false;
        try {
            $lockResult = $conn->query("SELECT GET_LOCK('cybershield-initial-admin-setup', 5)");
            $lockAcquired = (int) $lockResult->fetch_row()[0] === 1;
            if (!$lockAcquired) {
                throw new RuntimeException('La configuration est déjà en cours sur une autre session.');
            }
            if (setup_admin_exists($conn)) {
                $complete = true;
            } else {
                $duplicate = $conn->prepare('SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1');
                $duplicate->bind_param('ss', $username, $email);
                $duplicate->execute();
                if ($duplicate->get_result()->num_rows > 0) {
                    $error = 'Ce nom ou cette adresse e-mail est déjà utilisé.';
                } else {
                    $conn->begin_transaction();
                    try {
                        $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                        $insert = $conn->prepare("INSERT INTO users (username, password, email, role, active) VALUES (?, ?, ?, 'admin', 1)");
                        $insert->bind_param('sss', $username, $passwordHash, $email);
                        $insert->execute();
                        $adminId = (int) $conn->insert_id;
                        // Retire les comptes partagés des anciennes installations après création du compte propre.
                        $conn->query("UPDATE users SET active = 0 WHERE
                            (username = 'cybershield_admin' AND email = 'admin@cybershield.test') OR
                            (username = 'cybershield_client' AND email = 'client@cybershield.test')");
                        $conn->commit();

                        session_regenerate_id(true);
                        unset($_SESSION['logged_in'], $_SESSION['user_id'], $_SESSION['username'], $_SESSION['email'], $_SESSION['role']);
                        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                        $_SESSION['pending_admin_mfa_id'] = $adminId;
                        $_SESSION['pending_admin_mfa_started'] = time();
                        unset($_SESSION['pending_admin_mfa_secret']);
                        header('Location: mfa-enroll.php', true, 303);
                        exit;
                    } catch (Throwable $exception) {
                        $conn->rollback();
                        throw $exception;
                    }
                }
            }
        } catch (Throwable $exception) {
            error_log('CyberShield : configuration initiale administrateur échouée (' . get_class($exception) . ').');
            if ($error === '') {
                $error = $exception instanceof RuntimeException
                    ? $exception->getMessage()
                    : 'La configuration initiale a échoué. Vérifiez le schéma de base et réessayez.';
            }
        } finally {
            if ($lockAcquired) {
                $conn->query("SELECT RELEASE_LOCK('cybershield-initial-admin-setup')");
            }
        }
    }
}
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Première configuration · CyberShield AI</title>
  <link rel="stylesheet" href="style_login.css">
</head>
<body>
  <main class="container">
    <header class="header">
      <h1>Première configuration</h1>
      <p class="subtitle">Créez le compte administrateur propre à cette installation.</p>
    </header>
    <section class="form-container">
      <?php if ($error !== ''): ?><p class="error" role="alert"><?= escape_output($error) ?></p><?php endif; ?>
      <?php if ($complete): ?>
        <p class="success" role="status">Un administrateur est déjà configuré. La configuration initiale est fermée.</p>
        <div class="footer-links"><a href="login.php">Aller à la connexion</a></div>
      <?php elseif ($error === ''): ?>
        <p class="subtitle">Ce compte aura accès aux réglages de sécurité. Le mot de passe doit faire au moins 12 caractères et le second facteur sera activé avant la première session.</p>
        <form method="post" action="setup.php">
          <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
          <div class="form-group"><label for="username">Nom d’utilisateur</label><input id="username" name="username" type="text" maxlength="50" autocomplete="username" required></div>
          <div class="form-group"><label for="email">Adresse e-mail</label><input id="email" name="email" type="email" maxlength="100" autocomplete="email" required></div>
          <div class="form-group"><label for="password">Mot de passe</label><input id="password" name="password" type="password" minlength="12" maxlength="72" autocomplete="new-password" required></div>
          <div class="form-group"><label for="password_confirmation">Confirmer le mot de passe</label><input id="password_confirmation" name="password_confirmation" type="password" minlength="12" maxlength="72" autocomplete="new-password" required></div>
          <button class="submit-btn" type="submit">Créer l’administrateur</button>
        </form>
      <?php endif; ?>
    </section>
  </main>
</body>
</html>
