<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/LocalSetupAccess.php';
header('Cache-Control: no-store');

if (!cybershield_local_setup_allowed($_SERVER)) {
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
require_once __DIR__ . '/store_layout.php';
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Première configuration · CyberShield AI</title>
  <meta name="theme-color" content="#f5f4f0">
  <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
  <link rel="stylesheet" href="auth.css?v=<?= (int) filemtime(__DIR__ . '/auth.css') ?>">
</head>
<body class="store-page auth-page">
  <?php store_header('login', null); ?>
  <main class="auth-main" id="main-content">
    <section class="auth-intro" aria-labelledby="setup-title">
      <p class="store-eyebrow">PREMIÈRE INSTALLATION</p>
      <h1 id="setup-title">Votre installation commence ici.</h1>
      <p class="auth-lead">Créez le compte qui donnera accès aux réglages de sécurité de cette installation.</p>
      <div class="auth-intro-divider" aria-hidden="true"></div>
      <ol class="auth-steps">
        <li><span aria-hidden="true">1</span><div><strong>Créez l’administrateur</strong><p>Choisissez vos identifiants et un mot de passe d’au moins 12 caractères.</p></div></li>
        <li><span aria-hidden="true">2</span><div><strong>Associez votre application</strong><p>La double vérification sera configurée à l’étape suivante.</p></div></li>
      </ol>
      <a class="auth-back-link" href="login.php"><span aria-hidden="true">←</span> Retour à la connexion</a>
    </section>
    <section class="auth-panel" aria-labelledby="setup-form-title">
      <div class="auth-panel-heading"><p class="store-eyebrow">CONFIGURATION LOCALE</p><h2 id="setup-form-title"><?= $complete ? 'Déjà configuré' : 'Créer l’administrateur' ?></h2><p><?= $complete ? 'Un compte administrateur existe sur cette installation.' : 'Tous les champs sont nécessaires.' ?></p></div>
      <?php if ($error !== ''): ?><div class="auth-notice auth-notice--error" role="alert"><strong>Configuration indisponible</strong><p><?= escape_output($error) ?></p></div><?php endif; ?>
      <?php if ($complete): ?>
        <div class="auth-notice" role="status">La configuration initiale est fermée. Connectez-vous avec le compte administrateur existant.</div>
        <a class="store-button store-button--primary auth-submit" href="login.php">Aller à la connexion <span aria-hidden="true">→</span></a>
      <?php elseif ($error === ''): ?>
        <form method="post" action="setup.php" class="auth-form">
          <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
          <div class="auth-field"><label for="username">Nom d’utilisateur</label><input id="username" name="username" type="text" minlength="3" maxlength="50" autocomplete="username" value="<?= escape_output(input_text($_POST, 'username')) ?>" aria-describedby="setup-username-help" required><small class="auth-hint" id="setup-username-help">De 3 à 50 caractères.</small></div>
          <div class="auth-field"><label for="email">Adresse e-mail</label><input id="email" name="email" type="email" maxlength="100" autocomplete="email" placeholder="vous@exemple.com" value="<?= escape_output(input_text($_POST, 'email')) ?>" required></div>
          <div class="auth-field"><label for="password">Mot de passe</label><input id="password" name="password" type="password" minlength="12" maxlength="72" autocomplete="new-password" aria-describedby="setup-password-help" required><small class="auth-hint" id="setup-password-help">De 12 à 72 caractères.</small></div>
          <div class="auth-field"><label for="password_confirmation">Confirmer le mot de passe</label><input id="password_confirmation" name="password_confirmation" type="password" minlength="12" maxlength="72" autocomplete="new-password" required></div>
          <button class="store-button store-button--primary auth-submit" type="submit">Créer l’administrateur <span aria-hidden="true">→</span></button>
        </form>
      <?php endif; ?>
    </section>
  </main>
  <?php store_footer(); ?>
</body>
</html>
