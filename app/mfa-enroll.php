<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/AdminTotp.php';
header('Cache-Control: no-store');

if (!empty($_SESSION['logged_in'])) {
    header('Location: dashboard.php', true, 303);
    exit;
}
$adminId = (int) ($_SESSION['pending_admin_mfa_id'] ?? 0);
$startedAt = (int) ($_SESSION['pending_admin_mfa_started'] ?? 0);
if ($adminId < 1 || $startedAt < time() - 600) {
    unset($_SESSION['pending_admin_mfa_id'], $_SESSION['pending_admin_mfa_started'], $_SESSION['pending_admin_mfa_secret']);
    header('Location: login.php?mfa_expired=1', true, 303);
    exit;
}

$userQuery = execute_query_secure('SELECT id, username, email, role FROM users WHERE id = ? AND role = ? AND active = 1 LIMIT 1', [$adminId, 'admin']);
$user = $userQuery ? $userQuery->fetch_assoc() : null;
if (!$user) {
    unset($_SESSION['pending_admin_mfa_id'], $_SESSION['pending_admin_mfa_started'], $_SESSION['pending_admin_mfa_secret']);
    header('Location: login.php', true, 303);
    exit;
}
$existing = execute_query_secure('SELECT user_id FROM admin_mfa WHERE user_id = ? LIMIT 1', [$adminId]);
if (!$existing) {
    http_response_code(503);
    exit('Schéma MFA indisponible. Importez le schéma SQL à jour.');
}
if ($existing->fetch_assoc()) {
    unset($_SESSION['pending_admin_mfa_id'], $_SESSION['pending_admin_mfa_started'], $_SESSION['pending_admin_mfa_secret']);
    header('Location: login.php?mfa_already_set=1', true, 303);
    exit;
}

try {
    if (empty($_SESSION['pending_admin_mfa_secret'])) {
        $_SESSION['pending_admin_mfa_secret'] = AdminTotp::generateSecret();
    }
    $secret = (string) $_SESSION['pending_admin_mfa_secret'];
    $provisioningUri = AdminTotp::provisioningUri($secret, (string) $user['username']);
} catch (Throwable $exception) {
    error_log('CyberShield : préparation du second facteur impossible (' . get_class($exception) . ').');
    http_response_code(503);
    exit('Configuration du second facteur indisponible. Vérifiez PHP OpenSSL et le stockage privé des clés.');
}

$error = '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    validate_csrf_token();
    $code = input_text($_POST, 'totp_code');
    if (!AdminTotp::verify($secret, $code)) {
        $error = 'Code incorrect ou expiré. Vérifiez l’heure de votre appareil et réessayez.';
    } else {
        try {
            $encrypted = AdminTotp::encrypt($secret);
            $insert = $conn->prepare('INSERT INTO admin_mfa (user_id, encrypted_secret) VALUES (?, ?)');
            $insert->bind_param('is', $adminId, $encrypted);
            $insert->execute();
            establish_user_session($user);
            header('Location: dashboard.php', true, 303);
            exit;
        } catch (Throwable $exception) {
            error_log('CyberShield : enregistrement du second facteur impossible (' . get_class($exception) . ').');
            $error = 'Le second facteur n’a pas pu être enregistré. Vérifiez le schéma de base et le dossier privé des journaux.';
        }
    }
}
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Activer le second facteur · CyberShield AI</title>
  <link rel="stylesheet" href="theme.css?v=<?= (int) filemtime(__DIR__ . '/theme.css') ?>">
</head>
<body>
  <main class="container">
    <header class="header">
      <h1>Protéger l’accès administrateur</h1>
      <p class="subtitle">Ajoutez ce compte à une application d’authentification compatible avec les codes TOTP.</p>
    </header>
    <section class="form-container">
      <?php if ($error !== ''): ?><p class="error" role="alert"><?= escape_output($error) ?></p><?php endif; ?>
      <ol>
        <li>Dans votre application, choisissez l’ajout manuel d’une clé.</li>
        <li>Nom du compte : <strong><?= escape_output($user['username']) ?></strong> · Émetteur : <strong>CyberShield AI</strong>.</li>
        <li>Saisissez cette clé secrète : <code><?= escape_output($secret) ?></code></li>
      </ol>
      <details>
        <summary>Afficher l’URI de configuration</summary>
        <p><code><?= escape_output($provisioningUri) ?></code></p>
      </details>
      <form method="post" action="mfa-enroll.php">
        <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
        <div class="form-group"><label for="totp_code">Code à six chiffres de votre application</label>
          <input id="totp_code" name="totp_code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required></div>
        <button class="submit-btn" type="submit">Valider et terminer</button>
      </form>
      <p class="subtitle">Gardez votre application d’authentification disponible. En cas de perte, l’administrateur système devra réinitialiser la configuration MFA depuis la base de données.</p>
    </section>
  </main>
</body>
</html>
