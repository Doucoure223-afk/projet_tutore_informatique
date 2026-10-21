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
require_once __DIR__ . '/store_layout.php';
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Activer le second facteur · CyberShield AI</title>
  <meta name="theme-color" content="#f5f4f0">
  <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
  <link rel="stylesheet" href="auth.css?v=<?= (int) filemtime(__DIR__ . '/auth.css') ?>">
</head>
<body class="store-page auth-page">
  <?php store_header('login', null); ?>
  <main class="auth-main" id="main-content">
    <section class="auth-intro" aria-labelledby="enroll-title">
      <p class="store-eyebrow">ACCÈS ADMINISTRATEUR</p>
      <h1 id="enroll-title">Une vérification en plus.</h1>
      <p class="auth-lead">Associez une application d’authentification à votre compte avant d’ouvrir votre première session.</p>
      <div class="auth-intro-divider" aria-hidden="true"></div>
      <ol class="auth-steps">
        <li><span aria-hidden="true">1</span><div><strong>Ajoutez le compte</strong><p>Dans une application compatible TOTP, choisissez l’ajout manuel d’une clé.</p></div></li>
        <li><span aria-hidden="true">2</span><div><strong>Recopiez la clé</strong><p>Utilisez le nom du compte et la clé affichés sur cette page.</p></div></li>
        <li><span aria-hidden="true">3</span><div><strong>Validez le code</strong><p>Saisissez les six chiffres affichés par votre application.</p></div></li>
      </ol>
      <a class="auth-back-link" href="login.php"><span aria-hidden="true">←</span> Retour à la connexion</a>
    </section>
    <section class="auth-panel" aria-labelledby="enroll-form-title">
      <div class="auth-panel-heading"><p class="store-eyebrow">DOUBLE VÉRIFICATION</p><h2 id="enroll-form-title">Associer mon application</h2><p>Gardez votre application à portée de main.</p></div>
      <?php if ($error !== ''): ?><div class="auth-notice auth-notice--error" role="alert"><strong>Vérification impossible</strong><p><?= escape_output($error) ?></p></div><?php endif; ?>
      <dl class="auth-account-details">
        <div><dt>Nom du compte</dt><dd><?= escape_output($user['username']) ?></dd></div>
        <div><dt>Émetteur</dt><dd>CyberShield AI</dd></div>
      </dl>
      <div class="auth-secret"><span>Clé à recopier dans votre application</span><code><?= escape_output($secret) ?></code></div>
      <details class="auth-details auth-provisioning">
        <summary>Afficher l’URI de configuration</summary>
        <p><code><?= escape_output($provisioningUri) ?></code></p>
      </details>
      <form method="post" action="mfa-enroll.php" class="auth-form">
        <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
        <div class="auth-field"><label for="totp_code">Code à six chiffres</label>
          <input id="totp_code" name="totp_code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000" aria-describedby="enroll-code-help" required>
          <small class="auth-hint" id="enroll-code-help">Le code change régulièrement. Utilisez celui affiché maintenant.</small></div>
        <button class="store-button store-button--primary auth-submit" type="submit">Activer la double vérification</button>
      </form>
      <p class="auth-recovery">Conservez l’accès à votre application. En cas de perte, contactez l’administrateur système pour réinitialiser cette configuration.</p>
    </section>
  </main>
  <?php store_footer(); ?>
</body>
</html>
