<?php
declare(strict_types=1);

require_once __DIR__ . '/access.php';
require_once __DIR__ . '/ip_access.php';
console_require_access();

$config = require __DIR__ . '/../config/security.php';
$policy = new IpAccessControl($config['log_dir']);

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    console_check_csrf();
    $operation = is_string($_POST['operation'] ?? null) ? $_POST['operation'] : '';
    $ip = is_string($_POST['ip'] ?? null) ? trim($_POST['ip']) : '';
    try {
        if ($operation === 'add') {
            $comment = is_string($_POST['comment'] ?? null) ? $_POST['comment'] : '';
            $policy->addRule($ip, $comment);
            $_SESSION['ip_rules_flash'] = ['type' => 'success', 'text' => 'Adresse ajoutée à la liste de blocage.'];
        } elseif ($operation === 'remove') {
            if (!$policy->removeRule($ip)) {
                throw new InvalidArgumentException('Aucune règle ne correspond à cette adresse.');
            }
            $_SESSION['ip_rules_flash'] = ['type' => 'success', 'text' => 'Règle de blocage supprimée.'];
        } else {
            throw new InvalidArgumentException('Action invalide.');
        }
    } catch (InvalidArgumentException $error) {
        $_SESSION['ip_rules_flash'] = ['type' => 'error', 'text' => $error->getMessage()];
    } catch (Throwable $error) {
        error_log('CyberShield : gestion des règles IP indisponible (' . get_class($error) . ').');
        $_SESSION['ip_rules_flash'] = ['type' => 'error', 'text' => 'La règle n’a pas pu être enregistrée. Vérifiez le stockage local des journaux.'];
    }
    header('Location: ip-rules.php', true, 303);
    exit;
}

$flash = $_SESSION['ip_rules_flash'] ?? null;
unset($_SESSION['ip_rules_flash']);
$loadError = false;
try {
    $rules = $policy->listRules();
} catch (Throwable $error) {
    error_log('CyberShield : lecture de la liste IP indisponible (' . get_class($error) . ').');
    $rules = [];
    $loadError = true;
}
$currentIp = (string) ($_SERVER['REMOTE_ADDR'] ?? 'indisponible');
?>
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#f1efe8">
  <title>Accès par IP · CyberShield AI</title>
  <link rel="stylesheet" href="console.css">
</head>
<body>
<div class="shell">
  <?php console_sidebar('ip-rules'); ?>
  <main class="main">
    <div class="topline">
      <div class="headline">
        <p class="eyebrow">CONTRÔLE D’ACCÈS</p>
        <h1>Règles d’adresses IP</h1>
        <p class="muted">Bloquez une adresse précise sur les pages de l’application et les tentatives d’authentification.</p>
      </div>
      <span class="badge"><?php if ($loadError): ?>Stockage indisponible<?php else: ?><?= count($rules) ?> règle<?= count($rules) === 1 ? '' : 's' ?> active<?= count($rules) === 1 ? '' : 's' ?><?php endif; ?></span>
    </div>

    <?php if (is_array($flash)): ?>
      <div class="callout <?= ($flash['type'] ?? '') === 'error' ? 'danger' : '' ?>" role="status"><?= console_escape($flash['text'] ?? '') ?></div>
    <?php endif; ?>
    <?php if ($loadError): ?>
      <div class="callout danger" role="alert">Le fichier des règles est illisible. Les requêtes sont refusées par précaution jusqu’à sa réparation.</div>
    <?php endif; ?>

    <div class="grid">
      <section class="card">
        <div class="card-head">
          <div><h2>Ajouter une adresse</h2><p class="sub">IPv4 et IPv6 sont acceptées. Les plages CIDR ne sont pas prises en charge.</p></div>
        </div>
        <form method="post" action="ip-rules.php" class="field">
          <input type="hidden" name="csrf_token" value="<?= console_escape(console_csrf()) ?>">
          <input type="hidden" name="operation" value="add">
          <label for="ip">Adresse IP</label>
          <input id="ip" name="ip" type="text" autocomplete="off" maxlength="45" placeholder="192.0.2.25 ou 2001:db8::25" required <?= $loadError ? 'disabled' : '' ?>>
          <label for="comment">Motif (facultatif)</label>
          <input id="comment" name="comment" type="text" maxlength="160" placeholder="Abus répétés, origine d’essai…" <?= $loadError ? 'disabled' : '' ?>>
          <div class="actions"><button class="button" type="submit" <?= $loadError ? 'disabled' : '' ?>>Ajouter à la liste</button></div>
        </form>
      </section>
      <aside class="card">
        <div class="card-head"><div><h2>Portée de la règle</h2><p class="sub">Blocage exact, vérifié côté serveur à chaque requête.</p></div></div>
        <p class="event-detail">L’adresse courante de cette session est <strong><?= console_escape($currentIp) ?></strong>. Évitez de la bloquer pendant votre propre session de travail.</p>
        <p class="event-detail">La console conserve un accès de secours local et reste accessible à un administrateur connecté. Les règles sont enregistrées dans le dossier privé des journaux et chaque refus est ajouté au journal d’incidents.</p>
        <p class="event-detail">Cette liste n’accepte que des adresses individuelles. Elle ne modifie pas les données de compte ni les listes de règles du pare-feu du système.</p>
      </aside>
    </div>

    <section class="card">
      <div class="card-head"><div><h2>Adresses bloquées</h2><p class="sub">Les commentaires sont internes à la console et ne sont jamais affichés aux visiteurs bloqués.</p></div></div>
      <?php if (!$rules): ?>
        <div class="empty"><?= $loadError ? 'Aucune règle ne peut être affichée tant que le stockage est indisponible.' : 'Aucune adresse bloquée. Toutes les adresses restent soumises au filtre SQLi et à la limitation de débit.' ?></div>
      <?php else: ?>
        <div class="table-wrap">
          <table class="table">
            <thead><tr><th>Adresse IP</th><th>Motif</th><th>Ajoutée (UTC)</th><th><span class="sr-only">Action</span></th></tr></thead>
            <tbody>
            <?php foreach ($rules as $rule): ?>
              <tr>
                <td class="mono"><?= console_escape($rule['ip_address']) ?></td>
                <td><?= console_escape($rule['comment'] !== '' ? $rule['comment'] : '—') ?></td>
                <td><?= console_escape(gmdate('d/m/Y H:i', strtotime($rule['created_at']) ?: 0)) ?></td>
                <td>
                  <form method="post" action="ip-rules.php">
                    <input type="hidden" name="csrf_token" value="<?= console_escape(console_csrf()) ?>">
                    <input type="hidden" name="operation" value="remove">
                    <input type="hidden" name="ip" value="<?= console_escape($rule['ip_address']) ?>">
                    <button class="button danger" type="submit" <?= $loadError ? 'disabled' : '' ?>>Supprimer</button>
                  </form>
                </td>
              </tr>
            <?php endforeach; ?>
            </tbody>
          </table>
        </div>
      <?php endif; ?>
    </section>
  </main>
</div>
</body>
</html>
