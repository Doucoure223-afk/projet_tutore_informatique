<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['authenticated']) || empty($_SESSION['user_id'])) {
    $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    header('Location: ' . $baseUrl . '/login.php', true, 303);
    exit;
}

require_once __DIR__ . '/../vendor/autoload.php';

use App\Infrastructure\ApplicationConfig;
use App\Security\IpAccessControl;

ApplicationConfig::initialize(__DIR__ . '/..');

$baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
$dashboardUrl = $baseUrl ? $baseUrl . '/dashboard.php' : 'dashboard.php';
$db = ApplicationConfig::getDatabase();
$ipAccess = new IpAccessControl($db);

$message = '';
$error = '';

// Suppression
if (isset($_GET['delete']) && is_string($_GET['delete'])) {
    $ipToDelete = trim($_GET['delete']);
    if ($ipToDelete !== '' && filter_var($ipToDelete, FILTER_VALIDATE_IP)) {
        if ($ipAccess->removeRule($ipToDelete)) {
            $message = 'Règle supprimée pour ' . htmlspecialchars($ipToDelete);
        } else {
            $error = 'Impossible de supprimer.';
        }
    }
    header('Location: ' . $baseUrl . '/admin-ip-rules.php?ok=' . urlencode($message) . '&err=' . urlencode($error), true, 303);
    exit;
}

// Ajout
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_rule'])) {
    $ip = trim($_POST['ip'] ?? '');
    $ruleType = $_POST['rule_type'] ?? 'blacklist';
    $comment = trim($_POST['comment'] ?? '');
    if ($ruleType !== IpAccessControl::TYPE_WHITELIST) {
        $ruleType = IpAccessControl::TYPE_BLACKLIST;
    }
    if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
        if ($ipAccess->addRule($ip, $ruleType, $comment !== '' ? $comment : null)) {
            $message = 'Règle ajoutée pour ' . htmlspecialchars($ip);
            // Pour les requêtes AJAX, retourner JSON
            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                header('Content-Type: application/json');
                echo json_encode(['success' => true, 'message' => $message]);
                exit;
            }
        } else {
            $error = 'Erreur lors de l\'ajout.';
            // Pour les requêtes AJAX, retourner JSON
            if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
                header('Content-Type: application/json');
                echo json_encode(['success' => false, 'message' => $error]);
                exit;
            }
        }
    } else {
        $error = 'Adresse IP invalide.';
        // Pour les requêtes AJAX, retourner JSON
        if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] === 'XMLHttpRequest') {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'message' => $error]);
            exit;
        }
    }
}

// Message depuis redirect
if (isset($_GET['ok']) && is_string($_GET['ok']) && $_GET['ok'] !== '') {
    $message = $_GET['ok'];
}
if (isset($_GET['err']) && is_string($_GET['err']) && $_GET['err'] !== '') {
    $error = $_GET['err'];
}

$rules = $ipAccess->listRules();

?>
<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Liste noire / blanche IP</title>
    <script>(function(){var t=localStorage.getItem('theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);})();</script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root, [data-theme="dark"] {
            --admin-bg: #0f172a;
            --admin-text: #f8fafc;
            --admin-card: rgba(30, 41, 59, 0.8);
            --admin-border: #334155;
            --admin-muted: #94a3b8;
            --admin-input-bg: #1e293b;
            --admin-link: #60a5fa;
        }
        [data-theme="light"] {
            --admin-bg: #f1f5f9;
            --admin-text: #0f172a;
            --admin-card: rgba(255, 255, 255, 0.95);
            --admin-border: #cbd5e1;
            --admin-muted: #64748b;
            --admin-input-bg: #fff;
            --admin-link: #2563eb;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: var(--admin-bg); color: var(--admin-text); min-height: 100vh; padding: 24px; }
        a { color: var(--admin-link); }
        h1 { margin-bottom: 24px; font-size: 1.5rem; }
        .card { background: var(--admin-card); border-radius: 12px; padding: 24px; margin-bottom: 24px; border: 1px solid var(--admin-border); }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid var(--admin-border); }
        th { color: var(--admin-muted); font-weight: 600; }
        .badge-black { background: #dc2626; color: #fff; padding: 4px 8px; border-radius: 6px; font-size: 0.8rem; }
        .badge-white { background: #10b981; color: #fff; padding: 4px 8px; border-radius: 6px; font-size: 0.8rem; }
        .btn { display: inline-block; padding: 8px 16px; border-radius: 8px; text-decoration: none; font-size: 0.9rem; cursor: pointer; border: none; }
        .btn-primary { background: #2563eb; color: #fff; }
        .btn-secondary { background: #475569; color: #fff; }
        .btn-danger { background: #dc2626; color: #fff; }
        .form-group { margin-bottom: 12px; }
        .form-group label { display: block; margin-bottom: 4px; color: var(--admin-muted); }
        .form-group input, .form-group select { padding: 8px 12px; border-radius: 8px; border: 1px solid var(--admin-border); background: var(--admin-input-bg); color: var(--admin-text); width: 100%; max-width: 300px; }
        .msg { padding: 12px; border-radius: 8px; margin-bottom: 16px; }
        .msg.ok { background: rgba(16, 185, 129, 0.2); color: #10b981; }
        .msg.err { background: rgba(220, 38, 38, 0.2); color: #f87171; }
        .actions { margin-top: 16px; }
        .header-row { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; }
        .theme-toggle-admin { padding: 8px 14px; border-radius: 8px; border: 1px solid var(--admin-border); background: var(--admin-input-bg); color: var(--admin-text); cursor: pointer; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 8px; }
        .theme-toggle-admin:hover { border-color: #2563eb; background: rgba(37, 99, 235, 0.15); }
        .table-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; margin-top: 12px; }
        .table-wrapper table { min-width: 520px; }
        @media (max-width: 768px) {
            body { padding: 16px; }
            .card { padding: 16px; }
            .form-group input, .form-group select { max-width: none; }
            h1 { font-size: 1.25rem; }
        }
        @media (max-width: 480px) {
            body { padding: 12px; }
            .card { padding: 12px; }
            .header-row { flex-direction: column; }
            .theme-toggle-admin { align-self: flex-start; }
            .btn { padding: 6px 12px; font-size: 0.85rem; }
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="header-row">
            <div>
                <h1><i class="fas fa-shield-alt"></i> Liste noire / liste blanche d'IP</h1>
                <p style="margin-bottom: 16px; margin-top: 8px; color: var(--admin-muted);">Les IP en <strong>liste noire</strong> sont bloquées au login. Si au moins une IP est en <strong>liste blanche</strong>, seules les IP whitelistées peuvent se connecter.</p>
                <a href="<?php echo htmlspecialchars($dashboardUrl); ?>" class="btn btn-secondary"><i class="fas fa-arrow-left"></i> Retour au dashboard</a>
            </div>
            <button type="button" class="theme-toggle-admin" id="themeToggleAdmin" title="Changer de thème" aria-label="Changer de thème">
                <i class="fas fa-moon" id="themeIconAdmin"></i>
                <span id="themeLabelAdmin">Thème clair</span>
            </button>
        </div>
    </div>

    <?php if ($message !== '') { ?>
        <div class="msg ok"><?php echo htmlspecialchars($message); ?></div>
    <?php } ?>
    <?php if ($error !== '') { ?>
        <div class="msg err"><?php echo htmlspecialchars($error); ?></div>
    <?php } ?>

    <div class="card">
        <h2 style="margin-bottom: 16px; font-size: 1.2rem;">Ajouter une règle</h2>
        <form method="post" action="">
            <input type="hidden" name="add_rule" value="1">
            <div class="form-group">
                <label for="ip">Adresse IP</label>
                <input type="text" id="ip" name="ip" placeholder="ex. 192.168.1.100 ou ::1" required>
            </div>
            <div class="form-group">
                <label for="rule_type">Type</label>
                <select id="rule_type" name="rule_type">
                    <option value="blacklist">Liste noire (bloquer)</option>
                    <option value="whitelist">Liste blanche (autoriser uniquement)</option>
                </select>
            </div>
            <div class="form-group">
                <label for="comment">Commentaire (optionnel)</label>
                <input type="text" id="comment" name="comment" placeholder="ex. Serveur de test">
            </div>
            <button type="submit" class="btn btn-primary"><i class="fas fa-plus"></i> Ajouter</button>
        </form>
    </div>

    <div class="card">
        <h2 style="margin-bottom: 16px; font-size: 1.2rem;">Règles actuelles</h2>
        <?php if (empty($rules)) { ?>
            <p style="color: var(--admin-muted);">Aucune règle. Toutes les IP peuvent tenter de se connecter (sous réserve du rate limiting).</p>
        <?php } else { ?>
            <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Type</th>
                        <th>Commentaire</th>
                        <th>Ajouté le</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($rules as $r) { ?>
                        <tr>
                            <td><?php echo htmlspecialchars($r['ip_address']); ?></td>
                            <td>
                                <span class="<?php echo $r['rule_type'] === 'blacklist' ? 'badge-black' : 'badge-white'; ?>">
                                    <?php echo $r['rule_type'] === 'blacklist' ? 'Liste noire' : 'Liste blanche'; ?>
                                </span>
                            </td>
                            <td><?php echo htmlspecialchars($r['comment'] ?? '-'); ?></td>
                            <td><?php echo htmlspecialchars($r['created_at']); ?></td>
                            <td>
                                <a href="?delete=<?php echo urlencode($r['ip_address']); ?>" class="btn btn-danger" onclick="return confirm('Supprimer cette règle ?');">
                                    <i class="fas fa-trash"></i> Supprimer
                                </a>
                            </td>
                        </tr>
                    <?php } ?>
                </tbody>
            </table>
            </div>
        <?php } ?>
    </div>
    <script>
        (function() {
            var theme = document.documentElement.getAttribute('data-theme') || 'dark';
            var btn = document.getElementById('themeToggleAdmin');
            var icon = document.getElementById('themeIconAdmin');
            var label = document.getElementById('themeLabelAdmin');
            if (btn && icon && label) {
                if (theme === 'light') { icon.className = 'fas fa-sun'; label.textContent = 'Thème sombre'; } else { icon.className = 'fas fa-moon'; label.textContent = 'Thème clair'; }
                btn.addEventListener('click', function() {
                    var next = theme === 'light' ? 'dark' : 'light';
                    theme = next;
                    localStorage.setItem('theme', next);
                    document.documentElement.setAttribute('data-theme', next);
                    if (next === 'light') { icon.className = 'fas fa-sun'; label.textContent = 'Thème sombre'; } else { icon.className = 'fas fa-moon'; label.textContent = 'Thème clair'; }
                });
            }
        })();
    </script>
</body>
</html>
