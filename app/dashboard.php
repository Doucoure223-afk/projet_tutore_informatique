<?php
require_once 'config.php';

if (!isset($_SESSION['logged_in']) || !$_SESSION['logged_in']) {
    if (session_status() === PHP_SESSION_NONE) session_start();
    header('Location: login.php');
    exit;
}

$user_id = $_SESSION['user_id'];
$sql = "SELECT * FROM users WHERE id = $user_id";
$user_result = execute_query_vulnerable($sql);
$user = $user_result ? mysqli_fetch_assoc($user_result) : [];
$user = $user ?: ['id' => 0, 'username' => 'Inconnu', 'email' => '-', 'role' => 'user', 'created_at' => '-'];

$logs = [];
$sql_logs = "SELECT * FROM user_logs WHERE user_id = $user_id ORDER BY timestamp DESC LIMIT 10";
$logs_result = execute_query_vulnerable($sql_logs);
if ($logs_result) {
    while ($log = mysqli_fetch_assoc($logs_result)) {
        $logs[] = $log;
    }
}

$admin_users = [];
if (isset($_GET['admin_search']) && !empty($_GET['admin_search'])) {
    $admin_query = $_GET['admin_search'];
    $sql_admin = "SELECT * FROM users WHERE username LIKE '%$admin_query%' OR email LIKE '%$admin_query%'";
    $admin_result = execute_query_vulnerable($sql_admin);
    if ($admin_result) {
        while ($admin_user = mysqli_fetch_assoc($admin_result)) {
            $admin_users[] = $admin_user;
        }
    }
}
$is_admin = isset($user['role']) && strtolower($user['role']) === 'admin';
?>
<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <script>(function(){var t=localStorage.getItem('theme');if(t==='light'||t==='dark')document.documentElement.setAttribute('data-theme',t);})();</script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style_dashboard.css">
</head>
<body>
    <div class="dashboard">
        <aside class="sidebar">
            <div class="sidebar-brand">
                <i class="fas fa-chart-line"></i>
                <span>Dashboard</span>
            </div>
            <button type="button" class="theme-toggle" id="themeToggle" title="Changer de thème" aria-label="Changer de thème">
                <i class="fas fa-moon" id="themeIcon"></i> Thème
            </button>
            <nav class="sidebar-nav">
                <a href="search.php" class="nav-item"><i class="fas fa-search"></i> Recherche</a>
                <a href="panier.php" class="nav-item"><i class="fas fa-shopping-cart"></i> Panier</a>
                <a href="dashboard.php" class="nav-item active"><i class="fas fa-tachometer-alt"></i> Tableau de bord</a>
                <a href="logout.php" class="nav-item"><i class="fas fa-sign-out-alt"></i> Déconnexion</a>
            </nav>
            <div class="sidebar-user">
                <div class="user-avatar"><?php echo strtoupper(substr($user['username'] ?? 'U', 0, 1)); ?></div>
                <div class="user-name"><?php echo htmlspecialchars($user['username'] ?? ''); ?></div>
                <div class="user-role"><?php echo htmlspecialchars($user['role'] ?? 'user'); ?></div>
            </div>
        </aside>

        <main class="main-content">
            <header class="dashboard-header">
                <h1>Tableau de bord</h1>
                <p>Bienvenue, <?php echo htmlspecialchars($user['username'] ?? ''); ?></p>
            </header>

            <div class="stat-grid">
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-user"></i></div>
                    <div class="stat-label">ID Utilisateur</div>
                    <div class="stat-value"><?php echo (int)($user['id'] ?? 0); ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-shield-alt"></i></div>
                    <div class="stat-label">Rôle</div>
                    <div class="stat-value"><?php echo htmlspecialchars(ucfirst($user['role'] ?? 'user')); ?></div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-history"></i></div>
                    <div class="stat-label">Activités</div>
                    <div class="stat-value"><?php echo count($logs); ?></div>
                </div>
            </div>

            <div class="dashboard-grid">
                <section class="card">
                    <div class="card-header">
                        <i class="fas fa-user-circle card-icon"></i>
                        <div>
                            <h3>Informations Profil</h3>
                            <p>Données personnelles</p>
                        </div>
                    </div>
                    <ul class="user-details">
                        <li><span class="label">Nom d'utilisateur</span><span class="value"><?php echo htmlspecialchars($user['username'] ?? '-'); ?></span></li>
                        <li><span class="label">Email</span><span class="value"><?php echo htmlspecialchars($user['email'] ?? '-'); ?></span></li>
                        <li><span class="label">Rôle</span><span class="value"><?php echo htmlspecialchars($user['role'] ?? '-'); ?></span></li>
                        <li><span class="label">Inscription</span><span class="value"><?php echo htmlspecialchars($user['created_at'] ?? '-'); ?></span></li>
                    </ul>
                </section>

                <section class="card">
                    <div class="card-header">
                        <i class="fas fa-list-alt card-icon"></i>
                        <div>
                            <h3>Activités Récentes</h3>
                            <p>Dernières connexions et actions</p>
                        </div>
                    </div>
                    <ul class="logs-list">
                        <?php if (!empty($logs)): ?>
                            <?php foreach ($logs as $log): ?>
                            <li class="log-item">
                                <div class="log-action"><?php echo htmlspecialchars($log['action'] ?? '-'); ?></div>
                                <div class="log-meta"><?php echo htmlspecialchars($log['timestamp'] ?? ''); ?> · IP: <?php echo htmlspecialchars($log['ip_address'] ?? '-'); ?></div>
                            </li>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <li class="log-item empty">Aucune activité récente</li>
                        <?php endif; ?>
                    </ul>
                </section>
            </div>

            <?php if ($is_admin): ?>
            <section class="card admin-card">
                <div class="card-header">
                    <i class="fas fa-users-cog card-icon danger"></i>
                    <div>
                        <h3>Recherche Admin</h3>
                        <p>Recherche vulnérable SQLi</p>
                    </div>
                </div>
                <form method="GET" action="" class="admin-search">
                    <input type="text" name="admin_search" placeholder="Rechercher un utilisateur..." 
                           value="<?php echo isset($_GET['admin_search']) ? htmlspecialchars($_GET['admin_search']) : ''; ?>">
                    <button type="submit" class="btn-primary"><i class="fas fa-search"></i> Rechercher</button>
                </form>
                <?php if (isset($_GET['admin_search'])): ?>
                    <?php if (!empty($admin_users)): ?>
                    <div class="admin-results">
                        <h4>Résultats (<?php echo count($admin_users); ?>)</h4>
                        <div class="table-wrapper">
                            <table class="user-table">
                                <thead>
                                    <tr><th>ID</th><th>Username</th><th>Email</th><th>Rôle</th></tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($admin_users as $au): ?>
                                    <tr>
                                        <td><?php echo (int)$au['id']; ?></td>
                                        <td><?php echo htmlspecialchars($au['username']); ?></td>
                                        <td><?php echo htmlspecialchars($au['email']); ?></td>
                                        <td><?php echo htmlspecialchars($au['role']); ?></td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <?php else: ?>
                    <p class="no-results">Aucun utilisateur trouvé</p>
                    <?php endif; ?>
                <?php endif; ?>
                <div class="admin-warning">
                    <i class="fas fa-exclamation-triangle"></i> Vulnérable SQLi — Essayez: <code>test' UNION SELECT 1,2,3,4 --</code>
                </div>
            </section>
            <?php endif; ?>

            <details class="debug-section">
                <summary>Débogage - Requêtes SQL</summary>
                <div class="debug-content">
                    <p><strong>Requête utilisateur:</strong> <code>SELECT * FROM users WHERE id = <?php echo (int)$user_id; ?></code></p>
                    <p><strong>Requête logs:</strong> <code>SELECT * FROM user_logs WHERE user_id = <?php echo (int)$user_id; ?> ORDER BY timestamp DESC LIMIT 10</code></p>
                    <?php if (isset($_GET['admin_search'])): ?>
                    <p><strong>Requête admin:</strong> <code>SELECT * FROM users WHERE username LIKE '%<?php echo htmlspecialchars($_GET['admin_search']); ?>%' OR email LIKE '%<?php echo htmlspecialchars($_GET['admin_search']); ?>%'</code></p>
                    <?php endif; ?>
                    <ul>
                        <li>Concaténation directe dans les requêtes SQL</li>
                        <li>Pas de requêtes préparées</li>
                        <li>Pas de validation des entrées</li>
                    </ul>
                </div>
            </details>
        </main>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            var theme = document.documentElement.getAttribute('data-theme') || 'dark';
            var btn = document.getElementById('themeToggle');
            var icon = document.getElementById('themeIcon');
            if (btn && icon) {
                icon.className = theme === 'light' ? 'fas fa-sun' : 'fas fa-moon';
                btn.addEventListener('click', function() {
                    var next = theme === 'light' ? 'dark' : 'light';
                    theme = next;
                    localStorage.setItem('theme', next);
                    document.documentElement.setAttribute('data-theme', next);
                    icon.className = next === 'light' ? 'fas fa-sun' : 'fas fa-moon';
                });
            }
        });
    </script>
</body>
</html>
