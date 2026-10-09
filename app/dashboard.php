<?php
require_once __DIR__ . '/config.php';

$user = current_user();
if (!$user) {
    header('Location: login.php');
    exit;
}

$userId = (int) $user['id'];
$isAdmin = strtolower((string) ($user['role'] ?? '')) === 'admin';
$logs = [];
$logsResult = execute_query_secure(
    'SELECT action, timestamp, ip_address FROM user_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10',
    [$userId]
);
if ($logsResult) {
    $logs = $logsResult->fetch_all(MYSQLI_ASSOC);
}

$adminUsers = [];
$adminQuery = trim(input_text($_GET, 'admin_search'));
if ($adminQuery !== '') {
    if (!$isAdmin) {
        http_response_code(403);
        exit('Cette recherche est réservée aux administrateurs.');
    }
    $term = '%' . $adminQuery . '%';
    $adminResult = execute_query_secure(
        'SELECT id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ? LIMIT 100',
        [$term, $term]
    );
    if ($adminResult) {
        $adminUsers = $adminResult->fetch_all(MYSQLI_ASSOC);
    }
}

$createdTimestamp = strtotime((string) ($user['created_at'] ?? ''));
$createdDate = $createdTimestamp ? date('d/m/Y', $createdTimestamp) : '—';
$avatarInitial = mb_strtoupper(mb_substr((string) ($user['username'] ?? 'U'), 0, 1));
?>
<!doctype html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#f1efe8">
    <title>Mon compte · CyberShield AI</title>
    <link rel="stylesheet" href="style_dashboard.css?v=<?= (int) filemtime(__DIR__ . '/style_dashboard.css') ?>">
</head>
<body class="account-page">
    <a class="skip-link" href="#main-content">Aller au contenu</a>
    <header class="account-topbar">
        <a class="account-brand" href="../index.php" aria-label="CyberShield AI, accueil">
            <span class="account-brand-mark" aria-hidden="true">C<span>◆</span></span>
            <span>CyberShield <b>AI</b><small>ESPACE DE DÉMONSTRATION</small></span>
        </a>
        <nav class="account-nav" aria-label="Navigation du compte">
            <a href="search.php">Catalogue</a>
            <a href="panier.php">Panier</a>
            <a href="dashboard.php" aria-current="page">Mon compte</a>
        </nav>
        <div class="account-user">
            <span class="account-avatar" aria-hidden="true"><?= escape_output($avatarInitial) ?></span>
            <span class="account-user-name"><?= escape_output($user['username'] ?? '') ?></span>
            <form class="logout-form" method="post" action="logout.php"><input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><button class="logout-link" type="submit">Déconnexion</button></form>
        </div>
    </header>

    <main class="account-main" id="main-content">
        <section class="account-heading" aria-labelledby="account-title">
            <div>
                <p class="account-eyebrow"><?= $isAdmin ? 'ESPACE ADMINISTRATEUR' : 'ESPACE PERSONNEL' ?></p>
                <h1 id="account-title">Bonjour, <?= escape_output($user['username'] ?? '') ?></h1>
                <p>Les informations de ton compte et les dernières actions enregistrées.</p>
            </div>
            <div class="account-heading-actions">
                <?php if ($isAdmin): ?>
                    <a class="account-button primary" href="../security/dashboard.php">Ouvrir la supervision <span aria-hidden="true">↗</span></a>
                <?php endif; ?>
                <a class="account-button secondary" href="search.php">Parcourir le catalogue</a>
            </div>
        </section>

        <section class="account-summary" aria-label="Résumé du compte">
            <article class="summary-item">
                <span class="summary-label">Niveau d’accès</span>
                <strong><?= $isAdmin ? 'Administrateur' : 'Utilisateur' ?></strong>
                <span class="summary-note"><?= $isAdmin ? 'Console de sécurité disponible' : 'Espace personnel' ?></span>
            </article>
            <article class="summary-item">
                <span class="summary-label">Activités récentes</span>
                <strong><?= number_format(count($logs), 0, ',', ' ') ?></strong>
                <span class="summary-note">éléments conservés pour ce compte</span>
            </article>
            <article class="summary-item">
                <span class="summary-label">Compte créé le</span>
                <strong><?= escape_output($createdDate) ?></strong>
                <span class="summary-note">Identifiant interne · #<?= $userId ?></span>
            </article>
        </section>

        <div class="account-columns">
            <section class="account-card profile-card" aria-labelledby="profile-title">
                <div class="account-card-heading">
                    <span class="section-index" aria-hidden="true">01</span>
                    <div><p class="account-eyebrow">VOTRE COMPTE</p><h2 id="profile-title">Profil</h2></div>
                    <span class="account-status"><i aria-hidden="true"></i>Actif</span>
                </div>
                <dl class="profile-list">
                    <div><dt>Nom d’utilisateur</dt><dd><?= escape_output($user['username'] ?? '—') ?></dd></div>
                    <div><dt>Adresse courriel</dt><dd><?= escape_output($user['email'] ?? '—') ?></dd></div>
                    <div><dt>Rôle</dt><dd><?= escape_output(ucfirst((string) ($user['role'] ?? 'user'))) ?></dd></div>
                    <div><dt>Date d’inscription</dt><dd><?= escape_output($createdDate) ?></dd></div>
                </dl>
                <?php if ($isAdmin): ?>
                    <div class="profile-note"><strong>Double vérification activée</strong><span>La connexion administrateur a validé le code de sécurité à usage unique.</span></div>
                <?php endif; ?>
            </section>

            <section class="account-card activity-card" aria-labelledby="activity-title">
                <div class="account-card-heading">
                    <span class="section-index" aria-hidden="true">02</span>
                    <div><p class="account-eyebrow">JOURNAL DU COMPTE</p><h2 id="activity-title">Activité récente</h2></div>
                    <span class="activity-count"><?= count($logs) ?> entrées</span>
                </div>
                <?php if ($logs): ?>
                    <ol class="activity-list">
                        <?php foreach ($logs as $log): $logTimestamp = strtotime((string) ($log['timestamp'] ?? '')); ?>
                            <li class="activity-item">
                                <span class="activity-point" aria-hidden="true"></span>
                                <div class="activity-content">
                                    <strong><?= escape_output($log['action'] ?? 'Action enregistrée') ?></strong>
                                    <span class="activity-meta">
                                        <?= $logTimestamp ? escape_output(date('d/m/Y · H:i', $logTimestamp)) : 'Date inconnue' ?>
                                        <span aria-hidden="true">·</span>
                                        IP <?= escape_output($log['ip_address'] ?? 'inconnue') ?>
                                    </span>
                                </div>
                            </li>
                        <?php endforeach; ?>
                    </ol>
                <?php else: ?>
                    <div class="account-empty"><strong>Aucune activité à afficher</strong><span>Les actions de ce compte apparaîtront ici après utilisation.</span></div>
                <?php endif; ?>
            </section>
        </div>

        <?php if ($isAdmin): ?>
            <section class="account-card admin-lookup" aria-labelledby="lookup-title">
                <div class="account-card-heading">
                    <span class="section-index" aria-hidden="true">03</span>
                    <div><p class="account-eyebrow">ADMINISTRATION</p><h2 id="lookup-title">Recherche de comptes</h2></div>
                </div>
                <p class="lookup-intro">Recherche en lecture seule par nom d’utilisateur ou adresse courriel.</p>
                <form method="get" action="dashboard.php#lookup-results" class="lookup-form" role="search">
                    <label class="sr-only" for="admin-search">Nom d’utilisateur ou courriel</label>
                    <input type="search" id="admin-search" name="admin_search" value="<?= escape_output($adminQuery) ?>" placeholder="Ex. nom ou adresse courriel">
                    <button type="submit" class="account-button primary">Rechercher</button>
                    <?php if ($adminQuery !== ''): ?><a class="account-button secondary" href="dashboard.php#lookup-results">Effacer</a><?php endif; ?>
                </form>
                <?php if (isset($_GET['admin_search'])): ?>
                    <div class="lookup-results" id="lookup-results" aria-live="polite">
                        <?php if ($adminUsers): ?>
                            <p class="lookup-count"><?= number_format(count($adminUsers), 0, ',', ' ') ?> compte(s) trouvé(s) — maximum 100 résultats.</p>
                            <div class="account-table-wrap">
                                <table class="account-table">
                                    <caption class="sr-only">Résultats de recherche des comptes</caption>
                                    <thead><tr><th scope="col">Identifiant</th><th scope="col">Nom</th><th scope="col">Courriel</th><th scope="col">Rôle</th></tr></thead>
                                    <tbody>
                                        <?php foreach ($adminUsers as $adminUser): ?>
                                            <tr>
                                                <td><?= (int) $adminUser['id'] ?></td>
                                                <td><?= escape_output($adminUser['username']) ?></td>
                                                <td><?= escape_output($adminUser['email']) ?></td>
                                                <td><?= escape_output(ucfirst((string) $adminUser['role'])) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                        <?php else: ?>
                            <div class="account-empty"><strong>Aucun compte trouvé</strong><span>Essaie un autre nom ou une partie différente de l’adresse courriel.</span></div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </section>
        <?php endif; ?>

        <footer class="account-footer">
            <a href="../index.php">Accueil CyberShield AI</a>
            <span>Les activités affichées proviennent du journal de ce compte.</span>
        </footer>
    </main>
</body>
</html>
