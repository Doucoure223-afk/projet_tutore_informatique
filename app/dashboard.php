<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/store_layout.php';
require_once __DIR__ . '/OrderService.php';

$user = current_user();
if (!$user) { header('Location: login.php'); exit; }
$userId = (int) $user['id'];
$isAdmin = strtolower((string) ($user['role'] ?? '')) === 'admin';
$logs = [];
$logsResult = execute_query_secure('SELECT action, timestamp FROM user_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10', [$userId]);
if ($logsResult) { $logs = $logsResult->fetch_all(MYSQLI_ASSOC); }
$orderService = new OrderService($conn);
$orders = $orderService->schemaInstalled() ? $orderService->listForUser($userId, 10) : [];
$orderStatuses = [
    'pending' => ['label' => 'En attente de paiement', 'class' => 'pending'],
    'paid' => ['label' => 'Paiement reçu', 'class' => 'paid'],
    'payment_failed' => ['label' => 'Paiement non abouti', 'class' => 'failed'],
    'paid_review' => ['label' => 'Vérification en cours', 'class' => 'review'],
];
$adminUsers = [];
$adminQuery = trim(input_text($_GET, 'admin_search'));
if ($adminQuery !== '') {
    if (!$isAdmin) { http_response_code(403); exit('Cette recherche est réservée aux administrateurs.'); }
    $term = '%' . $adminQuery . '%';
    $adminResult = execute_query_secure('SELECT id, username, email, role FROM users WHERE username LIKE ? OR email LIKE ? LIMIT 100', [$term, $term]);
    if ($adminResult) { $adminUsers = $adminResult->fetch_all(MYSQLI_ASSOC); }
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
    <meta name="theme-color" content="#f5f4f0">
    <title>Mon espace · CyberShield AI</title>
    <link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>">
    <link rel="stylesheet" href="account.css?v=<?= (int) filemtime(__DIR__ . '/account.css') ?>">
</head>
<body class="store-page customer-account-page">
<?php store_header('account', $user); ?>
<main id="main-content" class="store-main">
    <header class="customer-heading">
        <div><p class="store-eyebrow">MON ESPACE PERSONNEL</p><h1>Bonjour, <?= escape_output($user['username'] ?? '') ?>.</h1><p>Vos commandes et vos informations, au même endroit.</p></div>
        <a class="store-button store-button--secondary" href="search.php">Continuer mes achats <?= store_icon('arrow') ?></a>
    </header>

    <div class="customer-layout">
        <aside class="customer-sidebar" aria-label="Votre compte">
            <section class="customer-identity">
                <div class="customer-avatar" aria-hidden="true"><?= escape_output($avatarInitial) ?></div>
                <h2><?= escape_output($user['username']) ?></h2>
                <p><?= escape_output($user['email']) ?></p>
                <span class="customer-member"><?= store_icon($isAdmin ? 'shield' : 'user') ?><?= $isAdmin ? 'Administrateur' : 'Compte personnel' ?></span>
            </section>
            <nav class="customer-menu" aria-label="Sections du compte">
                <a href="#orders" aria-current="location"><?= store_icon('package') ?>Mes commandes <?= store_icon('chevron') ?></a>
                <a href="#profile"><?= store_icon('user') ?>Mes informations <?= store_icon('chevron') ?></a>
                <a href="#activity"><?= store_icon('clock') ?>Activité du compte <?= store_icon('chevron') ?></a>
                <?php if ($isAdmin): ?><a href="../security/dashboard.php"><?= store_icon('shield') ?>Console de sécurité <?= store_icon('arrow') ?></a><?php endif; ?>
            </nav>
            <div class="customer-since">Membre depuis le <strong><?= escape_output($createdDate) ?></strong></div>
        </aside>

        <div class="customer-content">
            <section class="customer-orders" id="orders" aria-labelledby="orders-title">
                <div class="customer-section-head"><div><p class="store-eyebrow">VOTRE SUIVI</p><h2 id="orders-title">Mes commandes</h2></div><span class="customer-section-icon" aria-hidden="true"><?= store_icon('package') ?></span></div>
                <?php if ($orders): ?>
                    <p class="customer-section-note">Vos <?= count($orders) === 10 ? '10 dernières commandes' : 'commandes récentes' ?>. Ouvrez une commande pour consulter son détail et son paiement.</p>
                    <div class="customer-order-list">
                        <?php foreach ($orders as $order):
                            $orderTimestamp = strtotime((string) ($order['created_at'] ?? ''));
                            $orderStatus = $orderStatuses[$order['status']] ?? ['label' => 'État à vérifier', 'class' => 'review'];
                        ?>
                            <a class="customer-order" href="paiement.php?order=<?= rawurlencode((string) $order['reference']) ?>">
                                <span class="customer-order-icon" aria-hidden="true"><?= store_icon('bag') ?></span>
                                <span class="customer-order-info"><strong>Commande #<?= escape_output(strtoupper(substr((string) $order['reference'], -8))) ?></strong><span><?= $orderTimestamp ? escape_output(date('d/m/Y à H:i', $orderTimestamp)) : 'Date non disponible' ?></span></span>
                                <span class="customer-order-status is-<?= escape_output($orderStatus['class']) ?>"><?= escape_output($orderStatus['label']) ?></span>
                                <strong class="customer-order-total"><?= store_xof((int) $order['payment_amount']) ?></strong>
                                <span class="customer-order-arrow" aria-hidden="true"><?= store_icon('arrow') ?></span>
                            </a>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="customer-orders-empty">
                        <div class="customer-empty-art" aria-hidden="true"><span><?= store_icon('bag') ?></span><i><?= store_icon('package') ?></i></div>
                        <h3>Votre prochaine commande<br>commence ici.</h3>
                        <p>Vous n’avez pas encore de commande.<br>Découvrez le catalogue et trouvez votre équipement.</p>
                        <a class="store-button store-button--primary" href="search.php">Explorer le catalogue <?= store_icon('arrow') ?></a>
                    </div>
                <?php endif; ?>
            </section>

            <section class="customer-details-section" id="profile" aria-labelledby="profile-title">
                <details class="customer-disclosure">
                    <summary><span class="customer-disclosure-symbol"><?= store_icon('user') ?></span><span><strong id="profile-title">Mes informations</strong><small>Les coordonnées associées à votre compte</small></span><span class="customer-disclosure-chevron"><?= store_icon('chevron') ?></span></summary>
                    <div class="customer-disclosure-body"><dl class="customer-profile-list"><div><dt>Nom d’utilisateur</dt><dd><?= escape_output($user['username']) ?></dd></div><div><dt>Adresse courriel</dt><dd><?= escape_output($user['email']) ?></dd></div><div><dt>Type de compte</dt><dd><?= $isAdmin ? 'Administrateur' : 'Personnel' ?></dd></div><div><dt>Date d’inscription</dt><dd><?= escape_output($createdDate) ?></dd></div></dl></div>
                </details>
            </section>

            <section class="customer-details-section" id="activity" aria-labelledby="activity-title">
                <details class="customer-disclosure">
                    <summary><span class="customer-disclosure-symbol"><?= store_icon('clock') ?></span><span><strong id="activity-title">Activité du compte</strong><small>Vos dernières connexions et actions</small></span><span class="customer-disclosure-chevron"><?= store_icon('chevron') ?></span></summary>
                    <div class="customer-disclosure-body">
                        <?php if ($logs): ?>
                            <ol class="customer-activity-list">
                                <?php foreach ($logs as $log): $logTimestamp = strtotime((string) ($log['timestamp'] ?? '')); ?>
                                    <li><span class="customer-activity-dot" aria-hidden="true"></span><div><strong><?= escape_output($log['action'] ?? 'Action enregistrée') ?></strong><time<?= $logTimestamp ? ' datetime="' . escape_output(date('c', $logTimestamp)) . '"' : '' ?>><?= $logTimestamp ? escape_output(date('d/m/Y à H:i', $logTimestamp)) : 'Date non disponible' ?></time></div></li>
                                <?php endforeach; ?>
                            </ol>
                        <?php else: ?><p class="customer-section-note">Aucune activité récente à afficher.</p><?php endif; ?>
                    </div>
                </details>
            </section>

            <?php if ($isAdmin): ?>
                <section class="customer-details-section customer-admin" id="administration" aria-labelledby="lookup-title">
                    <details class="customer-disclosure" <?= isset($_GET['admin_search']) ? 'open' : '' ?>>
                        <summary><span class="customer-disclosure-symbol"><?= store_icon('shield') ?></span><span><strong id="lookup-title">Administration des comptes</strong><small>Rechercher un utilisateur en lecture seule</small></span><span class="customer-disclosure-chevron"><?= store_icon('chevron') ?></span></summary>
                        <div class="customer-disclosure-body">
                            <form method="get" action="dashboard.php#administration" class="customer-lookup-form" role="search">
                                <label for="admin-search">Nom d’utilisateur ou adresse courriel</label>
                                <div><input type="search" id="admin-search" name="admin_search" value="<?= escape_output($adminQuery) ?>" placeholder="Ex. nom ou adresse courriel"><button type="submit" class="store-button store-button--primary">Rechercher</button></div>
                                <?php if ($adminQuery !== ''): ?><a href="dashboard.php#administration">Effacer la recherche</a><?php endif; ?>
                            </form>
                            <?php if (isset($_GET['admin_search'])): ?>
                                <div class="customer-lookup-results" aria-live="polite">
                                    <?php if ($adminUsers): ?>
                                        <p class="customer-section-note"><?= count($adminUsers) ?> compte(s) trouvé(s). Maximum 100 résultats.</p>
                                        <div class="customer-table-wrap"><table class="customer-table"><caption class="sr-only">Comptes correspondant à la recherche</caption><thead><tr><th scope="col">Nom</th><th scope="col">Courriel</th><th scope="col">Accès</th></tr></thead><tbody><?php foreach ($adminUsers as $adminUser): ?><tr><td><?= escape_output($adminUser['username']) ?></td><td><?= escape_output($adminUser['email']) ?></td><td><?= strtolower((string) $adminUser['role']) === 'admin' ? 'Administrateur' : 'Personnel' ?></td></tr><?php endforeach; ?></tbody></table></div>
                                    <?php else: ?><p class="customer-section-note">Aucun compte trouvé. Essayez un autre nom ou une partie de l’adresse courriel.</p><?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </details>
                </section>
            <?php endif; ?>
        </div>
    </div>
</main>
<?php store_footer(); ?>
</body>
</html>

