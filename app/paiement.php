<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/cart_helpers.php';
validate_csrf_token();
$user = current_user();
if (!$user) {
    header('Location: login.php?redirect=paiement');
    exit;
}
$previous_cart = $_SESSION['cart'] ?? [];
$cart_items = refresh_cart();
if (!$cart_items) {
    header('Location: panier.php');
    exit;
}
$username = $user['username'];
$role = $user['role'];
$is_admin = strtolower((string) $role) === 'admin';
$total = cart_total($cart_items);
$total_fmt = number_format($total, 2, ',', ' ');
$error = '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $without_payment = isset($_POST['validate_without_pay']);
    if ($without_payment && !$is_admin) {
        http_response_code(403);
        exit('Cette simulation est réservée aux administrateurs.');
    }
    if (!isset($_POST['pay']) && !$without_payment) {
        http_response_code(400);
        exit('Action de simulation invalide.');
    }
    if ($previous_cart !== $cart_items) {
        $error = 'Le catalogue a changé. Vérifiez le récapitulatif puis confirmez de nouveau.';
    } else {
        $_SESSION['simulation_confirmation'] = [
            'reference' => 'DEMO-' . strtoupper(bin2hex(random_bytes(4))),
            'total' => $total,
            'method' => $without_payment ? 'admin' : 'simulation',
        ];
        $_SESSION['cart'] = [];
        log_user_action((int) $user['id'], $without_payment ? 'Simulation de commande administrateur' : 'Simulation de paiement');
        header('Location: panier.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Achat simulé — CyberShield AI</title>
    <link rel="stylesheet" href="style_paiement.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <p class="user-badge">Connecté en tant que <?php echo htmlspecialchars($username); ?> (<?php echo htmlspecialchars(ucfirst($role)); ?>)</p>
            <nav class="nav-links">
                <a href="panier.php"><i class="fas fa-arrow-left"></i> Panier</a>
                <a href="search.php">Recherche</a>
                <a href="dashboard.php">Dashboard</a>
                <a href="logout.php">Déconnexion</a>
            </nav>
        </div>

        <?php if ($error): ?><p class="admin-box" role="alert"><?= escape_output($error) ?></p><?php endif; ?>
        <div class="recap-card">
            <h2>Récapitulatif</h2>
            <?php foreach ($cart_items as $item): 
                $line_total = number_format($item['price'] * $item['qty'], 2, ',', ' ');
                $price_fmt = number_format($item['price'], 2, ',', ' ');
            ?>
            <div class="recap-item">
                <span><?php echo htmlspecialchars($item['name']); ?> × <?php echo (int) $item['qty']; ?></span>
                <span><?php echo $line_total; ?> €</span>
            </div>
            <?php endforeach; ?>
            <div class="recap-total">
                <strong>Total</strong>
                <strong><?php echo $total_fmt; ?> €</strong>
            </div>
        </div>

        <?php if ($is_admin): ?>
        <div class="admin-box">
            <h3>Privilège administrateur</h3>
            <p>Testez le parcours administrateur. Cette validation reste une simulation.</p>
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                <button type="submit" name="validate_without_pay" class="btn-admin">Simuler la validation administrateur</button>
            </form>
        </div>
        <div class="separator">— ou simuler un paiement —</div>
        <?php endif; ?>

        <div class="payment-card">
            <h3>Paiement simulé</h3>
            <form method="POST" action="">
                <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                <p class="demo-note">Achat fictif pour la démonstration CyberShield AI. Aucune donnée bancaire demandée, aucun prélèvement et aucune commande réelle.</p>
                <button type="submit" name="pay" class="btn-pay">Simuler le paiement de <?php echo $total_fmt; ?> €</button>
            </form>
        </div>
    </div>
</body>
</html>
