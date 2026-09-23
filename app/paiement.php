<?php
/**
 * Page de paiement - Affichage selon le rôle (admin / utilisateur)
 */
require_once 'config.php';

// Connexion obligatoire
if (empty($_SESSION['logged_in']) || empty($_SESSION['username'])) {
    header('Location: login.php?redirect=paiement');
    exit;
}

// Panier requis
$cart_items = $_SESSION['cart'] ?? [];
if (empty($cart_items)) {
    header('Location: panier.php');
    exit;
}

$username = $_SESSION['username'];
$role = $_SESSION['role'] ?? 'user';
$is_admin = (strtolower($role) === 'admin');

// Calcul du total
$total = 0;
foreach ($cart_items as $item) {
    $total += $item['price'] * $item['qty'];
}
$total_fmt = number_format($total, 2, ',', ' ');

// Action : Valider sans payer (admin uniquement)
if ($is_admin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['validate_without_pay'])) {
    $_SESSION['cart'] = [];
    header('Location: panier.php?validated=1');
    exit;
}

// Action : Payer (simulation)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pay'])) {
    $_SESSION['cart'] = [];
    header('Location: panier.php?validated=1');
    exit;
}

// Réafficher succès sur panier si validated
// (panier.php devra gérer ?validated=1 pour afficher le message succès)
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Paiement</title>
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

        <div class="recap-card">
            <h2>Récapitulatif</h2>
            <?php foreach ($cart_items as $item): 
                $line_total = number_format($item['price'] * $item['qty'], 2, ',', ' ');
                $price_fmt = number_format($item['price'], 2, ',', ' ');
            ?>
            <div class="recap-item">
                <span><?php echo htmlspecialchars($item['name']); ?> × <?php echo (int) $item['qty']; ?></span>
                <span><?php echo $price_fmt; ?> €</span>
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
            <p>En tant qu'admin, vous pouvez valider la commande sans passer par le paiement.</p>
            <form method="POST" action="">
                <button type="submit" name="validate_without_pay" class="btn-admin">Valider sans payer</button>
            </form>
        </div>
        <div class="separator">— ou simuler un paiement —</div>
        <?php endif; ?>

        <div class="payment-card">
            <h3>Paiement simulé</h3>
            <form method="POST" action="">
                <div class="form-row">
                    <label for="card">Numéro de carte</label>
                    <input type="text" id="card" name="card" value="4111 1111 1111 1111" placeholder="4111 1111 1111 1111">
                </div>
                <div class="form-row inline">
                    <div>
                        <label for="date">Date</label>
                        <input type="text" id="date" name="date" value="MM/AA" placeholder="MM/AA">
                    </div>
                    <div>
                        <label for="cvv">CVV</label>
                        <input type="text" id="cvv" name="cvv" value="123" placeholder="123">
                    </div>
                </div>
                <p class="demo-note">Aucune vérification réelle – démo uniquement.</p>
                <button type="submit" name="pay" class="btn-pay">Payer <?php echo $total_fmt; ?> €</button>
            </form>
        </div>
    </div>
</body>
</html>
