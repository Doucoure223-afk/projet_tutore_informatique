<?php
/**
 * Panier e-commerce - Gestion des articles
 */
require_once 'config.php';

if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

$conn = getDatabaseConnection();

if (isset($_GET['add']) && !empty($_GET['add'])) {
    $product_id = (int) $_GET['add'];
    $sql = "SELECT id, name, price, stock FROM products WHERE id = $product_id";
    $result = mysqli_query($conn, $sql);
    if ($result && $row = mysqli_fetch_assoc($result)) {
        $found = false;
        foreach ($_SESSION['cart'] as &$item) {
            if ($item['id'] == $product_id) {
                $item['qty']++;
                $found = true;
                break;
            }
        }
        if (!$found) {
            $_SESSION['cart'][] = [
                'id' => (int) $row['id'],
                'name' => $row['name'],
                'price' => (float) $row['price'],
                'qty' => 1
            ];
        }
        $q = isset($_GET['q']) ? '?q=' . urlencode($_GET['q']) : '';
        header('Location: search.php' . $q);
        exit;
    }
}

if (isset($_GET['remove']) && !empty($_GET['remove'])) {
    $product_id = (int) $_GET['remove'];
    $_SESSION['cart'] = array_values(array_filter($_SESSION['cart'], function ($item) use ($product_id) {
        return $item['id'] != $product_id;
    }));
    header('Location: panier.php');
    exit;
}

$order_validated = isset($_GET['validated']) && $_GET['validated'] == '1';

$cart_items = $_SESSION['cart'] ?? [];
$total = 0;
foreach ($cart_items as $item) {
    $total += $item['price'] * $item['qty'];
}
$total = number_format($total, 2, ',', ' ');
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mon panier</title>
    <link rel="stylesheet" href="style_panier.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Mon panier</h1>
            <p class="subtitle">Récapitulatif de votre sélection</p>
            <nav class="nav-links">
                <a href="search.php">Recherche</a>
                <a href="login.php">Connexion</a>
                <a href="dashboard.php">Dashboard</a>
                <a href="panier.php">Panier</a>
                <a href="inscription.php">Inscription</a>
            </nav>
        </div>

        <?php if ($order_validated): ?>
        <div class="success-box">
            <i class="fas fa-check-circle"></i>
            <strong>Commande validée</strong>
            <p>Votre commande a été enregistrée.</p>
            <a href="search.php" class="link-continue">Continuer mes achats</a>
        </div>
        <?php else: ?>

        <?php if (empty($cart_items)): ?>
        <div class="empty-cart">
            <i class="fas fa-shopping-cart"></i>
            <p>Votre panier est vide</p>
            <a href="search.php" class="btn-search">Parcourir les produits</a>
        </div>
        <?php else: ?>

        <div class="cart-card">
            <?php foreach ($cart_items as $item):
                $line_total = number_format($item['price'] * $item['qty'], 2, ',', ' ');
                $price_fmt = number_format($item['price'], 2, ',', ' ');
            ?>
            <div class="cart-item">
                <div class="item-info">
                    <span class="item-name"><?php echo htmlspecialchars($item['name']); ?></span>
                    <span class="item-detail"><?php echo $price_fmt; ?> € × <?php echo (int) $item['qty']; ?></span>
                </div>
                <div class="item-actions">
                    <span class="item-price"><?php echo $line_total; ?> €</span>
                    <a href="panier.php?remove=<?php echo $item['id']; ?>" class="link-remove">Retirer</a>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="total-card">
            <div class="total-row">
                <strong>Total</strong>
                <span class="total-amount"><?php echo $total; ?> €</span>
            </div>
            <a href="login.php?redirect=paiement" class="btn-validate">Valider la commande</a>
        </div>

        <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
