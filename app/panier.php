<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/cart_helpers.php';
validate_csrf_token();
$_SESSION['cart'] = $_SESSION['cart'] ?? [];
$cart_items = refresh_cart();
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $action = input_text($_POST, 'action');
    $product_id = (int) input_text($_POST, 'product_id');
    if ($action === 'add') {
        $result = execute_query_secure('SELECT id, name, price, stock FROM products WHERE id = ?', [$product_id]);
        $product = $result ? $result->fetch_assoc() : null;
        if (!$product || (int) $product['stock'] <= 0) {
            $_SESSION['cart_notice'] = 'Ce produit est indisponible.';
        } else {
            $index = null;
            foreach ($_SESSION['cart'] as $key => $item) {
                if ((int) $item['id'] === $product_id) { $index = $key; break; }
            }
            $quantity = $index === null ? 0 : (int) $_SESSION['cart'][$index]['qty'];
            if ($quantity >= min((int) $product['stock'], 99)) {
                $_SESSION['cart_notice'] = 'Quantité maximale disponible déjà présente dans le panier.';
            } else {
                if ($index === null) {
                    $_SESSION['cart'][] = ['id' => $product_id, 'name' => $product['name'], 'price' => (float) $product['price'], 'qty' => 1];
                } else {
                    $_SESSION['cart'][$index]['qty']++;
                }
                $_SESSION['cart_notice'] = 'Produit ajouté au panier.';
            }
        }
        header('Location: search.php?q=' . rawurlencode(input_text($_POST, 'q')));
        exit;
    }
    if ($action === 'remove') {
        $_SESSION['cart'] = array_values(array_filter($_SESSION['cart'], static function ($item) use ($product_id) {
            return (int) $item['id'] !== $product_id;
        }));
        $_SESSION['cart_notice'] = 'Produit retiré du panier.';
        header('Location: panier.php');
        exit;
    }
    http_response_code(400);
    exit('Action de panier invalide.');
}
$confirmation = $_SESSION['simulation_confirmation'] ?? null;
unset($_SESSION['simulation_confirmation']);
$cart_notice = $_SESSION['cart_notice'] ?? '';
unset($_SESSION['cart_notice']);
$total = number_format(cart_total($cart_items), 2, ',', ' ');
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

        <?php if ($cart_notice): ?><p class="cart-card" role="status"><?= escape_output($cart_notice) ?></p><?php endif; ?>
        <?php if ($confirmation): ?>
        <div class="success-box">
            <i class="fas fa-check-circle"></i>
            <strong>Simulation terminée</strong>
            <p>Référence <?= escape_output($confirmation['reference']) ?> · <?= number_format($confirmation['total'], 2, ',', ' ') ?> €</p>
            <p>Aucun paiement ni achat réel n’a été effectué.</p>
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
                    <form method="post" action="panier.php">
                        <input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>">
                        <input type="hidden" name="action" value="remove">
                        <input type="hidden" name="product_id" value="<?= (int) $item['id'] ?>">
                        <button type="submit" class="link-remove">Retirer</button>
                    </form>
                </div>
            </div>
            <?php endforeach; ?>
        </div>

        <div class="total-card">
            <div class="total-row">
                <strong>Total</strong>
                <span class="total-amount"><?php echo $total; ?> €</span>
            </div>
            <a href="<?= !empty($_SESSION['logged_in']) ? 'paiement.php' : 'login.php?redirect=paiement' ?>" class="btn-validate">Continuer vers la simulation</a>
        </div>

        <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
