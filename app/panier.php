<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/cart_helpers.php';
require_once __DIR__ . '/store_layout.php';
validate_csrf_token();
$user = current_user();
$cart_items = refresh_cart();
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
    $action = input_text($_POST, 'action');
    $productId = (int) input_text($_POST, 'product_id');
    $index = null;
    foreach ($_SESSION['cart'] as $key => $item) { if ((int) $item['id'] === $productId) { $index = $key; break; } }
    if ($action === 'add') {
        $result = execute_query_secure('SELECT id, name, price, stock FROM products WHERE id = ?', [$productId]);
        $product = $result ? $result->fetch_assoc() : null;
        $quantity = $index === null ? 0 : (int) $_SESSION['cart'][$index]['qty'];
        if (!$product || (int) $product['stock'] <= 0) {
            $_SESSION['cart_notice'] = 'Ce produit est actuellement indisponible.';
        } elseif ($quantity >= min((int) $product['stock'], 99)) {
            $_SESSION['cart_notice'] = 'La quantité disponible est déjà dans votre panier.';
        } else {
            if ($index === null) { $_SESSION['cart'][] = ['id' => $productId, 'name' => $product['name'], 'price' => (float) $product['price'], 'qty' => 1]; }
            else { $_SESSION['cart'][$index]['qty']++; }
            unset($_SESSION['checkout_token']);
            $_SESSION['cart_notice'] = $product['name'] . ' a été ajouté à votre panier.';
        }
        $query = array_filter(['q' => input_text($_POST, 'q'), 'category' => input_text($_POST, 'category')], static fn($value) => $value !== '');
        header('Location: search.php' . ($query ? '?' . http_build_query($query) : '') . '#products');
        exit;
    }
    if ($action === 'remove' || $action === 'quantity') {
        if ($index !== null) {
            if ($action === 'remove') {
                unset($_SESSION['cart'][$index]);
                $_SESSION['cart'] = array_values($_SESSION['cart']);
                $_SESSION['cart_notice'] = 'L’article a été retiré. Votre total est à jour.';
            } else {
                $quantity = filter_var(input_text($_POST, 'quantity'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 99]]);
                if ($quantity === false) { http_response_code(400); exit('La quantité doit être comprise entre 1 et 99.'); }
                $_SESSION['cart'][$index]['qty'] = $quantity;
                refresh_cart();
                $_SESSION['cart_notice'] = $_SESSION['cart_notice'] ?? 'La quantité et le total ont été mis à jour.';
            }
            unset($_SESSION['checkout_token']);
        }
        header('Location: panier.php#cart-content');
        exit;
    }
    http_response_code(400);
    exit('Action de panier invalide.');
}
$notice = $_SESSION['cart_notice'] ?? '';
unset($_SESSION['cart_notice'], $_SESSION['simulation_confirmation']);
$itemCount = array_sum(array_column($cart_items, 'qty'));
$total = cart_total_xof($cart_items);
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#f5f4f0"><title>Votre panier · CyberShield AI</title>
<link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>"><link rel="stylesheet" href="checkout.css?v=<?= (int) filemtime(__DIR__ . '/checkout.css') ?>"></head>
<body class="store-page cart-page"><?php store_header('cart', $user); ?><main class="store-main" id="main-content">
<?php store_steps('cart'); ?>
<div class="store-heading"><div><p class="store-eyebrow">VOTRE SÉLECTION</p><h1>Votre panier</h1><p><?= $itemCount ? $itemCount . ' article' . ($itemCount > 1 ? 's' : '') . ' à retrouver dans votre commande.' : 'Vos prochains essentiels commencent ici.' ?></p></div><a class="store-back" href="search.php#products"><?= store_icon('arrow') ?> Continuer mes achats</a></div>
<?php if ($notice): ?><div class="store-notice" role="status"><?= store_icon('check') ?><p><?= escape_output($notice) ?></p></div><?php endif; ?>
<?php if (!$cart_items): ?>
<section class="cart-empty"><div class="cart-empty-art"><?= store_icon('bag') ?></div><p class="store-eyebrow">UNE PLACE POUR L’ESSENTIEL</p><h2>Votre panier est vide</h2><p>Parcourez le catalogue et ajoutez les articles qui vous conviennent.</p><a class="store-button store-button--primary" href="search.php#products">Découvrir le catalogue <?= store_icon('arrow') ?></a></section>
<?php else: ?>
<div class="purchase-layout" id="cart-content"><section class="cart-selection" aria-labelledby="selection-title"><div class="purchase-section-head"><h2 id="selection-title">Vos articles</h2><span><?= $itemCount ?> article<?= $itemCount > 1 ? 's' : '' ?></span></div>
<?php foreach ($cart_items as $item): ?><article class="cart-product"><div class="cart-product-art"><?= store_product_art($item) ?></div><div class="cart-product-info"><p class="cart-product-label">ÉQUIPEMENT</p><h3><?= escape_output($item['name']) ?></h3><span class="cart-unit-price"><?= store_money((float) $item['price']) ?> <span>/ unité</span></span>
<div class="cart-product-controls"><form method="post" action="panier.php" class="quantity-control"><input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><input type="hidden" name="action" value="quantity"><input type="hidden" name="product_id" value="<?= (int) $item['id'] ?>"><button type="submit" name="quantity" value="<?= (int) $item['qty'] - 1 ?>" aria-label="Diminuer la quantité de <?= escape_output($item['name']) ?>" <?= (int) $item['qty'] <= 1 ? 'disabled' : '' ?>><?= store_icon('minus') ?></button><span aria-label="Quantité"><?= (int) $item['qty'] ?></span><button type="submit" name="quantity" value="<?= (int) $item['qty'] + 1 ?>" aria-label="Augmenter la quantité de <?= escape_output($item['name']) ?>" <?= (int) $item['qty'] >= min((int) ($item['stock'] ?? 99), 99) ? 'disabled' : '' ?>><?= store_icon('plus') ?></button></form>
<form method="post" action="panier.php" class="cart-remove-form"><input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><input type="hidden" name="action" value="remove"><input type="hidden" name="product_id" value="<?= (int) $item['id'] ?>"><button type="submit" class="cart-remove" aria-label="Retirer <?= escape_output($item['name']) ?> du panier">Retirer</button></form></div></div><strong class="cart-line-price"><?= store_xof(StoreMoney::cartTotal([$item])) ?></strong></article><?php endforeach; ?>
<div class="cart-selection-foot"><?= store_icon('bag') ?><p>Vous gardez la main.<span>Modifiez les quantités ou retirez un article avant de commander.</span></p></div></section>
<aside class="purchase-summary" aria-labelledby="summary-title"><p class="store-eyebrow">RÉCAPITULATIF</p><h2 id="summary-title">Votre récapitulatif</h2><dl class="purchase-totals"><div><dt>Articles <span>(<?= $itemCount ?>)</span></dt><dd><?= store_xof($total) ?></dd></div><div class="purchase-grand-total"><dt>Total</dt><dd><?= store_xof($total) ?></dd></div></dl><p class="purchase-summary-note">Vérifiez vos coordonnées à l’étape suivante, puis retrouvez le statut de votre commande dans votre compte.</p><a class="store-button store-button--primary purchase-main-action" href="<?= $user ? 'paiement.php' : 'login.php?redirect=paiement' ?>">Passer à la commande <?= store_icon('arrow') ?></a><a class="purchase-summary-link" href="search.php#products">Continuer mes achats</a><div class="purchase-assurance"><?= store_icon('lock') ?><span>Aucun prélèvement à cette étape.</span></div></aside></div>
<?php endif; ?></main><?php store_footer(); ?></body></html>
