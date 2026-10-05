<?php
/** Revalide les prix et quantités depuis le catalogue, sans modifier le stock. */
function refresh_cart(): array {
    $validated = [];
    $changed = false;
    foreach ($_SESSION['cart'] ?? [] as $item) {
        $result = execute_query_secure('SELECT id, name, price, stock FROM products WHERE id = ?', [(int) ($item['id'] ?? 0)]);
        $product = $result ? $result->fetch_assoc() : null;
        if (!$product || (int) $product['stock'] <= 0) { $changed = true; continue; }
        $qty = min(max(1, (int) ($item['qty'] ?? 1)), (int) $product['stock'], 99);
        if ($qty !== (int) $item['qty'] || (float) $product['price'] !== (float) $item['price']) { $changed = true; }
        $validated[] = ['id' => (int) $product['id'], 'name' => $product['name'], 'price' => (float) $product['price'], 'qty' => $qty];
    }
    $_SESSION['cart'] = $validated;
    if ($changed) { $_SESSION['cart_notice'] = 'Le panier a été actualisé selon les prix et le stock disponibles.'; }
    return $validated;
}

function cart_total(array $items): float {
    $cents = 0;
    foreach ($items as $item) { $cents += (int) round($item['price'] * 100) * $item['qty']; }
    return $cents / 100;
}
