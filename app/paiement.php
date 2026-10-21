<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/cart_helpers.php';
require_once __DIR__ . '/store_layout.php';
require_once __DIR__ . '/OrderService.php';
require_once __DIR__ . '/CinetPay.php';
require_once __DIR__ . '/RequestTransport.php';
validate_csrf_token();
$user = current_user();
if (!$user) { header('Location: login.php?redirect=paiement'); exit; }
$orders = new OrderService($conn);
$schemaReady = $orders->schemaInstalled();
$payments = CinetPay::fromEnvironment();
$reference = trim(input_text($_GET, 'order'));
$order = $schemaReady && $reference !== '' ? $orders->findForUser($reference, (int) $user['id']) : null;
$notFound = $reference !== '' && !$order;
if ($notFound) { http_response_code(404); }
$previousCart = $_SESSION['cart'] ?? [];
$cartItems = refresh_cart();
if ($reference === '' && !$cartItems) { header('Location: panier.php'); exit; }
$customer = [
    'name' => trim(input_text($_POST, 'name', (string) $user['username'])),
    'email' => trim(input_text($_POST, 'email', (string) $user['email'])),
    'phone' => trim(input_text($_POST, 'phone')),
    'address' => trim(input_text($_POST, 'address')),
    'city' => trim(input_text($_POST, 'city')),
    'country' => 'ML',
];
$errors = [];
$error = '';
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && input_text($_POST, 'intent') === 'pay') {
    if (!$order) { http_response_code(404); $error = 'Cette commande n’est pas accessible avec votre compte.'; }
    elseif (!$payments->isReady()) { http_response_code(503); $error = 'Le paiement en ligne n’est pas encore disponible. Votre commande est conservée.'; }
    elseif (!RequestTransport::isHttps($_SERVER)) { http_response_code(403); $error = 'Ouvrez la boutique via son adresse HTTPS avant de régler votre commande.'; }
    elseif (in_array($order['status'], ['paid', 'paid_review'], true)) {
        header('Location: paiement.php?order=' . rawurlencode($order['reference']), true, 303); exit;
    } else {
        try {
            $paymentUrl = (string) ($order['payment_url'] ?? '');
            if (!CinetPay::validCheckoutUrl($paymentUrl)) {
                $checkout = $payments->startCheckout($order);
                $paymentUrl = $checkout['payment_url'];
                $orders->attachCheckout((int) $order['id'], $paymentUrl);
            }
            header('Location: ' . $paymentUrl, true, 303); exit;
        } catch (Throwable $exception) {
            error_log('CyberShield : ouverture du guichet de paiement indisponible.');
            http_response_code(502); $error = 'Le guichet ne répond pas. Votre commande est conservée ; réessayez plus tard.';
        }
    }
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' && input_text($_POST, 'intent') !== 'pay') {
    if (input_text($_POST, 'intent') !== 'record' || $reference !== '') { http_response_code(400); exit('Action de commande invalide.'); }
    $signature = static fn(array $items) => array_map(static fn(array $item) => [(int) $item['id'], (int) $item['qty'], (float) $item['price']], $items);
    if (!$schemaReady) {
        $error = 'La prise de commande est momentanément indisponible. Votre panier est conservé.';
    } elseif ($signature($previousCart) !== $signature($cartItems)) {
        $error = 'Le prix ou le stock a changé. Vérifiez le récapitulatif avant de confirmer à nouveau.';
    } elseif (!isset($_SESSION['checkout_token']) || !hash_equals((string) $_SESSION['checkout_token'], input_text($_POST, 'checkout_token'))) {
        $error = 'Votre panier a changé ou la page a expiré. Vérifiez les articles puis confirmez à nouveau.';
    }
    if (mb_strlen($customer['name']) < 2 || mb_strlen($customer['name']) > 100) { $errors['name'] = 'Indiquez votre nom complet, de 2 à 100 caractères.'; }
    if (!filter_var($customer['email'], FILTER_VALIDATE_EMAIL) || strlen($customer['email']) > 100) { $errors['email'] = 'Indiquez une adresse e-mail valide.'; }
    if (!preg_match('/^\+?[0-9 ()-]{6,24}$/D', $customer['phone'])) { $errors['phone'] = 'Indiquez un numéro de téléphone valide avec son indicatif.'; }
    if (mb_strlen($customer['address']) < 4 || mb_strlen($customer['address']) > 200) { $errors['address'] = 'Précisez une adresse, un quartier ou un point de repère (4 à 200 caractères).'; }
    if (mb_strlen($customer['city']) < 2 || mb_strlen($customer['city']) > 80) { $errors['city'] = 'Indiquez une ville, de 2 à 80 caractères.'; }
    if (!$error && !$errors) {
        try {
            $order = $orders->createPending((int) $user['id'], $cartItems, (string) $_SESSION['checkout_token'], $customer);
            log_user_action((int) $user['id'], 'Commande enregistrée en attente de paiement');
            header('Location: paiement.php?order=' . rawurlencode($order['reference']), true, 303);
            exit;
        } catch (Throwable $exception) {
            error_log('CyberShield: enregistrement de commande indisponible (code ' . $exception->getCode() . ').');
            $error = 'La commande n’a pas pu être enregistrée. Votre panier est conservé ; vérifiez les disponibilités puis réessayez.';
        }
    }
}
if (empty($_SESSION['checkout_token'])) { $_SESSION['checkout_token'] = bin2hex(random_bytes(32)); }
$total = $order ? ((int) $order['total_cents']) / 100 : cart_total($cartItems);
$paymentAmount = $order ? (int) $order['payment_amount'] : cart_total_xof($cartItems);
$orderItems = $order ? $orders->items((int) $order['id']) : [];
$orderAdjustment = $order ? $paymentAmount - array_sum(array_map([StoreMoney::class, 'orderLine'], $orderItems)) : 0;
?>
<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#f5f4f0"><title><?= $order ? 'Votre commande' : 'Commander' ?> · CyberShield AI</title><link rel="stylesheet" href="store.css?v=<?= (int) filemtime(__DIR__ . '/store.css') ?>"><link rel="stylesheet" href="checkout.css?v=<?= (int) filemtime(__DIR__ . '/checkout.css') ?>"></head>
<body class="store-page checkout-page"><?php store_header('checkout', $user); ?><main id="main-content" class="store-main checkout-main">
<?php store_steps($order ? 'payment' : 'checkout'); ?>
<?php if ($order && $error): ?><div class="store-notice store-notice--error" role="alert"><p><?= escape_output($error) ?></p></div><?php endif; ?>
<?php if ($notFound): ?>
<div class="store-heading"><div><p class="store-eyebrow">COMMANDE INTROUVABLE</p><h1>Repartons de votre compte.</h1><p>Cette commande n’existe pas ou n’est pas accessible avec ce compte.</p></div></div><a class="store-button store-button--primary" href="dashboard.php#orders">Retrouver mes commandes <?= store_icon('arrow') ?></a>
<?php elseif ($order):
$status = (string) $order['status'];
[$statusTitle, $statusBody, $statusIcon] = match ($status) {
    'paid' => ['Votre paiement est confirmé.', 'Le règlement a été vérifié. Vous pouvez retrouver cette commande dans votre compte.', 'check'],
    'paid_review' => ['Votre commande est à vérifier.', 'Le règlement a été reçu, mais la disponibilité des articles nécessite une vérification par le marchand. Ne payez pas à nouveau.', 'clock'],
    'payment_failed' => ['Le paiement n’a pas abouti.', 'La commande reste enregistrée. Aucun paiement confirmé n’est associé à cette tentative.', 'close'],
    default => ['Votre commande est enregistrée.', 'Elle est en attente de paiement. Aucun règlement n’a encore été confirmé.', 'package'],
};
?>
<div class="store-heading"><div><p class="store-eyebrow">VOTRE COMMANDE</p><h1>Votre commande</h1></div><a class="store-back" href="dashboard.php#orders"><?= store_icon('arrow') ?> Mes commandes</a></div>
<div class="order-confirmation"><section class="order-message"><span class="order-state-icon"><?= store_icon($statusIcon) ?></span><h2><?= escape_output($statusTitle) ?></h2><p><?= escape_output($statusBody) ?></p><p><span class="store-eyebrow">RÉFÉRENCE DE COMMANDE</span><strong class="order-reference"><?= escape_output($order['reference']) ?></strong></p><dl class="order-contact"><div><dt>Contact</dt><dd><?= escape_output($order['customer_name']) ?> · <?= escape_output($order['customer_email']) ?></dd></div><div><dt>Adresse renseignée</dt><dd><?= escape_output($order['customer_address']) ?>, <?= escape_output($order['customer_city']) ?></dd></div></dl>
<?php if (!in_array($status, ['paid', 'paid_review'], true)): ?>
<?php if ($payments->isReady()): ?><p>Le règlement Mobile Money s’effectue sur le guichet sécurisé de CinetPay. Le retour à la boutique ne confirme pas à lui seul le paiement.</p><form method="post" action="paiement.php?order=<?= rawurlencode($order['reference']) ?>"><input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><input type="hidden" name="intent" value="pay"><button class="store-button store-button--primary" type="submit">Payer <?= store_xof((int) $order['payment_amount']) ?> <?= store_icon('lock') ?></button></form>
<?php else: ?><div class="store-notice store-notice--warning" role="status"><?= store_icon('lock') ?><p><strong>Paiement en ligne à activer</strong>Votre commande est conservée. Le service de paiement n’accepte pas encore de règlement.</p></div><button class="store-button store-button--primary" type="button" disabled>Payer en ligne <?= store_icon('lock') ?></button><?php endif; ?>
<?php endif; ?>
<div class="order-actions"><a class="store-button store-button--secondary" href="dashboard.php#orders">Suivre mes commandes</a><a class="store-button store-button--secondary" href="search.php#products">Retour au catalogue</a></div></section><aside class="purchase-summary"><p class="store-eyebrow">VOS ARTICLES</p><h2>Le récapitulatif</h2><ul class="checkout-lines"><?php foreach ($orderItems as $line): ?><li><span><strong><?= escape_output($line['name']) ?></strong><small>Quantité : <?= (int) $line['quantity'] ?></small></span><b><?= store_xof(StoreMoney::orderLine($line)) ?></b></li><?php endforeach; ?><?php if ($orderAdjustment !== 0): ?><li><span>Arrondi de la commande d’origine</span><b><?= $orderAdjustment > 0 ? '+' : '−' ?><?= store_xof(abs($orderAdjustment)) ?></b></li><?php endif; ?></ul><dl class="purchase-totals"><div class="purchase-grand-total"><dt>Total</dt><dd><?= store_xof($paymentAmount) ?></dd></div></dl></aside></div>
<?php else: ?>
<div class="store-heading"><div><p class="store-eyebrow">UNE DERNIÈRE VÉRIFICATION</p><h1>Finaliser la commande</h1><p>Vérifiez vos coordonnées et vos articles.</p></div><a class="store-back" href="panier.php"><?= store_icon('arrow') ?> Retour au panier</a></div>
<?php if ($error || $errors): ?><div class="store-notice store-notice--error checkout-error-summary" role="alert" id="checkout-errors"><div><strong>Vérifions ces informations.</strong><?php if ($error): ?><p><?= escape_output($error) ?></p><?php endif; ?><?php if ($errors): ?><ul><?php foreach ($errors as $field => $message): ?><li><a href="#customer-<?= escape_output($field) ?>"><?= escape_output($message) ?></a></li><?php endforeach; ?></ul><?php endif; ?></div></div><?php endif; ?>
<form method="post" action="paiement.php" class="purchase-layout"><input type="hidden" name="csrf_token" value="<?= escape_output($_SESSION['csrf_token']) ?>"><input type="hidden" name="checkout_token" value="<?= escape_output($_SESSION['checkout_token']) ?>"><input type="hidden" name="intent" value="record">
<section class="checkout-details"><div class="checkout-section-title"><span>01</span><div><h2>Vos coordonnées</h2></div></div><div class="checkout-fields">
<?php $fields = [
    'name' => ['Nom complet', 'text', 'name', 100, 'checkout-field--wide'],
    'email' => ['Adresse e-mail', 'email', 'email', 100, 'checkout-field--wide'],
    'phone' => ['Téléphone', 'tel', 'tel', 24, 'checkout-field--wide'],
    'address' => ['Adresse ou quartier', 'text', 'street-address', 200, 'checkout-field--wide'],
    'city' => ['Ville', 'text', 'address-level2', 80, ''],
]; foreach ($fields as $field => [$label, $type, $autocomplete, $maxlength, $class]): ?><div class="checkout-field <?= $class ?>"><label for="customer-<?= $field ?>"><?= $label ?></label><input id="customer-<?= $field ?>" name="<?= $field ?>" type="<?= $type ?>" value="<?= escape_output($customer[$field]) ?>" autocomplete="<?= $autocomplete ?>" maxlength="<?= $maxlength ?>" required <?= isset($errors[$field]) ? 'aria-invalid="true" aria-describedby="error-' . $field . '"' : '' ?>><?php if (isset($errors[$field])): ?><span class="checkout-field-error" id="error-<?= $field ?>"><?= escape_output($errors[$field]) ?></span><?php endif; ?></div><?php endforeach; ?><p class="checkout-location">Livraison au Mali.</p></div>
<details class="checkout-payment-info"><summary>À propos du paiement</summary><p><?= $payments->isReady() ? 'Après l’enregistrement, vous pourrez ouvrir le guichet Mobile Money de CinetPay. Aucun prélèvement à cette étape.' : 'Paiement en ligne indisponible pour le moment. L’enregistrement ne déclenche aucun prélèvement.' ?></p></details></section>
<aside class="purchase-summary"><p class="store-eyebrow">VOTRE COMMANDE</p><h2>Votre récapitulatif</h2><ul class="checkout-lines"><?php foreach ($cartItems as $item): ?><li><span><strong><?= escape_output($item['name']) ?></strong><small>Quantité : <?= (int) $item['qty'] ?></small></span><b><?= store_xof(StoreMoney::cartTotal([$item])) ?></b></li><?php endforeach; ?></ul><dl class="purchase-totals"><div class="purchase-grand-total"><dt>Total</dt><dd><?= store_xof($paymentAmount) ?></dd></div></dl><button class="store-button store-button--primary purchase-main-action" type="submit" <?= !$schemaReady ? 'disabled' : '' ?>>Enregistrer ma commande <?= store_icon('arrow') ?></button><p class="purchase-summary-note"><?= $schemaReady ? 'Sans prélèvement à cette étape.' : 'La prise de commande est momentanément indisponible. Votre panier est conservé.' ?></p></aside></form>
<?php endif; ?></main><?php store_footer(); ?></body></html>
