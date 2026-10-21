<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once dirname(__DIR__) . '/app/OrderService.php';
require_once dirname(__DIR__) . '/app/CinetPay.php';
require_once dirname(__DIR__) . '/app/DatabasePassword.php';
$checks = 0;
function order_check(bool $condition, string $description): void
{
    global $checks;
    if (!$condition) { throw new RuntimeException('ÉCHEC : ' . $description); }
    $checks++;
    echo 'OK ' . $description . PHP_EOL;
}
function order_rejects(callable $action, string $description): void
{
    try { $action(); } catch (InvalidArgumentException | RuntimeException $exception) {
        order_check(true, $description); return;
    }
    throw new RuntimeException('ÉCHEC : ' . $description);
}

try {
    order_check(OrderService::priceInCents('149.00') === 14900, 'Prix DECIMAL converti sans arrondi flottant');
    order_check(OrderService::priceInCents('0.10') === 10, 'Dix centimes restent dix centimes');
    order_check(OrderService::priceInCents('7.5') === 750, 'Décimale simple normalisée');
    order_rejects(static fn() => OrderService::priceInCents('-10'), 'Prix négatif refusé');
    order_check(OrderService::amountInXof(14900) === 97740, '149 EUR convertis en 97 740 XOF');
    order_check(OrderService::amountInXof(100) === 655, 'Arrondi au multiple de cinq XOF le plus proche');
    order_rejects(static fn() => OrderService::amountInXof(0), 'Commande nulle refusée');
    order_rejects(static fn() => OrderService::amountInXof(100000001), 'Montant borné avant multiplication');
    $reference = 'CS' . str_repeat('A1', 16);
    order_check(OrderService::validReference($reference) && !OrderService::validReference("' OR 1=1 --"), 'Références strictes et non séquentielles');
    order_check(CinetPay::validCheckoutUrl('https://checkout.cinetpay.com/payment/' . str_repeat('a', 64)), 'Guichet HTTPS officiel accepté');
    foreach (['http://checkout.cinetpay.com/payment/' . str_repeat('a', 64), 'https://checkout.cinetpay.com.evil.example/payment/' . str_repeat('a', 64), 'https://attacker@checkout.cinetpay.com/payment/' . str_repeat('a', 64), 'javascript:alert(1)'] as $url) {
        order_check(!CinetPay::validCheckoutUrl($url), 'Adresse de guichet trompeuse refusée');
    }
    foreach (['http://shop.example.com', 'https://127.0.0.1', 'https://10.0.0.1', 'https://localhost', 'https://shop.local', 'https://shop.example.com/?secret=x'] as $url) {
        order_check(!CinetPay::validPublicUrl($url), 'Adresse publique non adaptée refusée');
    }
    order_check(CinetPay::validPublicUrl('https://shop.example.com'), 'Origine publique HTTPS acceptée');
    $configuration = ['enabled' => false, 'api_key' => 'test-only-api-key', 'site_id' => '123456', 'secret_key' => 'test-only-hmac-secret', 'public_url' => 'https://shop.example.com'];
    $payments = new CinetPay($configuration);
    order_check(!$payments->isReady(), 'Envoi externe désactivé même avec des identifiants fournis');
    order_rejects(static fn() => $payments->startCheckout([]), 'Aucune ouverture de paiement sans activation');
    order_rejects(static fn() => $payments->checkTransaction($reference), 'Aucun statut financier fabriqué');
    $posted = [
        'cpm_site_id' => '123456', 'cpm_trans_id' => $reference, 'cpm_trans_date' => '2026-10-19 12:00:00',
        'cpm_amount' => '97740', 'cpm_currency' => 'XOF', 'signature' => 'provider-fixture',
        'payment_method' => 'OM', 'cel_phone_num' => '', 'cpm_phone_prefixe' => '', 'cpm_language' => 'fr',
        'cpm_version' => 'V4', 'cpm_payment_config' => 'Single', 'cpm_page_action' => 'Payment',
        'cpm_custom' => $reference, 'cpm_designation' => 'Commande', 'cpm_error_message' => '',
    ];
    $token = hash_hmac('sha256', implode('', $posted), $configuration['secret_key']);
    order_check($payments->verifyNotification($posted, $token) === $reference, 'HMAC vérifié selon les champs officiels');
    $tampered = $posted; $tampered['cpm_amount'] = '5';
    order_rejects(static fn() => $payments->verifyNotification($tampered, $token), 'Montant de notification altéré refusé');
    $reordered = array_reverse($posted, true);
    order_check($payments->verifyNotification($reordered, $token) === $reference, 'Ordre du formulaire sans effet sur l’ordre canonique HMAC');
    $foreignSite = $posted; $foreignSite['cpm_site_id'] = '999999';
    $foreignToken = hash_hmac('sha256', implode('', $foreignSite), $configuration['secret_key']);
    order_rejects(static fn() => $payments->verifyNotification($foreignSite, $foreignToken), 'Notification d’un autre site marchand refusée');
    $arrayField = $posted; $arrayField['signature'] = ['unexpected'];
    order_rejects(static fn() => $payments->verifyNotification($arrayField, $token), 'Paramètre tableau refusé');

    if (in_array('--database', $argv, true)) {
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $db = new mysqli(getenv('DB_HOST') ?: '127.0.0.1', getenv('DB_USER') ?: 'root', cybershield_database_password(), getenv('DB_NAME') ?: 'projet_sqli_vulnerable', (int) (getenv('DB_PORT') ?: 3306));
        $db->set_charset('utf8mb4');
        // Toutes les tables utilisées par le service sont temporaires et masquent les vraies.
        // Aucun CREATE/DROP/UPDATE ne touche les données applicatives persistantes.
        $db->query('CREATE TEMPORARY TABLE users (id INT PRIMARY KEY, username VARCHAR(50), email VARCHAR(100), active TINYINT NOT NULL DEFAULT 1) ENGINE=InnoDB');
        $db->query('CREATE TEMPORARY TABLE products (id INT PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2), stock INT) ENGINE=InnoDB');
        $schema = file_get_contents(dirname(__DIR__) . '/database/orders.sql');
        $schema = str_replace('CREATE TABLE IF NOT EXISTS', 'CREATE TEMPORARY TABLE', $schema);
        $schema = preg_replace('/,\s*CONSTRAINT [^\n]+/', '', $schema);
        $db->multi_query($schema);
        do {
            if ($result = $db->store_result()) { $result->free(); }
            if (!$db->more_results()) { break; }
        } while ($db->next_result());
        $db->query("INSERT INTO users (id, username, email) VALUES (1, 'client1', 'one@example.com'), (2, 'client2', 'two@example.com')");
        $db->query("INSERT INTO products (id, name, price, stock) VALUES (1, 'Produit A', 149.00, 10), (2, 'Produit B', 7.50, 3)");
        $orders = new OrderService($db);
        order_check($orders->schemaInstalled(), 'Schéma des commandes disponible');
        $checkoutToken = str_repeat('1a', 32);
        $order = $orders->createPending(1, [['id' => 1, 'qty' => 2, 'price' => 0.01, 'name' => 'Prix falsifié']], $checkoutToken);
        order_check((int) $order['total_cents'] === 29800 && (int) $order['payment_amount'] === 195480, 'Prix et total FCFA reconstruits depuis le catalogue verrouillé et les unités arrondies');
        order_check((int) $db->query('SELECT stock FROM products WHERE id=1')->fetch_row()[0] === 10, 'Aucun stock débité à la création');
        $lines = $orders->items((int) $order['id']);
        order_check($lines[0]['name'] === 'Produit A' && (int) $lines[0]['quantity'] === 2, 'Instantané du produit et de la quantité conservé');
        order_check(StoreMoney::orderLine($lines[0]) === (int) $order['payment_amount'] && $order['currency'] === 'EUR' && $order['payment_currency'] === 'XOF', 'Total FCFA égal à la somme des prix unitaires affichés, instantané EUR interne conservé');
        $repeated = $orders->createPending(1, [], $checkoutToken);
        order_check($repeated['reference'] === $order['reference'] && count($orders->listForUser(1)) === 1, 'Double envoi idempotent même si le panier change');
        // Une ancienne commande pouvait être arrondie après totalisation EUR.
        // Rejouer son jeton ne doit ni la convertir ni changer le montant dû.
        $db->query('UPDATE commerce_orders SET payment_amount = 195475 WHERE id = ' . (int) $order['id']);
        $historical = $orders->createPending(1, [], $checkoutToken);
        order_check((int) $historical['payment_amount'] === 195475, 'Ancien montant enregistré conservé lors d’une tentative répétée');
        $db->query('UPDATE commerce_orders SET payment_amount = 195480 WHERE id = ' . (int) $order['id']);
        order_check($orders->findForUser($order['reference'], 2) === null, 'Accès à une commande d’un autre compte refusé');
        order_check(count($orders->listForUser(2)) === 0, 'Historique limité au propriétaire');
        order_rejects(static fn() => $orders->createPending(1, [['id' => 1, 'qty' => 11]], str_repeat('2b', 32)), 'Stock insuffisant refusé à la commande');
        order_rejects(static fn() => $orders->createPending(1, [['id' => '1 OR 1=1', 'qty' => 1]], str_repeat('3c', 32)), 'Identifiant article injecté refusé');
        order_check(count($orders->listForUser(1)) === 1, 'Création refusée ne laisse aucune commande partielle');
        $proof = ['code' => '00', 'status' => 'ACCEPTED', 'amount' => (string) $order['payment_amount'], 'currency' => 'XOF'];
        $badAmount = $proof; $badAmount['amount'] = '5';
        order_rejects(static fn() => $orders->reconcilePayment($order['reference'], $badAmount), 'Paiement de montant différent refusé');
        $badCurrency = $proof; $badCurrency['currency'] = 'EUR';
        order_rejects(static fn() => $orders->reconcilePayment($order['reference'], $badCurrency), 'Paiement de devise différente refusé');
        $waiting = $proof; $waiting['status'] = 'WAITING_FOR_CUSTOMER'; $waiting['code'] = '623';
        order_check($orders->reconcilePayment($order['reference'], $waiting)['status'] === 'pending', 'Attente opérateur conservée en attente');
        order_check($orders->reconcilePayment($order['reference'], $proof)['status'] === 'paid', 'Confirmation vérifiée marque la commande payée');
        order_check((int) $db->query('SELECT stock FROM products WHERE id=1')->fetch_row()[0] === 8, 'Stock débité exactement à la confirmation');
        $orders->reconcilePayment($order['reference'], $proof);
        $refused = $proof; $refused['status'] = 'REFUSED'; $refused['code'] = '627';
        $orders->reconcilePayment($order['reference'], $refused);
        order_check((int) $db->query('SELECT stock FROM products WHERE id=1')->fetch_row()[0] === 8 && $orders->findForUser($order['reference'], 1)['status'] === 'paid', 'Notifications répétées ou tardives sans double débit ni régression');
        $review = $orders->createPending(2, [['id' => 2, 'qty' => 3]], str_repeat('4d', 32));
        $db->query('UPDATE products SET stock=1 WHERE id=2');
        $reviewProof = ['code' => '00', 'status' => 'ACCEPTED', 'amount' => (string) $review['payment_amount'], 'currency' => 'XOF'];
        order_check($orders->reconcilePayment($review['reference'], $reviewProof)['status'] === 'paid_review', 'Paiement encaissé mais stock devenu insuffisant signalé pour revue');
        order_check((int) $db->query('SELECT stock FROM products WHERE id=2')->fetch_row()[0] === 1, 'Stock jamais négatif et pas de débit partiel en revue');
        $failed = $orders->createPending(2, [['id' => 2, 'qty' => 1]], str_repeat('5e', 32));
        $failedProof = ['code' => '627', 'status' => 'REFUSED', 'amount' => (string) $failed['payment_amount'], 'currency' => 'XOF'];
        order_check($orders->reconcilePayment($failed['reference'], $failedProof)['status'] === 'payment_failed', 'Refus prestataire conservé sans annoncer un paiement');
        $db->close();
    }
    echo $checks . " contrôles réussis ; aucun appel externe ni transaction financière.\n";
} catch (Throwable $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
