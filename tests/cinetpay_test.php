<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once dirname(__DIR__) . '/app/CinetPayNotification.php';
$checks = 0;
function payment_assert(bool $condition, string $message): void {
    global $checks;
    if (!$condition) { throw new RuntimeException('ÉCHEC : ' . $message); }
    $checks++;
}
function payment_reject(callable $action, string $message): void {
    try { $action(); } catch (InvalidArgumentException | RuntimeException $error) { payment_assert(true, $message); return; }
    throw new RuntimeException('ÉCHEC : ' . $message);
}
function payment_response(array $body, int $status = 200): array {
    return ['status' => $status, 'body' => json_encode($body, JSON_THROW_ON_ERROR)];
}
$config = ['enabled' => true, 'api_key' => 'fixture-key-only', 'site_id' => '123456',
    'secret_key' => 'fixture-hmac-only', 'public_url' => 'https://shop.example.com'];
$reference = 'CS' . str_repeat('AB', 16);
$order = ['reference' => $reference, 'payment_amount' => 97740, 'payment_currency' => 'XOF', 'status' => 'pending'];
$url = 'https://checkout.cinetpay.com/payment/' . str_repeat('a', 64);
$requests = [];
$fake = static function (string $endpoint, string $body) use (&$requests, $url): array {
    $requests[] = ['url' => $endpoint, 'payload' => json_decode($body, true, 16, JSON_THROW_ON_ERROR)];
    return str_ends_with($endpoint, '/check')
        ? payment_response(['code' => '00', 'data' => ['amount' => '97740', 'currency' => 'XOF', 'status' => 'ACCEPTED']])
        : payment_response(['code' => '201', 'data' => ['payment_url' => $url]]);
};
try {
    $disabled = new CinetPay(array_replace($config, ['enabled' => false]), $fake);
    payment_assert(!$disabled->isReady(), 'Désactivation prioritaire sur les identifiants');
    payment_reject(static fn() => $disabled->startCheckout($order), 'Aucun initialisation désactivée');
    payment_reject(static fn() => $disabled->checkTransaction($reference), 'Aucune vérification désactivée');
    payment_assert($requests === [], 'Zéro transport quand désactivé');
    foreach ([['secret_key' => ''], ['site_id' => '12x'], ['api_key' => "bad\nkey"], ['public_url' => 'http://shop.example.com']] as $bad) {
        $client = new CinetPay(array_replace($config, $bad), $fake);
        payment_assert(!$client->isReady(), 'Configuration incomplète refusée');
    }
    $client = new CinetPay($config, $fake);
    payment_assert($client->isReady(), 'Préparation activable uniquement avec configuration complète');
    payment_assert($client->startCheckout($order, ['email' => 'private@test.invalid', 'name' => 'Private']) === ['payment_url' => $url], 'Guichet officiel vérifié');
    $payload = $requests[0]['payload'];
    payment_assert($requests[0]['url'] === 'https://api-checkout.cinetpay.com/v2/payment', 'Hôte API constant');
    payment_assert($payload['amount'] === 97740 && $payload['currency'] === 'XOF', 'Montant entier en FCFA');
    payment_assert($payload['transaction_id'] === $reference && $payload['metadata'] === $reference, 'Référence persistante utilisée');
    payment_assert($payload['channels'] === 'MOBILE_MONEY', 'Canal prévu explicite');
    payment_assert($payload['notify_url'] === 'https://shop.example.com/app/payment-notify.php', 'Notification HTTPS fixe');
    payment_assert(!str_contains(json_encode($payload), 'private@test.invalid') && !array_filter(array_keys($payload), static fn($key) => str_starts_with($key, 'customer_')), 'Aucune coordonnée client transférée');
    foreach ([['payment_amount' => 4], ['payment_amount' => 97741], ['payment_amount' => 97740.0], ['payment_currency' => 'EUR'], ['status' => 'paid'], ['reference' => 'foreign']] as $bad) {
        $count = count($requests);
        payment_reject(static fn() => $client->startCheckout(array_replace($order, $bad)), 'Commande non payable rejetée');
        payment_assert(count($requests) === $count, 'Validation avant transport');
    }
    $checked = $client->checkTransaction($reference);
    payment_assert($checked['status'] === 'ACCEPTED' && $checked['amount'] === '97740' && $checked['reference'] === $reference, 'Résultat serveur normalisé');
    foreach ([
        ['code' => '00', 'data' => ['amount' => '97740', 'currency' => 'EUR', 'status' => 'ACCEPTED']],
        ['code' => '627', 'data' => ['amount' => '97740', 'currency' => 'XOF', 'status' => 'ACCEPTED']],
        ['code' => '00', 'data' => ['amount' => [], 'currency' => 'XOF', 'status' => 'ACCEPTED']],
        ['code' => '00', 'data' => ['amount' => '97740', 'currency' => 'XOF', 'status' => 'UNKNOWN']],
        ['code' => '00', 'data' => ['amount' => '97740', 'currency' => 'XOF', 'status' => 'ACCEPTED', 'metadata' => 'other']],
        ['code' => '00', 'data' => ['amount' => '97740', 'currency' => 'XOF', 'status' => 'ACCEPTED', 'site_id' => []]],
    ] as $body) {
        $invalid = new CinetPay($config, static fn() => payment_response($body));
        payment_reject(static fn() => $invalid->checkTransaction($reference), 'Vérification incohérente rejetée');
    }
    foreach ([['status' => 302, 'body' => '{}'], ['status' => 200, 'body' => 'invalid'], ['status' => 200, 'body' => str_repeat('x', 65537)]] as $response) {
        $invalid = new CinetPay($config, static fn() => $response);
        payment_reject(static fn() => $invalid->checkTransaction($reference), 'Erreur HTTP ou réponse invalide rejetée');
    }
    $invalid = new CinetPay($config, static fn() => payment_response(['code' => '201', 'data' => ['payment_url' => 'https://checkout.cinetpay.com.evil.example/payment/' . str_repeat('a', 64)]]));
    payment_reject(static fn() => $invalid->startCheckout($order), 'Redirection vers un autre hôte rejetée');
    $posted = ['cpm_site_id' => '123456', 'cpm_trans_id' => $reference, 'cpm_trans_date' => '2026-10-21 12:00:00',
        'cpm_amount' => '97740', 'cpm_currency' => 'XOF', 'signature' => 'fixture', 'payment_method' => 'OM',
        'cel_phone_num' => '', 'cpm_phone_prefixe' => '', 'cpm_language' => 'fr', 'cpm_version' => 'V4',
        'cpm_payment_config' => 'Single', 'cpm_page_action' => 'Payment', 'cpm_custom' => $reference,
        'cpm_designation' => 'Commande', 'cpm_error_message' => ''];
    $token = hash_hmac('sha256', implode('', $posted), $config['secret_key']);
    $reconciliations = [];
    $reconcile = static function ($ref, $verification) use (&$reconciliations): void { $reconciliations[] = [$ref, $verification]; };
    $count = count($requests);
    payment_reject(static fn() => CinetPayNotification::process($client, $posted, str_repeat('0', 64), $reconcile), 'Faux HMAC rejeté');
    payment_assert(count($requests) === $count && $reconciliations === [], 'HMAC vérifié avant réseau et mutation');
    foreach (['WAITING_FOR_CUSTOMER' => '600', 'REFUSED' => '627', 'ACCEPTED' => '00'] as $state => $code) {
        $notifier = new CinetPay($config, static fn() => payment_response(['code' => $code, 'data' => ['amount' => '97740', 'currency' => 'XOF', 'status' => $state, 'metadata' => $reference]]));
        CinetPayNotification::process($notifier, $posted, $token, $reconcile);
        payment_assert(end($reconciliations)[1]['status'] === $state, 'État serveur transmis sans invention');
    }
    payment_assert(count($reconciliations) === 3, 'Notifications vérifiées remises au service transactionnel');
    echo "OK: $checks payment checks passed; transport fictif uniquement, aucun appel réseau ni paiement.\n";
} catch (Throwable $error) { fwrite(STDERR, $error->getMessage() . PHP_EOL); exit(1); }
