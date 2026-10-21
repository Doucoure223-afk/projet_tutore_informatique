<?php
/** Integration locale : cree et retire uniquement sa propre base aleatoire. */
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (!extension_loaded('mysqli') || !extension_loaded('curl')) {
    fwrite(STDERR, "Utiliser PHP avec mysqli et curl (PHP de Wamp).\n"); exit(1);
}
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$root = dirname(__DIR__);
$database = 'cybershield_test_' . bin2hex(random_bytes(6));
$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $database;
mkdir($directory, 0700);
$ownedDatabase = false;
$server = null;
$client = null;
$checks = 0;
$exitCode = 0;
function check_app(bool $condition, string $message): void {
    global $checks;
    if (!$condition) { throw new RuntimeException($message); }
    $checks++;
    echo "OK $message\n";
}
function import_app_sql(mysqli $connection, string $sql): void {
    $connection->multi_query($sql);
    do {
        if ($result = $connection->store_result()) { $result->free(); }
        if (!$connection->more_results()) { break; }
    } while ($connection->next_result());
}
function app_request(string $path, ?array $data = null): array {
    global $client, $baseUrl;
    curl_setopt($client, CURLOPT_URL, $baseUrl . $path);
    curl_setopt($client, CURLOPT_POSTFIELDS, null);
    curl_setopt($client, CURLOPT_HTTPGET, true);
    if ($data !== null) {
        curl_setopt($client, CURLOPT_POST, true);
        curl_setopt($client, CURLOPT_POSTFIELDS, http_build_query($data));
    }
    $body = curl_exec($client);
    if ($body === false) { throw new RuntimeException(curl_error($client)); }
    if (preg_match('/Fatal error|Warning:|Parse error|Deprecated:/', $body)) {
        throw new RuntimeException('Erreur PHP dans ' . $path);
    }
    return ['body' => $body, 'status' => curl_getinfo($client, CURLINFO_RESPONSE_CODE), 'url' => curl_getinfo($client, CURLINFO_EFFECTIVE_URL)];
}
function app_token(array $response): string {
    if (!preg_match('/name="csrf_token" value="([a-f0-9]+)"/', $response['body'], $matches)) {
        throw new RuntimeException('Jeton CSRF absent');
    }
    return $matches[1];
}
function app_checkout_token(array $response): string {
    if (!preg_match('/name="checkout_token" value="([a-f0-9]{64})"/', $response['body'], $matches)) {
        throw new RuntimeException('Jeton de commande absent');
    }
    return $matches[1];
}
function app_oversized_path_status(string $root, array $environment): int {
    // Le serveur PHP intégré rejette les lignes HTTP > 8 Ko avant le middleware.
    // Exercer ce cas dans PHP évite de confondre sa limite avec celle de l'application.
    $code = 'register_shutdown_function(static function () { echo "\nHTTP_STATUS:" . http_response_code(); });'
        . '$_SERVER["REQUEST_METHOD"]="GET"; $_SERVER["REMOTE_ADDR"]="127.0.0.1";'
        . '$_SERVER["HTTP_ACCEPT"]="application/json"; $_SERVER["REQUEST_URI"]="/app/search.php/".str_repeat("a",8193);'
        . 'require ' . var_export($root . '/security/bootstrap.php', true) . ';';
    $process = proc_open([PHP_BINARY, '-r', $code], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, $root, $environment, ['bypass_shell' => true]);
    if (!is_resource($process)) { throw new RuntimeException('Sous-processus de taille de chemin indisponible.'); }
    fclose($pipes[0]);
    $output = stream_get_contents($pipes[1]); fclose($pipes[1]);
    $errors = stream_get_contents($pipes[2]); fclose($pipes[2]);
    if (proc_close($process) !== 0 || !preg_match('/HTTP_STATUS:(\d+)$/', $output, $matches)) {
        throw new RuntimeException('Contrôle du chemin long impossible : ' . $errors);
    }
    return (int) $matches[1];
}
try {
    $host = getenv('DB_HOST') ?: '127.0.0.1';
    $user = getenv('DB_USER') ?: 'root';
    $password = getenv('DB_PASSWORD') ?: '';
    $port = (int) (getenv('DB_PORT') ?: 3306);
    $db = new mysqli($host, $user, $password, '', $port);
    $db->set_charset('utf8mb4');
    // Sans IF NOT EXISTS : le test ne peut jamais prendre possession d'une base existante.
    $db->query('CREATE DATABASE `' . $database . '` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $ownedDatabase = true;
    $schema = str_replace('projet_sqli_vulnerable', $database, file_get_contents($root . '/database/schema.sql'));
    $seed = str_replace('projet_sqli_vulnerable', $database, file_get_contents($root . '/database/seed_products.sql'));
    import_app_sql($db, $schema);
    import_app_sql($db, $seed);
    $db->select_db($database);
    import_app_sql($db, file_get_contents($root . '/database/orders.sql'));
    $db->query('UPDATE products SET price = 7.50, stock = 2 WHERE id = 1');
    import_app_sql($db, $schema);
    import_app_sql($db, $seed);
    check_app((int) $db->query('SELECT COUNT(*) FROM products')->fetch_row()[0] === 8, 'Double import sans doublons');
    check_app((float) $db->query('SELECT price FROM products WHERE id = 1')->fetch_row()[0] === 7.5, 'Seed preserve les produits existants');
    check_app((int) $db->query('SELECT COUNT(*) FROM users')->fetch_row()[0] === 0, 'Aucun compte partagé créé par défaut');
    require_once $root . '/app/SecureDataGateway.php';
    $gateway = new SecureDataGateway($db);
    check_app($gateway->execute('SELECT id FROM users WHERE username = ?', ["' OR 1=1 -- "])->num_rows === 0, 'Gateway refuse le contournement SQLi');
    $gateway->execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, 'user')", ['legacy_test', 'LegacyPassword!2026', 'legacy@test.invalid']);

    $socket = stream_socket_server('tcp://127.0.0.1:0');
    if (!$socket) { throw new RuntimeException('Port local indisponible'); }
    $address = stream_socket_get_name($socket, false);
    fclose($socket);
    $baseUrl = 'http://' . $address;
    $environment = array_merge(getenv(), ['DB_HOST' => $host, 'DB_USER' => $user, 'DB_PASSWORD' => $password,
        'DB_NAME' => $database, 'DB_PORT' => (string) $port, 'CYBERSHIELD_LOG_DIR' => $directory, 'APP_ENV' => 'test']);
    $server = proc_open([PHP_BINARY, '-d', 'xdebug.mode=off', '-d', 'session.save_path=' . $directory,
        '-S', $address, '-t', $root], [0 => ['pipe', 'r'], 1 => ['file', $directory . '/server.log', 'a'],
        2 => ['file', $directory . '/server.log', 'a']], $pipes, $root, $environment, ['bypass_shell' => true]);
    if (!is_resource($server)) { throw new RuntimeException('Serveur PHP indisponible'); }
    fclose($pipes[0]);
    $client = curl_init();
    curl_setopt_array($client, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_TIMEOUT => 10,
        CURLOPT_COOKIEFILE => '', CURLOPT_PROXY => '']);
    $ready = false;
    for ($attempt = 0; $attempt < 30; $attempt++) {
        try { $response = app_request('/app/search.php'); $ready = true; break; }
        catch (RuntimeException $e) { usleep(100000); }
    }
    check_app($ready && $response['status'] === 200, 'Catalogue HTTP disponible');
    check_app(str_contains($response['body'], 'FCFA') && !preg_match('/€|&euro;|\bEUR\b/u', $response['body']), 'Catalogue affiche uniquement les prix en FCFA');
    require_once $root . '/security/ip_access.php';
    $testIpPolicy = new IpAccessControl($directory);
    $testIpPolicy->addRule('127.0.0.1', 'middleware integration');
    check_app(app_request('/app/search.php')['status'] === 403, 'Regle IP refuse une requete applicative');
    $events = array_map(static fn(string $line) => json_decode($line, true), file($directory . '/events.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    $ipEvents = array_values(array_filter($events, static fn($event) => is_array($event) && ($event['attack_type'] ?? '') === 'IP_ACCESS_RULE'));
    check_app(($ipEvents[0]['action'] ?? '') === 'BLOCKED' && ($ipEvents[0]['source'] ?? '') === 'ip_policy', 'Refus IP ajouté au journal structuré');
    $testIpPolicy->removeRule('127.0.0.1');
    check_app(app_request('/app/search.php')['status'] === 200, 'Suppression de regle IP retablit la requete');
    $token = app_token($response);
    $pathPayload = rawurlencode("' OR '1'='1 --");
    check_app(app_request('/app/search.php/' . $pathPayload)['status'] === 403, 'Injection SQLi dans le chemin URL bloquee');
    check_app(app_request('/app/search.php?q=%27a%27%3D%27a%27')['status'] === 403, 'Preselection MLP bloque une injection sans signature PHP');
    check_app(app_oversized_path_status($root, $environment) === 413, 'Chemin URL trop long refuse par le middleware');
    check_app(app_request('/app/panier.php', ['action' => 'add', 'product_id' => '1'])['status'] === 403, 'Ajout sans CSRF refuse');
    $response = app_request('/app/panier.php?add=1&validated=1');
    check_app(str_contains($response['body'], 'Votre panier est vide') && (int) $db->query('SELECT COUNT(*) FROM commerce_orders')->fetch_row()[0] === 0, 'GET ne modifie ni le panier ni les commandes');
    for ($i = 0; $i < 3; $i++) { app_request('/app/panier.php', ['action' => 'add', 'product_id' => '1', 'csrf_token' => $token]); }
    $response = app_request('/app/panier.php');
    check_app(str_contains($response['body'], '<span aria-label="Quantité">2</span>') && str_contains($response['body'], '9 840 FCFA'), 'Stock limite a deux et total FCFA correct');
    check_app(!preg_match('/€|&euro;|\bEUR\b/u', $response['body']), 'Panier ne montre ni euros ni seconde devise');
    $response = app_request('/app/login.php', ['username' => "' OR 1=1 -- ", 'password' => 'anything', 'csrf_token' => $token]);
    check_app(in_array($response['status'], [200, 403], true) && !str_contains($response['url'], 'dashboard.php'), 'Injection login ne connecte pas');
    $response = app_request('/app/inscription.php', ['username' => 'registered_test', 'password' => 'NewPassword!2026', 'mail' => 'new@test.invalid', 'role' => 'admin', 'csrf_token' => $token]);
    $registered = $db->query("SELECT password, role FROM users WHERE username = 'registered_test'")->fetch_assoc();
    check_app($registered !== null && $registered['role'] === 'user' && password_verify('NewPassword!2026', $registered['password']), 'Inscription hache le mot de passe et refuse auto-admin');
    $response = app_request('/app/login.php', ['username' => 'registered_test', 'password' => 'NewPassword!2026', 'csrf_token' => $token]);
    check_app(str_contains($response['url'], 'dashboard.php'), 'Connexion avec mot de passe hache');
    $response = app_request('/app/login.php?redirect=console');
    check_app(str_contains($response['url'], '/security/dashboard.php') && $response['status'] === 200,
        'Connexion depuis la console retourne à la supervision demandée');
    check_app(app_request('/app/dashboard.php?admin_search=test')['status'] === 403, 'Recherche admin refusee au client');
    $response = app_request('/app/paiement.php');
    $token = app_token($response);
    $checkoutToken = app_checkout_token($response);
    check_app(str_contains($response['body'], '9 840 FCFA') && str_contains($response['body'], 'Enregistrer ma commande') && !str_contains($response['body'], 'name="card"'), 'Commande affiche le total FCFA sans collecter de carte');
    check_app(!preg_match('/€|&euro;|\bEUR\b/u', $response['body']), 'Page de commande affiche uniquement des montants FCFA');
    check_app(app_request('/app/paiement.php', ['intent' => 'record'])['status'] === 403, 'Enregistrement sans CSRF refuse');
    check_app(app_request('/app/paiement.php', ['intent' => 'pay', 'csrf_token' => $token])['status'] === 400, 'Action de paiement non disponible refusee cote serveur');
    check_app(app_request('/app/paiement.php', ['validate_without_pay' => '1', 'csrf_token' => $token])['status'] === 400, 'Ancien contournement administrateur supprime');
    $customer = ['name' => 'Client Test', 'email' => 'buyer@example.com', 'phone' => '+223 70000000', 'address' => 'Quartier de test, Bamako', 'city' => 'Bamako'];
    $invalidCustomer = app_request('/app/paiement.php', ['intent' => 'record', 'checkout_token' => $checkoutToken, 'csrf_token' => $token]);
    check_app($invalidCustomer['status'] === 200 && str_contains($invalidCustomer['body'], 'aria-invalid="true"') && (int) $db->query('SELECT COUNT(*) FROM commerce_orders')->fetch_row()[0] === 0, 'Coordonnees manquantes signalees sans creation partielle');
    $missingCheckout = app_request('/app/paiement.php', array_merge($customer, ['intent' => 'record', 'csrf_token' => $token]));
    check_app($missingCheckout['status'] === 200 && str_contains($missingCheckout['body'], 'page a expiré') && (int) $db->query('SELECT COUNT(*) FROM commerce_orders')->fetch_row()[0] === 0, 'Jeton de commande absent refuse sans vider le panier');
    $response = app_request('/app/panier.php', ['action' => 'quantity', 'product_id' => '1', 'quantity' => '1', 'csrf_token' => $token]);
    check_app(str_contains($response['body'], '<span aria-label="Quantité">1</span>') && str_contains($response['body'], '4 920 FCFA'), 'Modification de quantite recalcule le total FCFA');
    $newCheckoutToken = app_checkout_token(app_request('/app/paiement.php'));
    check_app($newCheckoutToken !== $checkoutToken, 'Modification du panier renouvelle le jeton de commande');
    $expiredCheckout = app_request('/app/paiement.php', array_merge($customer, ['intent' => 'record', 'checkout_token' => $checkoutToken, 'csrf_token' => $token]));
    check_app(str_contains($expiredCheckout['body'], 'panier a changé') && (int) $db->query('SELECT COUNT(*) FROM commerce_orders')->fetch_row()[0] === 0, 'Ancienne page de commande refusee apres mutation du panier');
    $response = app_request('/app/panier.php', ['action' => 'quantity', 'product_id' => '1', 'quantity' => '99', 'csrf_token' => $token]);
    check_app(str_contains($response['body'], '<span aria-label="Quantité">2</span>') && str_contains($response['body'], '9 840 FCFA'), 'Quantite demandee limitee au stock reel');
    check_app(app_request('/app/panier.php', ['action' => 'quantity', 'product_id' => '1', 'quantity' => '0', 'csrf_token' => $token])['status'] === 400, 'Quantite nulle refusee');
    $response = app_request('/app/paiement.php');
    $checkoutToken = app_checkout_token($response);
    $checkout = array_merge($customer, ['intent' => 'record', 'checkout_token' => $checkoutToken, 'csrf_token' => $token]);
    $response = app_request('/app/paiement.php', $checkout);
    $persistedOrder = $db->query('SELECT * FROM commerce_orders ORDER BY id LIMIT 1')->fetch_assoc();
    check_app($response['status'] === 200 && is_array($persistedOrder) && str_contains($response['url'], 'order=' . $persistedOrder['reference']) && str_contains($response['body'], 'Votre commande est enregistrée.'), 'Enregistrement explicite cree une vraie commande persistante');
    check_app(str_contains($response['body'], '9 840 FCFA') && !preg_match('/€|&euro;|\bEUR\b/u', $response['body']), 'Confirmation conserve le même total public en FCFA');
    check_app($persistedOrder['status'] === 'pending' && (int) $persistedOrder['total_cents'] === 1500 && (int) $persistedOrder['payment_amount'] === 9840 && $persistedOrder['customer_name'] === $customer['name'], 'Commande conserve montants EUR et XOF, coordonnees et etat en attente');
    check_app(str_contains($response['body'], 'Paiement en ligne à activer') && preg_match('/<button[^>]+disabled>\s*Payer en ligne/', $response['body']) === 1, 'Règlement indisponible affiche clairement avec bouton desactive');
    $orderLine = $db->query('SELECT * FROM commerce_order_items LIMIT 1')->fetch_assoc();
    check_app(is_array($orderLine) && (int) $orderLine['quantity'] === 2 && (int) $orderLine['unit_price_cents'] === 750, 'Articles commandes conserves avec leurs prix et quantites');
    $response = app_request('/app/paiement.php', $checkout);
    check_app((int) $db->query('SELECT COUNT(*) FROM commerce_orders')->fetch_row()[0] === 1 && str_contains($response['url'], $persistedOrder['reference']), 'Double clic ne cree pas une deuxieme commande');
    $cartAfterOrder = app_request('/app/panier.php');
    check_app(str_contains($cartAfterOrder['body'], '<span aria-label="Quantité">2</span>') && str_contains($cartAfterOrder['body'], '9 840 FCFA'), 'Panier conserve apres enregistrement sans paiement');
    $response = app_request('/app/paiement.php?order=' . $persistedOrder['reference'] . '&paid=1&status=ACCEPTED');
    check_app(str_contains($response['body'], 'en attente de paiement') && $db->query('SELECT status FROM commerce_orders LIMIT 1')->fetch_row()[0] === 'pending', 'Retour navigateur ne confirme jamais un paiement');
    require_once $root . '/app/OrderService.php';
    $legacyId = (int) $db->query("SELECT id FROM users WHERE username='legacy_test'")->fetch_row()[0];
    $foreignOrder = (new OrderService($db))->createPending($legacyId, [['id' => 1, 'qty' => 1]], bin2hex(random_bytes(32)), ['name' => 'Autre Client']);
    $response = app_request('/app/paiement.php?order=' . $foreignOrder['reference']);
    check_app($response['status'] === 404 && !str_contains($response['body'], 'Autre Client') && !str_contains($response['body'], $foreignOrder['customer_email']), 'Commande d’un autre compte inaccessible et coordonnees non divulguees');
    $response = app_request('/app/dashboard.php');
    check_app(str_contains($response['body'], $persistedOrder['reference']) && !str_contains($response['body'], $foreignOrder['reference']), 'Historique du compte limite aux commandes du proprietaire');
    check_app(str_contains($response['body'], '9 840 FCFA') && !preg_match('/€|&euro;|\bEUR\b/u', $response['body']), 'Compte et historique de commande affichent seulement les montants FCFA');
    check_app((int) $db->query('SELECT COUNT(*) FROM orders')->fetch_row()[0] === 0 && (int) $db->query('SELECT stock FROM products WHERE id = 1')->fetch_row()[0] === 2, 'Anciennes commandes preservees et stock non debite avant reglement');
    $response = app_request('/app/logout.php');
    $token = app_token($response);
    check_app(str_contains(app_request('/app/dashboard.php')['url'], 'dashboard.php'), 'GET logout conserve la session');
    app_request('/app/logout.php', ['csrf_token' => $token]);
    $response = app_request('/app/login.php');
    $token = app_token($response);
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $response = app_request('/app/login.php', ['username' => 'throttle_probe', 'password' => 'invalid', 'csrf_token' => $token]);
    }
    $response = app_request('/app/login.php', ['username' => 'throttle_probe', 'password' => 'invalid', 'csrf_token' => $token]);
    check_app(str_contains($response['body'], 'Trop de tentatives') && !str_contains($response['url'], 'dashboard.php'),
        'Connexion ne limite pas les tentatives répétées');
    $response = app_request('/app/login.php');
    $token = app_token($response);
    $response = app_request('/app/login.php', ['username' => 'legacy_test', 'password' => 'LegacyPassword!2026', 'csrf_token' => $token]);
    check_app(str_contains($response['url'], 'dashboard.php'), 'Compatibilite anciens comptes demo');
    $db->query("UPDATE users SET active = 0 WHERE username = 'legacy_test'");
    check_app(str_contains(app_request('/app/dashboard.php')['url'], 'login.php'), 'Compte desactive perd son acces');
    $response = app_request('/security/ip-rules.php');
    check_app($response['status'] === 200 && str_contains($response['body'], 'Règles d’adresses IP'), 'Console IP accessible en local');
    $consoleToken = app_token($response);
    $response = app_request('/security/dashboard.php');
    check_app($response['status'] === 200 && str_contains($response['body'], 'Blocage SQLi') && str_contains($response['body'], 'JSONL / SIEM'),
        'Supervision ne présente pas clairement le mode actif et les exports');
    // Le parcours de commande ajoute des événements autorisés : cibler les alertes
    // évite qu'elles sortent de la première page du journal avant le contrôle de triage.
    $response = app_request('/security/dashboard.php?action=BLOCKED');
    check_app(str_contains($response['body'], 'CATALOGUE DE RÈGLES') && str_contains($response['body'], 'Questionner l’assistant sur cette alerte'),
        'Les alertes exposent la règle structurée et le contexte assistant');
    if (!preg_match('/name="request_id" value="([A-Za-z0-9_-]{1,128})"/', $response['body'], $triageMatch)) {
        throw new RuntimeException('Aucun événement révisable ne propose le formulaire de triage.');
    }
    $triagedRequestId = $triageMatch[1];
    $eventsBeforeTriage = array_map(static fn(string $line) => json_decode($line, true), file($directory . '/events.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    $eventBeforeTriage = null;
    foreach ($eventsBeforeTriage as $candidate) { if (is_array($candidate) && ($candidate['request_id'] ?? '') === $triagedRequestId) { $eventBeforeTriage = $candidate; break; } }
    if (!is_array($eventBeforeTriage)) { throw new RuntimeException('Événement choisi introuvable avant le triage.'); }
    check_app(app_request('/security/triage.php', ['csrf_token' => 'invalid', 'request_id' => $triagedRequestId,
        'status' => 'false_positive', 'note' => 'note test'])['status'] === 403, 'Triage refuse une mutation sans jeton CSRF');
    $response = app_request('/security/triage.php', ['csrf_token' => $consoleToken, 'request_id' => $triagedRequestId,
        'status' => 'false_positive', 'note' => 'password=triage-secret']);
    $triageFile = $directory . '/triage.jsonl';
    $triageRecords = is_file($triageFile) ? array_map(static fn(string $line) => json_decode($line, true), file($triageFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)) : [];
    $triageRecord = $triageRecords ? end($triageRecords) : null;
    check_app($response['status'] === 200 && str_contains($response['body'], 'Annotation enregistrée') && is_array($triageRecord) && ($triageRecord['status'] ?? '') === 'false_positive' &&
        !str_contains((string) ($triageRecord['note'] ?? ''), 'triage-secret') && !str_contains($response['body'], 'triage-secret'),
        'Triage CSRF-protégé enregistre une note expurgée');
    $triagedEvents = array_map(static fn(string $line) => json_decode($line, true), file($directory . '/events.jsonl', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
    $triagedEvent = null;
    foreach ($triagedEvents as $candidate) { if (is_array($candidate) && ($candidate['request_id'] ?? '') === $triagedRequestId) { $triagedEvent = $candidate; break; } }
    check_app(is_array($triagedEvent) && ($triagedEvent['action'] ?? '') === ($eventBeforeTriage['action'] ?? null),
        'Le triage ne réécrit pas la décision du journal de sécurité');
    $response = app_request('/security/dashboard.php?export=jsonl&action=BLOCKED');
    $jsonlEvents = array_values(array_filter(explode("\n", trim($response['body']))));
    $jsonlValid = $response['status'] === 200 && count($jsonlEvents) > 0;
    foreach ($jsonlEvents as $line) {
        $event = json_decode($line, true);
        $jsonlValid = $jsonlValid && is_array($event) && ($event['action'] ?? '') === 'BLOCKED';
    }
    check_app($jsonlValid, 'Export SIEM JSONL invalide ou sans application des filtres');
    check_app(app_request('/security/ip-rules.php', ['operation' => 'add', 'ip' => '203.0.113.44', 'csrf_token' => 'invalid'])['status'] === 403,
        'Mutation de règle IP sans CSRF refusée');
    $response = app_request('/security/ip-rules.php', ['operation' => 'add', 'ip' => '203.0.113.44', 'comment' => 'integration test', 'csrf_token' => $consoleToken]);
    check_app($response['status'] === 200 && str_contains($response['body'], '203.0.113.44'), 'Ajout IP affiché après redirection');
    $response = app_request('/security/ip-rules.php', ['operation' => 'remove', 'ip' => '203.0.113.44', 'csrf_token' => $consoleToken]);
    check_app($response['status'] === 200 && !str_contains($response['body'], '203.0.113.44'), 'Suppression IP protégée par CSRF');
    $legacyPasswordHash = password_hash('RetiredDemoPassword!2026', PASSWORD_DEFAULT);
    $legacyInsert = $db->prepare('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)');
    $legacyUser = 'cybershield_admin'; $legacyEmail = 'admin@cybershield.test'; $legacyRole = 'admin';
    $legacyInsert->bind_param('ssss', $legacyUser, $legacyPasswordHash, $legacyEmail, $legacyRole); $legacyInsert->execute();
    $legacyUser = 'cybershield_client'; $legacyEmail = 'client@cybershield.test'; $legacyRole = 'user';
    $legacyInsert->bind_param('ssss', $legacyUser, $legacyPasswordHash, $legacyEmail, $legacyRole); $legacyInsert->execute();
    $response = app_request('/app/login.php');
    $response = app_request('/app/login.php', ['username' => 'cybershield_admin', 'password' => 'RetiredDemoPassword!2026', 'csrf_token' => app_token($response)]);
    check_app(!str_contains($response['url'], 'dashboard.php'), 'Compte avec identifiants de démonstration refusé');
    $response = app_request('/app/setup.php');
    check_app($response['status'] === 200 && str_contains($response['body'], 'Première configuration'), 'Configuration initiale accessible en local');
    $setupToken = app_token($response);
    $response = app_request('/app/setup.php', ['username' => 'first_admin', 'email' => 'first-admin@test.invalid',
        'password' => 'StrongAdminPassword!2026', 'password_confirmation' => 'StrongAdminPassword!2026', 'csrf_token' => $setupToken]);
    check_app($response['status'] === 200 && str_contains($response['url'], 'mfa-enroll.php'), 'Création du premier administrateur impose MFA');
    if (!preg_match('/<code>([A-Z2-7]{32})<\/code>/', $response['body'], $secretMatch)) {
        throw new RuntimeException('Clé TOTP absente du parcours de configuration.');
    }
    require_once $root . '/app/AdminTotp.php';
    $adminMfaCode = AdminTotp::codeAt($secretMatch[1]);
    $response = app_request('/app/mfa-enroll.php', ['csrf_token' => app_token($response), 'totp_code' => $adminMfaCode]);
    check_app($response['status'] === 200 && str_contains($response['url'], 'dashboard.php'), 'Activation TOTP ouvre la session administrateur');
    $storedMfa = $db->query("SELECT encrypted_secret FROM admin_mfa WHERE user_id = (SELECT id FROM users WHERE username = 'first_admin')")->fetch_assoc();
    check_app(is_array($storedMfa) && str_starts_with($storedMfa['encrypted_secret'], 'v1.') && !str_contains($storedMfa['encrypted_secret'], $secretMatch[1]),
        'Secret TOTP chiffré au repos');
    check_app((int) $db->query("SELECT COUNT(*) FROM users WHERE username IN ('cybershield_admin','cybershield_client') AND active = 0")->fetch_row()[0] === 2,
        'Configuration initiale désactive les anciens comptes partagés');
    $response = app_request('/app/logout.php');
    app_request('/app/logout.php', ['csrf_token' => app_token($response)]);
    $response = app_request('/app/login.php');
    $response = app_request('/app/login.php', ['username' => 'first_admin', 'password' => 'StrongAdminPassword!2026',
        'totp_code' => AdminTotp::codeAt($secretMatch[1]), 'csrf_token' => app_token($response)]);
    check_app($response['status'] === 200 && str_contains($response['url'], 'dashboard.php'), 'Connexion administrateur vérifie le code TOTP');
    echo "$checks controles applicatifs reussis.\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'ECHEC : ' . $e->getMessage() . "\n");
    if (is_file($directory . '/server.log')) { fwrite(STDERR, file_get_contents($directory . '/server.log')); }
    $exitCode = 1;
} finally {
    if ($client !== null) { curl_close($client); }
    if (is_resource($server)) { proc_terminate($server); proc_close($server); }
    if ($ownedDatabase && preg_match('/^cybershield_test_[a-f0-9]{12}$/D', $database)) {
        $db->query('DROP DATABASE `' . $database . '`');
    }
    // Le dossier porte le meme identifiant aleatoire ; retrait des seuls fichiers crees pour ce test.
    foreach (glob($directory . '/*') ?: [] as $file) { if (is_file($file) && !is_link($file)) { unlink($file); } }
    $rateDirectory = $directory . DIRECTORY_SEPARATOR . 'rate';
    if (is_dir($rateDirectory)) {
        foreach (glob($rateDirectory . DIRECTORY_SEPARATOR . '*') ?: [] as $file) {
            if (is_file($file) && !is_link($file)) { unlink($file); }
        }
        rmdir($rateDirectory);
    }
    foreach (['.retention-last-run', '.retention.lock'] as $marker) {
        $file = $directory . DIRECTORY_SEPARATOR . $marker;
        if (is_file($file) && !is_link($file)) { unlink($file); }
    }
    rmdir($directory);
}
exit($exitCode);
