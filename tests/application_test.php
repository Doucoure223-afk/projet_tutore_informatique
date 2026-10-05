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
    $db->query('UPDATE products SET price = 7.50, stock = 2 WHERE id = 1');
    import_app_sql($db, $schema);
    import_app_sql($db, $seed);
    check_app((int) $db->query('SELECT COUNT(*) FROM products')->fetch_row()[0] === 8, 'Double import sans doublons');
    check_app((float) $db->query('SELECT price FROM products WHERE id = 1')->fetch_row()[0] === 7.5, 'Seed preserve les produits existants');
    check_app((int) $db->query('SELECT COUNT(*) FROM users')->fetch_row()[0] === 2, 'Comptes de demonstration idempotents');
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
    $token = app_token($response);
    $pathPayload = rawurlencode("' OR '1'='1 --");
    check_app(app_request('/app/search.php/' . $pathPayload)['status'] === 403, 'Injection SQLi dans le chemin URL bloquee');
    check_app(app_request('/app/search.php/' . str_repeat('a', 8193))['status'] === 413, 'Chemin URL trop long refuse');
    check_app(app_request('/app/panier.php', ['action' => 'add', 'product_id' => '1'])['status'] === 403, 'Ajout sans CSRF refuse');
    $response = app_request('/app/panier.php?add=1&validated=1');
    check_app(str_contains($response['body'], 'Votre panier est vide') && !str_contains($response['body'], 'Simulation terminée'), 'GET ne modifie pas le panier ni le recu');
    for ($i = 0; $i < 3; $i++) { app_request('/app/panier.php', ['action' => 'add', 'product_id' => '1', 'csrf_token' => $token]); }
    $response = app_request('/app/panier.php');
    check_app(str_contains($response['body'], '× 2') && str_contains($response['body'], '15,00'), 'Stock limite a deux et total correct');
    $response = app_request('/app/login.php', ['username' => "' OR 1=1 -- ", 'password' => 'anything', 'csrf_token' => $token]);
    check_app(in_array($response['status'], [200, 403], true) && !str_contains($response['url'], 'dashboard.php'), 'Injection login ne connecte pas');
    $response = app_request('/app/inscription.php', ['username' => 'registered_test', 'password' => 'NewPassword!2026', 'mail' => 'new@test.invalid', 'role' => 'admin', 'csrf_token' => $token]);
    $registered = $db->query("SELECT password, role FROM users WHERE username = 'registered_test'")->fetch_assoc();
    check_app($registered !== null && $registered['role'] === 'user' && password_verify('NewPassword!2026', $registered['password']), 'Inscription hache le mot de passe et refuse auto-admin');
    $response = app_request('/app/login.php', ['username' => 'registered_test', 'password' => 'NewPassword!2026', 'csrf_token' => $token]);
    check_app(str_contains($response['url'], 'dashboard.php'), 'Connexion avec mot de passe hache');
    check_app(app_request('/app/dashboard.php?admin_search=test')['status'] === 403, 'Recherche admin refusee au client');
    $response = app_request('/app/paiement.php');
    $token = app_token($response);
    check_app(str_contains($response['body'], '15,00') && !str_contains($response['body'], 'name="card"'), 'Simulation affiche total et ne collecte aucune carte');
    check_app(app_request('/app/paiement.php', ['pay' => '1'])['status'] === 403, 'Simulation sans CSRF refusee');
    check_app(app_request('/app/paiement.php', ['validate_without_pay' => '1', 'csrf_token' => $token])['status'] === 403, 'Privilege de simulation admin controle cote serveur');
    $response = app_request('/app/paiement.php', ['pay' => '1', 'csrf_token' => $token]);
    check_app(str_contains($response['body'], 'Simulation terminée') && str_contains($response['body'], 'DEMO-'), 'Recu authentique apres simulation');
    check_app(!str_contains(app_request('/app/panier.php?validated=1')['body'], 'Simulation terminée'), 'Recu a usage unique');
    check_app((int) $db->query('SELECT COUNT(*) FROM orders')->fetch_row()[0] === 0 && (int) $db->query('SELECT stock FROM products WHERE id = 1')->fetch_row()[0] === 2, 'Simulation sans commande reelle ni modification stock');
    $response = app_request('/app/logout.php');
    $token = app_token($response);
    check_app(str_contains(app_request('/app/dashboard.php')['url'], 'dashboard.php'), 'GET logout conserve la session');
    app_request('/app/logout.php', ['csrf_token' => $token]);
    $response = app_request('/app/login.php');
    $token = app_token($response);
    $response = app_request('/app/login.php', ['username' => 'legacy_test', 'password' => 'LegacyPassword!2026', 'csrf_token' => $token]);
    check_app(str_contains($response['url'], 'dashboard.php'), 'Compatibilite anciens comptes demo');
    $db->query("UPDATE users SET active = 0 WHERE username = 'legacy_test'");
    check_app(str_contains(app_request('/app/dashboard.php')['url'], 'login.php'), 'Compte desactive perd son acces');
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
