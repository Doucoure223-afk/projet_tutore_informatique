<?php
require_once '/var/www/html/app/DatabasePassword.php';
try {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $database = new mysqli(getenv('DB_HOST') ?: 'db', getenv('DB_USER') ?: '', cybershield_database_password(),
        getenv('DB_NAME') ?: 'projet_sqli_vulnerable', (int) (getenv('DB_PORT') ?: 3306));
    $database->query('SELECT 1');
    $database->close();
} catch (Throwable $error) {
    exit(1);
}

$client = curl_init('http://127.0.0.1/index.php');
curl_setopt_array($client, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_CONNECTTIMEOUT_MS => 1000,
    CURLOPT_TIMEOUT_MS => 2500,
]);
$body = curl_exec($client);
$status = curl_getinfo($client, CURLINFO_RESPONSE_CODE);
curl_close($client);
exit($body !== false && $status === 200 ? 0 : 1);
