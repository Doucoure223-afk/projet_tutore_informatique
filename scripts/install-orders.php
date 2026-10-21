<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require_once dirname(__DIR__) . '/app/DatabasePassword.php';
try {
    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
    $connection = new mysqli(getenv('DB_HOST') ?: 'localhost', getenv('DB_USER') ?: 'root', cybershield_database_password(),
        getenv('DB_NAME') ?: 'projet_sqli_vulnerable', (int) (getenv('DB_PORT') ?: 3306));
    $connection->set_charset('utf8mb4');
    $connection->multi_query(file_get_contents(dirname(__DIR__) . '/database/orders.sql'));
    do {
        if ($result = $connection->store_result()) { $result->free(); }
        if (!$connection->more_results()) { break; }
    } while ($connection->next_result());
    echo "Tables de commandes installées. Données et privilèges existants conservés.\n";
} catch (Throwable $exception) {
    fwrite(STDERR, 'Installation des commandes impossible (code ' . (int) $exception->getCode() . "). Utiliser un compte de migration autorisé.\n");
    exit(1);
}
