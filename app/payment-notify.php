<?php
declare(strict_types=1);

require_once __DIR__ . '/CinetPayNotification.php';
require_once __DIR__ . '/RequestTransport.php';
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'GET') { echo '{"status":"ok"}'; exit; }
if ($method !== 'POST') { header('Allow: GET, POST'); http_response_code(405); echo '{"error":"method"}'; exit; }
$payments = CinetPay::fromEnvironment();
if (!$payments->isReady()) { http_response_code(503); echo '{"error":"payment_integration_not_active"}'; exit; }
if (!RequestTransport::isHttps($_SERVER)) { http_response_code(403); echo '{"error":"https_required"}'; exit; }
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 65536 || count($_POST) > 32) {
    http_response_code(413); echo '{"error":"body_too_large"}'; exit;
}
$contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
if ($contentType !== 'application/x-www-form-urlencoded') { http_response_code(415); echo '{"error":"content_type"}'; exit; }
try {
    CinetPayNotification::process($payments, $_POST, (string) ($_SERVER['HTTP_X_TOKEN'] ?? ''), static function (string $reference, array $verified): void {
        require_once __DIR__ . '/DatabasePassword.php';
        require_once __DIR__ . '/OrderService.php';
        mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
        $connection = new mysqli(getenv('DB_HOST') ?: 'localhost', getenv('DB_USER') ?: 'root',
            cybershield_database_password(), getenv('DB_NAME') ?: 'projet_sqli_vulnerable', (int) (getenv('DB_PORT') ?: 3306));
        try {
            $connection->set_charset('utf8mb4');
            (new OrderService($connection))->reconcilePayment($reference, $verified);
        } finally { $connection->close(); }
    });
    echo '{"accepted":true}';
} catch (UnexpectedValueException $error) {
    http_response_code(401); echo '{"error":"verification_rejected"}';
} catch (OutOfBoundsException $error) {
    http_response_code(404); echo '{"error":"unknown_order"}';
} catch (Throwable $error) {
    error_log('CyberShield : notification de paiement non traitée, une nouvelle tentative est nécessaire.');
    http_response_code(503); echo '{"error":"verification_unavailable"}';
}
