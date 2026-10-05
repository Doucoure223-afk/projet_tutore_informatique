<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off',
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
}
if (!empty($_SESSION['last_activity']) && time() - (int) $_SESSION['last_activity'] > 1800) {
    $_SESSION = [];
    session_regenerate_id(true);
}
if (empty($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
}
$_SESSION['last_activity'] = time();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if (!defined('CYBERSHIELD_SKIP_REQUEST')) {
    require_once __DIR__ . '/../security/middleware.php';
    cybershield_protect();
}

require_once __DIR__ . '/SecureDataGateway.php';
if (!extension_loaded('mysqli')) {
    http_response_code(503);
    exit('Extension mysqli absente. Utilisez le PHP de Wamp.');
}
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
try {
    $conn = new mysqli(
        getenv('DB_HOST') ?: 'localhost',
        getenv('DB_USER') ?: 'root',
        getenv('DB_PASSWORD') ?: '',
        getenv('DB_NAME') ?: 'projet_sqli_vulnerable',
        (int) (getenv('DB_PORT') ?: 3306)
    );
    $conn->set_charset('utf8mb4');
    $conn_logs = $conn;
    $gateway = new SecureDataGateway($conn);
} catch (mysqli_sql_exception $e) {
    error_log('CyberShield: connexion à la base indisponible (code ' . $e->getCode() . ').');
    http_response_code(503);
    exit('Base de démonstration indisponible. Vérifiez MySQL et importez database/schema.sql puis database/seed_products.sql.');
}

function getDatabaseConnection(): mysqli { global $conn; return $conn; }
function getLogsDatabaseConnection(): mysqli { global $conn_logs; return $conn_logs; }
function getDataGateway(): SecureDataGateway { global $gateway; return $gateway; }

function escape_output($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function input_text(array $source, string $key, string $default = ''): string {
    return isset($source[$key]) && is_string($source[$key]) ? $source[$key] : $default;
}

function validate_csrf_token(): void {
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST' &&
        !hash_equals($_SESSION['csrf_token'], input_text($_POST, 'csrf_token'))) {
        http_response_code(403);
        exit('Formulaire expiré ou invalide. Rechargez la page avant de réessayer.');
    }
}

function execute_query_secure(string $sql, array $params = []) {
    try {
        return getDataGateway()->execute($sql, $params);
    } catch (mysqli_sql_exception $e) {
        error_log('CyberShield: opération de base refusée (code ' . $e->getCode() . ').');
        return false;
    }
}

function log_user_action(int $userId, string $action): void {
    execute_query_secure('INSERT INTO user_logs (user_id, action, ip_address) VALUES (?, ?, ?)',
        [$userId, $action, $_SERVER['REMOTE_ADDR'] ?? '']);
}

function current_user(): ?array {
    if (empty($_SESSION['logged_in']) || empty($_SESSION['user_id'])) { return null; }
    $result = execute_query_secure('SELECT id, username, email, role, created_at FROM users WHERE id = ? AND active = 1',
        [(int) $_SESSION['user_id']]);
    return $result ? ($result->fetch_assoc() ?: null) : null;
}

if (!defined('APP_ENV')) { define('APP_ENV', getenv('APP_ENV') ?: 'development'); }
if (!defined('SESSION_TIMEOUT')) { define('SESSION_TIMEOUT', 1800); }
function is_development(): bool { return APP_ENV === 'development'; }
