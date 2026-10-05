<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (empty($_SESSION['authenticated']) || empty($_SESSION['user_id'])) {
    $baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
    header('Location: ' . $baseUrl . '/login.php', true, 303);
    exit;
}

require_once __DIR__ . '/../vendor/autoload.php';

use App\Infrastructure\ApplicationConfig;
use App\Security\Dashboard\SecurityDashboard;

ApplicationConfig::initialize(__DIR__ . '/..');

$period = isset($_GET['period']) ? (int) $_GET['period'] : 7;
if (!in_array($period, [1, 7, 30], true)) {
    $period = 7;
}

$logger = ApplicationConfig::getLogger('security');
$pdo = ApplicationConfig::getDatabase();
$dashboard = new SecurityDashboard($logger, $pdo, true);

$csv = $dashboard->getCsvContent($period);
$suffix = $period === 1 ? '24h' : ($period === 7 ? '7j' : '30j');
$filename = 'incidents_securite_' . $suffix . '_' . date('Y-m-d_His') . '.csv';

header('Content-Type: text/csv; charset=UTF-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

echo $csv;
exit;
