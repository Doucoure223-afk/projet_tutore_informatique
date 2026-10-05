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

$baseUrl = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/');
$logger = ApplicationConfig::getLogger('security');
$pdo = ApplicationConfig::getDatabase();
$dashboard = new SecurityDashboard($logger, $pdo, true);

echo $dashboard->renderReport($baseUrl, $period);
