<?php
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/access.php';

console_require_access();
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    header('Location: dashboard.php#incidents', true, 303);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Méthode non autorisée.');
}
console_check_csrf();
$requestId = $_POST['request_id'] ?? '';
$status = $_POST['status'] ?? '';
$note = $_POST['note'] ?? '';
if (!is_string($requestId) || !is_string($status) || !is_string($note) || strlen($requestId) > 128 || strlen($note) > 4000) {
    http_response_code(400);
    exit('Données de triage invalides.');
}
try {
    $actorId = isset($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null;
    console_logger()->updateTriage($requestId, $status, $note, $actorId);
    header('Location: dashboard.php?triage=updated#incidents', true, 303);
} catch (InvalidArgumentException $error) {
    http_response_code(400);
    exit('La référence ou l’état de triage est invalide.');
} catch (Throwable $error) {
    error_log('CyberShield triage unavailable; the security decision remains unchanged.');
    http_response_code(503);
    exit('Le journal de triage est indisponible. La décision initiale n’a pas été modifiée.');
}
