<?php
require_once __DIR__ . '/assistant-client.php';

console_require_access();
header('Content-Type: application/json; charset=utf-8');
header('X-Frame-Options: DENY');
header('Cross-Origin-Resource-Policy: same-origin');

$respond = static function (int $status, array $body): never {
    http_response_code($status);
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
};

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    header('Allow: POST');
    $respond(405, ['ok' => false, 'error' => 'Cette route accepte uniquement les questions envoyées en POST.']);
}
if (strtolower(trim(explode(';', (string) ($_SERVER['CONTENT_TYPE'] ?? ''))[0])) !== 'application/x-www-form-urlencoded') {
    $respond(415, ['ok' => false, 'error' => 'Format de formulaire non accepté.']);
}
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 16_384) {
    $respond(413, ['ok' => false, 'error' => 'La demande est trop volumineuse.']);
}
$csrf = $_POST['csrf_token'] ?? '';
if (!is_string($csrf) || !hash_equals(console_csrf(), $csrf)) {
    $respond(403, ['ok' => false, 'error' => 'La page a expiré. Recharge-la avant de réessayer.']);
}
$page = $_POST['page'] ?? 'console';
$page = is_string($page) ? $page : 'console';
$eventId = $_POST['event_id'] ?? '';
if (!is_string($eventId) || strlen($eventId) > 128 || ($eventId !== '' && preg_match('/^[a-zA-Z0-9_-]+$/D', $eventId) !== 1)) {
    $respond(400, ['ok' => false, 'error' => 'Référence d’alerte invalide.']);
}
$result = cybershield_assistant_ask($_POST['question'] ?? null, $page, $eventId !== '' ? $eventId : null);
if (empty($result['ok'])) {
    $respond((int) ($result['status'] ?? 503), ['ok' => false, 'error' => (string) ($result['error'] ?? 'Assistant indisponible.')]);
}
$respond(200, ['ok' => true, 'answer' => (string) $result['answer'],
    'source' => $result['source'], 'kind' => $result['kind'], 'elapsed_ms' => $result['elapsed_ms']]);
