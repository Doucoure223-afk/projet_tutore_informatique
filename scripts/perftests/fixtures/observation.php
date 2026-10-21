<?php
if (getenv('CYBERSHIELD_READINESS_DISPOSABLE') !== '1') { http_response_code(404); exit; }
$id = $_GET['id'] ?? '';
if (!is_string($id) || !preg_match('/^[a-f0-9]{32}$/D', $id)) { http_response_code(400); exit; }
require_once dirname(__DIR__) . '/security/logger.php';
$config = require dirname(__DIR__) . '/config/security.php';
$event = (new SecurityLogger($config['log_dir'] . '/events.jsonl'))->findEventByRequestId($id);
if (!$event) { http_response_code(404); exit; }
header('Content-Type: application/json');
header('Cache-Control: no-store');
// No payload, personal data, IP, route or arbitrary event properties.
echo json_encode(array_intersect_key($event, array_flip(['request_id', 'action', 'source', 'ai_status',
    'model_version', 'score', 'risk', 'mlp_calls', 'mlp_attempts', 'mlp_failures', 'latency_ms'])));
