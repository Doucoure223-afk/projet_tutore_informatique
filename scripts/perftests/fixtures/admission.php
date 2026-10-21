<?php
if (getenv('CYBERSHIELD_READINESS_DISPOSABLE') !== '1') { http_response_code(404); exit; }
require_once dirname(__DIR__) . '/security/middleware.php';
$config = require dirname(__DIR__) . '/config/security.php';
// An independent state directory permits a fresh 100/60-second admission test
// without resetting or manipulating the application's actual request counters.
$config['log_dir'] = sys_get_temp_dir() . '/cybershield-readiness-admission';
$allowed = cybershield_rate_allowed($config, $_SERVER['REMOTE_ADDR'] ?? 'unknown');
http_response_code($allowed ? 200 : 429);
header('Content-Type: application/json');
header('Cache-Control: no-store');
if (!$allowed) { header('Retry-After: 60'); }
echo json_encode(['allowed' => $allowed, 'limit' => $config['rate_limiting']['max_requests'],
    'window_seconds' => $config['rate_limiting']['window_seconds'], 'kind' => 'isolated_actual_php_admission']);
