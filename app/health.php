<?php
// Internal Apache/PHP liveness only. Database health is checked by the CLI
// healthcheck; this route must not generate visitor or security events.
if (($_SERVER['REMOTE_ADDR'] ?? '') !== '127.0.0.1'
    || isset($_SERVER['HTTP_X_CYBERSHIELD_CLIENT_IP'])
    || isset($_SERVER['HTTP_X_CYBERSHIELD_TIMESTAMP'])
    || isset($_SERVER['HTTP_X_CYBERSHIELD_SIGNATURE'])) {
    http_response_code(404);
    exit;
}
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
echo '{"status":"ok"}';
