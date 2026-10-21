<?php
if (getenv('CYBERSHIELD_READINESS_DISPOSABLE') !== '1') { http_response_code(404); exit; }
require_once dirname(__DIR__) . '/security/middleware.php';
cybershield_protect();
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo json_encode(['kind' => 'protected', 'database_called' => false]);
