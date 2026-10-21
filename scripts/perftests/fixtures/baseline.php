<?php
// Bind only into a disposable acceptance deployment, never into a live image.
if (getenv('CYBERSHIELD_READINESS_DISPOSABLE') !== '1') { http_response_code(404); exit; }
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo json_encode(['kind' => 'baseline', 'database_called' => false]);
