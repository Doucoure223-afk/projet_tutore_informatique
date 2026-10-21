<?php
declare(strict_types=1);
require_once __DIR__ . '/../app/RequestTransport.php';

function cybershield_require_secure_transport(): void
{
    if (PHP_SAPI !== 'cli' && !RequestTransport::requireSecureTransport()) {
        http_response_code(426);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        exit('Une connexion HTTPS est requise pour cette installation.');
    }
}
