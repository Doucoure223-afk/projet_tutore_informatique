<?php
/**
 * Application entry point for the CyberShield request filter.
 * Include it before application output. Define CYBERSHIELD_SKIP_REQUEST
 * before inclusion only for routes intentionally outside request inspection.
 */
require_once __DIR__ . '/middleware.php';

if (!defined('CYBERSHIELD_SKIP_REQUEST') && !defined('CYBERSHIELD_MIDDLEWARE_RAN')) {
    define('CYBERSHIELD_MIDDLEWARE_RAN', true);
    cybershield_protect();
}
