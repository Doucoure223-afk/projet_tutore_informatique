<?php
declare(strict_types=1);
require_once __DIR__ . '/../app/RequestTransport.php';
$tests = 0;
function transport_check(bool $condition, string $name): void {
    global $tests; $tests++; if (!$condition) { throw new RuntimeException($name); }
}
putenv('CYBERSHIELD_HTTPS_PROXY_PEERS'); putenv('CYBERSHIELD_REQUIRE_HTTPS');
$plain = ['REMOTE_ADDR' => '127.0.0.1'];
transport_check(!RequestTransport::isHttps($plain), 'HTTP local preserved');
transport_check(!RequestTransport::isHttps($plain + ['HTTP_X_FORWARDED_PROTO' => 'https']), 'Forwarded header ignored by default');
foreach (['on', 'ON', '1'] as $value) { transport_check(RequestTransport::isHttps(['HTTPS' => $value]), 'HTTPS server flag'); }
foreach (['off', 'false', 'https', '0'] as $value) { transport_check(!RequestTransport::isHttps(['HTTPS' => $value]), 'Only explicit server flags'); }
putenv('CYBERSHIELD_HTTPS_PROXY_PEERS=172.30.240.2,::1');
transport_check(RequestTransport::isHttps(['REMOTE_ADDR' => '172.30.240.2', 'HTTP_X_FORWARDED_PROTO' => 'https']), 'Exact trusted IPv4');
transport_check(RequestTransport::isHttps(['REMOTE_ADDR' => '::1', 'HTTP_X_FORWARDED_PROTO' => 'https']), 'Exact trusted IPv6');
transport_check(!RequestTransport::isHttps(['REMOTE_ADDR' => '172.30.240.3', 'HTTP_X_FORWARDED_PROTO' => 'https']), 'Adjacent address not trusted');
foreach (['https,http', 'https, https', 'HTTPS', ' https', "https\r\n"] as $value) {
    transport_check(!RequestTransport::isHttps(['REMOTE_ADDR' => '172.30.240.2', 'HTTP_X_FORWARDED_PROTO' => $value]), 'Ambiguous proxy value rejected');
}
putenv('CYBERSHIELD_HTTPS_PROXY_PEERS=172.30.240.0/24,docker-gateway,*');
transport_check(!RequestTransport::isHttps(['REMOTE_ADDR' => '172.30.240.2', 'HTTP_X_FORWARDED_PROTO' => 'https']), 'Networks and wildcard not accepted');
transport_check(RequestTransport::requireSecureTransport($plain), 'Demo HTTP default');
putenv('CYBERSHIELD_REQUIRE_HTTPS=1');
transport_check(!RequestTransport::requireSecureTransport($plain), 'Production HTTP refused');
transport_check(RequestTransport::requireSecureTransport(['HTTPS' => 'on']), 'HTTPS accepted');
transport_check(RequestTransport::requireSecureTransport(['SCRIPT_NAME' => '/app/health.php']), 'Sessionless health check');
transport_check(RequestTransport::cookieOptions(['HTTPS' => 'on'])['secure'] === true, 'HTTPS cookie secure');
transport_check(RequestTransport::cookieOptions($plain)['secure'] === false, 'Demo cookie works on HTTP');
transport_check(RequestTransport::cookieOptions($plain)['httponly'] === true && RequestTransport::cookieOptions($plain)['samesite'] === 'Lax', 'HttpOnly SameSite');
putenv('CYBERSHIELD_REQUIRE_HTTPS'); putenv('CYBERSHIELD_HTTPS_PROXY_PEERS');
echo "$tests transport checks passed.\n";
