<?php
require_once __DIR__ . '/../app/LocalSetupAccess.php';

function expectSetupAccess(bool $expected, array $server, string $label): void
{
    $actual = cybershield_local_setup_allowed($server, false);
    if ($actual !== $expected) {
        throw new RuntimeException('Failed setup access test: ' . $label);
    }
    echo 'OK ' . $label . PHP_EOL;
}

function expectDockerGatewayAccess(bool $expected, array $server, string $routeTable, string $label): void
{
    $actual = cybershield_local_request_allowed($server, false, $routeTable);
    if ($actual !== $expected) {
        throw new RuntimeException('Failed Docker gateway access test: ' . $label);
    }
    echo 'OK ' . $label . PHP_EOL;
}

putenv('CYBERSHIELD_CONTAINERIZED=1');
putenv('CYBERSHIELD_DOCKER_SETUP_PEER=172.19.0.1');
putenv('CYBERSHIELD_APP_BIND_ADDRESS=127.0.0.1');
expectSetupAccess(true, ['REMOTE_ADDR' => '127.0.0.1'], 'loopback remains allowed');
expectSetupAccess(true, ['REMOTE_ADDR' => '172.19.0.1'], 'configured Docker host forwarder is allowed');
expectSetupAccess(false, ['REMOTE_ADDR' => '172.19.0.2'], 'other container addresses remain denied');
$activeRoutes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth1 00000000 010014AC 0003 0 0 0 00000000 0 0 0";
expectDockerGatewayAccess(true, ['REMOTE_ADDR' => '172.20.0.1'], $activeRoutes, 'current Docker bridge gateway is detected after subnet changes');
if (cybershield_docker_default_gateway($activeRoutes) !== '172.20.0.1') {
    throw new RuntimeException('Failed Docker gateway parsing test');
}

putenv('CYBERSHIELD_CONTAINERIZED=0');
expectSetupAccess(false, ['REMOTE_ADDR' => '172.19.0.1'], 'Docker exception is disabled outside containers');

putenv('CYBERSHIELD_CONTAINERIZED=1');
putenv('CYBERSHIELD_APP_BIND_ADDRESS=0.0.0.0');
expectSetupAccess(false, ['REMOTE_ADDR' => '172.19.0.1'], 'Docker exception requires loopback host publishing');

putenv('CYBERSHIELD_APP_BIND_ADDRESS=127.0.0.1');
putenv('CYBERSHIELD_DOCKER_SETUP_PEER=172.19.0.0/24');
expectSetupAccess(false, ['REMOTE_ADDR' => '172.19.0.1'], 'trusted peer must be one IPv4 address');

// A valid envelope from Docker's host forwarder identifies a remote phone;
// it must never inherit the local setup/console exception of that forwarder.
$proxyVariables = ['CYBERSHIELD_LAN_PROXY_ENABLED', 'CYBERSHIELD_LAN_PROXY_PEERS',
    'CYBERSHIELD_LAN_PROXY_SECRET_FILE', 'CYBERSHIELD_CONTAINERIZED',
    'CYBERSHIELD_DOCKER_SETUP_PEER', 'CYBERSHIELD_APP_BIND_ADDRESS'];
$proxyPrevious = [];
foreach ($proxyVariables as $name) { $proxyPrevious[$name] = getenv($name); }
$proxyFixture = tempnam(sys_get_temp_dir(), 'cybershield-local-access-test-');
if (!is_string($proxyFixture)) { throw new RuntimeException('Cannot create isolated local access test fixture.'); }
$proxyTestKey = str_repeat('local-access-unit-test-', 3);
file_put_contents($proxyFixture, $proxyTestKey);
@chmod($proxyFixture, 0600);
try {
    putenv('CYBERSHIELD_LAN_PROXY_ENABLED=1');
    putenv('CYBERSHIELD_LAN_PROXY_PEERS=127.0.0.1,172.19.0.1');
    putenv('CYBERSHIELD_LAN_PROXY_SECRET_FILE=' . $proxyFixture);
    putenv('CYBERSHIELD_CONTAINERIZED=1');
    putenv('CYBERSHIELD_DOCKER_SETUP_PEER=172.19.0.1');
    putenv('CYBERSHIELD_APP_BIND_ADDRESS=127.0.0.1');
    $proxiedPhone = [
        'REMOTE_ADDR' => '172.19.0.1', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/app/setup.php',
        'HTTP_X_CYBERSHIELD_CLIENT_IP' => '192.168.1.45',
        'HTTP_X_CYBERSHIELD_TIMESTAMP' => (string) time(),
    ];
    $signLocalTest = static function (array $server) use ($proxyTestKey): array {
        $message = "v1\n" . $server['HTTP_X_CYBERSHIELD_CLIENT_IP'] . "\n" . $server['HTTP_X_CYBERSHIELD_TIMESTAMP'] . "\n" . $server['REQUEST_METHOD'] . "\n" . $server['REQUEST_URI'];
        $server['HTTP_X_CYBERSHIELD_SIGNATURE'] = hash_hmac('sha256', $message, $proxyTestKey);
        return $server;
    };
    $proxiedPhone = $signLocalTest($proxiedPhone);
    if (!cybershield_is_lan_proxy_request($proxiedPhone)) {
        throw new RuntimeException('Failed setup access test: phone fixture must carry a valid authenticated proxy envelope');
    }
    expectSetupAccess(false, $proxiedPhone, 'authenticated phone cannot inherit Docker gateway local access');
    $claimedLoopback = $proxiedPhone;
    $claimedLoopback['HTTP_X_CYBERSHIELD_CLIENT_IP'] = '127.0.0.1';
    expectSetupAccess(false, $signLocalTest($claimedLoopback), 'even a signed loopback identity from the relay cannot become local setup access');
    $invalidEnvelope = $proxiedPhone;
    $invalidEnvelope['HTTP_X_CYBERSHIELD_SIGNATURE'] = str_repeat('0', 64);
    expectSetupAccess(false, $invalidEnvelope, 'invalid proxy signature cannot fall back to Docker gateway local access');
    expectSetupAccess(false, ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_CYBERSHIELD_CLIENT_IP' => '192.168.1.45'],
        'partial proxy headers cannot fall back to loopback local access');
    putenv('CYBERSHIELD_LAN_PROXY_ENABLED=0');
    expectSetupAccess(false, $proxiedPhone, 'proxy envelope is denied if the relay feature is disabled');
    expectSetupAccess(true, ['REMOTE_ADDR' => '172.19.0.1'], 'ordinary Docker host traffic retains local access');
} finally {
    foreach ($proxyPrevious as $name => $value) { putenv($value === false ? $name : $name . '=' . $value); }
    if (is_file($proxyFixture)) { unlink($proxyFixture); }
}
