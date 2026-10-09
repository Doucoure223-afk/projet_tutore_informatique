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
