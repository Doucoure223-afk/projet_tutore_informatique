<?php
require_once __DIR__ . '/../security/client_identity.php';

$checks = 0;
function expectClientIdentity(bool $condition, string $label): void
{
    global $checks;
    if (!$condition) { throw new RuntimeException('Failed client identity test: ' . $label); }
    $checks++;
    echo 'OK ' . $label . PHP_EOL;
}
function rejectClientIdentity(array $server, string $label): void
{
    try { cybershield_client_identity($server); }
    catch (CybershieldClientIdentityException $error) { expectClientIdentity(true, $label); return; }
    throw new RuntimeException('Failed client identity rejection test: ' . $label);
}
function signedClientRequest(string $key, array $changes = []): array
{
    $server = array_merge([
        'REMOTE_ADDR' => '127.0.0.1', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/app/search.php?q=casque%20audio',
        'HTTP_X_CYBERSHIELD_CLIENT_IP' => '192.168.1.45', 'HTTP_X_CYBERSHIELD_TIMESTAMP' => (string) time(),
    ], $changes);
    $signed = "v1\n" . $server['HTTP_X_CYBERSHIELD_CLIENT_IP'] . "\n" . $server['HTTP_X_CYBERSHIELD_TIMESTAMP'] . "\n" . $server['REQUEST_METHOD'] . "\n" . $server['REQUEST_URI'];
    $server['HTTP_X_CYBERSHIELD_SIGNATURE'] = hash_hmac('sha256', $signed, $key);
    return $server;
}

$envNames = ['CYBERSHIELD_LAN_PROXY_ENABLED', 'CYBERSHIELD_LAN_PROXY_PEERS', 'CYBERSHIELD_LAN_PROXY_SECRET_FILE'];
$previous = [];
foreach ($envNames as $name) { $previous[$name] = getenv($name); }
$fixture = tempnam(sys_get_temp_dir(), 'cybershield-identity-test-');
if (!is_string($fixture)) { throw new RuntimeException('Cannot create isolated identity test fixture.'); }
$key = str_repeat('unit-test-key-', 4);
file_put_contents($fixture, $key . "\n");
@chmod($fixture, 0600);
try {
    putenv('CYBERSHIELD_LAN_PROXY_ENABLED=1');
    putenv('CYBERSHIELD_LAN_PROXY_PEERS=127.0.0.1,::1,172.20.0.1');
    putenv('CYBERSHIELD_LAN_PROXY_SECRET_FILE=' . $fixture);

    $direct = ['REMOTE_ADDR' => '192.168.1.72', 'HTTP_X_FORWARDED_FOR' => '127.0.0.1', 'HTTP_FORWARDED' => 'for=127.0.0.1'];
    $identity = cybershield_client_identity($direct);
    expectClientIdentity($identity['ip'] === '192.168.1.72' && !$identity['authenticated_proxy'], 'untrusted forwarding headers do not replace the direct client');
    expectClientIdentity(cybershield_client_ip(['REMOTE_ADDR' => '::ffff:192.168.1.72']) === '192.168.1.72', 'IPv4 mapped peer addresses normalize to IPv4');
    expectClientIdentity(cybershield_client_ip(['REMOTE_ADDR' => '2001:0DB8:0:0::1']) === '2001:db8::1', 'IPv6 peer addresses normalize consistently');

    $signed = signedClientRequest($key);
    $identity = cybershield_client_identity($signed);
    expectClientIdentity($identity === ['ip' => '192.168.1.45', 'peer_ip' => '127.0.0.1', 'authenticated_proxy' => true], 'a valid HMAC establishes the actual phone address');
    expectClientIdentity(cybershield_is_lan_proxy_request($signed), 'local access can distinguish authenticated proxy traffic');
    $ipv6 = signedClientRequest($key, ['HTTP_X_CYBERSHIELD_CLIENT_IP' => '2001:db8::45', 'REMOTE_ADDR' => '::1']);
    expectClientIdentity(cybershield_client_ip($ipv6) === '2001:db8::45', 'IPv6 phone address is accepted with a valid signature');
    expectClientIdentity(cybershield_client_ip(signedClientRequest($key, ['REMOTE_ADDR' => '172.20.0.1'])) === '192.168.1.45', 'the configured exact Docker gateway can relay requests');

    $forged = $signed; $forged['HTTP_X_CYBERSHIELD_CLIENT_IP'] = '192.168.1.90';
    rejectClientIdentity($forged, 'changing the client address invalidates its signature');
    $forged = $signed; $forged['REQUEST_METHOD'] = 'POST';
    rejectClientIdentity($forged, 'changing the request method invalidates its signature');
    $forged = $signed; $forged['REQUEST_URI'] = '/security/dashboard.php';
    rejectClientIdentity($forged, 'a signature cannot be reused for a different route');
    $forged = $signed; $forged['REQUEST_URI'] = '/app/search.php?q=casque+audio';
    rejectClientIdentity($forged, 'the raw request URI is bound without URL decoding');
    rejectClientIdentity(signedClientRequest($key, ['REMOTE_ADDR' => '172.20.0.2']), 'another address in the same private subnet is not a trusted relay');
    rejectClientIdentity(signedClientRequest($key, ['HTTP_X_CYBERSHIELD_TIMESTAMP' => (string) (time() - 60)]), 'expired signatures fail closed');
    rejectClientIdentity(signedClientRequest($key, ['HTTP_X_CYBERSHIELD_TIMESTAMP' => (string) (time() + 60)]), 'future signatures outside the tolerance fail closed');
    rejectClientIdentity(signedClientRequest($key, ['HTTP_X_CYBERSHIELD_TIMESTAMP' => '0' . time()]), 'noncanonical timestamps are rejected');
    rejectClientIdentity(signedClientRequest($key, ['HTTP_X_CYBERSHIELD_CLIENT_IP' => '2001:0DB8:0:0::45']), 'forwarded IP must use the canonical representation');
    rejectClientIdentity(signedClientRequest($key, ['HTTP_X_CYBERSHIELD_CLIENT_IP' => "192.168.1.45\r\nX: value"]), 'header injection cannot become a client address');
    rejectClientIdentity(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_CYBERSHIELD_SIGNATURE' => str_repeat('a', 64)], 'partial reserved headers are rejected instead of falling back to loopback');
    $forged = $signed; $forged['HTTP_X_CYBERSHIELD_SIGNATURE'] = [$signed['HTTP_X_CYBERSHIELD_SIGNATURE']];
    rejectClientIdentity($forged, 'non-string signature values fail closed');
    $forged = $signed; $forged['HTTP_X_CYBERSHIELD_SIGNATURE'] = str_repeat('0', 64);
    rejectClientIdentity($forged, 'an arbitrary signature is rejected');
    rejectClientIdentity(signedClientRequest($key, ['REQUEST_URI' => '/app/search.php?q=unsafe value']), 'an invalid raw URI cannot be signed');
    rejectClientIdentity(['REMOTE_ADDR' => 'not-an-ip'], 'invalid network peers are rejected');

    putenv('CYBERSHIELD_LAN_PROXY_ENABLED=0');
    rejectClientIdentity($signed, 'reserved proxy headers fail closed when the proxy feature is disabled');
    expectClientIdentity(cybershield_client_ip($direct) === '192.168.1.72', 'ordinary requests still work while the feature is disabled');
    putenv('CYBERSHIELD_LAN_PROXY_ENABLED=1');
    putenv('CYBERSHIELD_LAN_PROXY_SECRET_FILE=' . $fixture . '.missing');
    rejectClientIdentity($signed, 'a missing secret never grants fallback local access');
    putenv('CYBERSHIELD_LAN_PROXY_SECRET_FILE=' . $fixture);
    file_put_contents($fixture, 'too-short');
    rejectClientIdentity($signed, 'a short secret is refused');

    $routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00000000 010014AC 0003 0 0 0 00000000 0 0 0\neth0 000014AC 00000000 0001 0 0 0 0000FFFF 0 0 0\n";
    expectClientIdentity(cybershield_lan_proxy_gateway($routes) === '172.20.0.1', 'the active Linux default gateway is decoded correctly');
    expectClientIdentity(cybershield_lan_proxy_gateway("Iface Destination Gateway Flags\neth0 00000000 010014AC 0001") === null, 'routes without a gateway flag cannot establish relay trust');
    putenv('CYBERSHIELD_LAN_PROXY_PEERS=172.20.0.0/24');
    expectClientIdentity(!cybershield_lan_proxy_peer_allowed('172.20.0.1'), 'CIDR subnets are never accepted as trusted peers');
    echo $checks . ' client identity checks passed.' . PHP_EOL;
} finally {
    foreach ($previous as $name => $value) { putenv($value === false ? $name : $name . '=' . $value); }
    if (is_file($fixture)) { unlink($fixture); }
}
