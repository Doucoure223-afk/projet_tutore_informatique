<?php
/**
 * Authenticate the address forwarded by the optional local LAN proxy.
 * Ordinary Forwarded/X-Forwarded-For headers never establish a client identity.
 */
class CybershieldClientIdentityException extends RuntimeException {}

function cybershield_canonical_client_ip(string $value): ?string
{
    if (filter_var($value, FILTER_VALIDATE_IP) === false) { return null; }
    $packed = @inet_pton($value);
    if (!is_string($packed)) { return null; }
    if (strlen($packed) === 16 && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
        $packed = substr($packed, 12);
    }
    $canonical = @inet_ntop($packed);
    return is_string($canonical) ? strtolower($canonical) : null;
}

/** Only the exact active gateway is eligible; a private subnet is never trusted. */
function cybershield_lan_proxy_gateway(?string $routeTable = null): ?string
{
    $routeTable ??= @file_get_contents('/proc/net/route');
    if (!is_string($routeTable) || strlen($routeTable) > 65536) { return null; }
    foreach (array_slice(preg_split('/\r?\n/', $routeTable) ?: [], 1) as $line) {
        $columns = preg_split('/\s+/', trim($line));
        if (!is_array($columns) || count($columns) < 4 || $columns[1] !== '00000000'
            || !preg_match('/^[a-f0-9]{8}$/i', $columns[2]) || !ctype_xdigit($columns[3])
            || (hexdec($columns[3]) & 3) !== 3) { continue; }
        $gateway = implode('.', array_map(static fn(string $octet): string => (string) hexdec($octet), array_reverse(str_split($columns[2], 2))));
        if ($gateway !== '0.0.0.0' && cybershield_canonical_client_ip($gateway) !== null) { return $gateway; }
    }
    return null;
}

function cybershield_lan_proxy_peer_allowed(string $peer): bool
{
    $configured = getenv('CYBERSHIELD_LAN_PROXY_PEERS');
    $configured = is_string($configured) && $configured !== '' ? $configured : '127.0.0.1,::1';
    foreach (explode(',', $configured) as $candidate) {
        $candidate = trim($candidate);
        $canonical = $candidate === 'docker-gateway'
            ? cybershield_lan_proxy_gateway() : cybershield_canonical_client_ip($candidate);
        if ($canonical !== null && hash_equals($canonical, $peer)) { return true; }
    }
    return false;
}

/** @return array{ip:string,peer_ip:string,authenticated_proxy:bool} */
function cybershield_client_identity(?array $server = null): array
{
    static $requestIdentity = null;
    $useRequestCache = $server === null;
    if ($useRequestCache && is_array($requestIdentity)) { return $requestIdentity; }
    $server ??= $_SERVER;
    $rawPeer = $server['REMOTE_ADDR'] ?? '';
    $peer = is_string($rawPeer) ? cybershield_canonical_client_ip($rawPeer) : null;
    if ($peer === null) { throw new CybershieldClientIdentityException('Adresse réseau du client invalide.'); }

    $headers = ['HTTP_X_CYBERSHIELD_CLIENT_IP', 'HTTP_X_CYBERSHIELD_TIMESTAMP', 'HTTP_X_CYBERSHIELD_SIGNATURE'];
    $hasProxyHeader = false;
    foreach ($headers as $header) { $hasProxyHeader = $hasProxyHeader || array_key_exists($header, $server); }
    if (!$hasProxyHeader) {
        $identity = ['ip' => $peer, 'peer_ip' => $peer, 'authenticated_proxy' => false];
    } else {
        $enabled = filter_var(getenv('CYBERSHIELD_LAN_PROXY_ENABLED'), FILTER_VALIDATE_BOOLEAN);
        if (!$enabled || !cybershield_lan_proxy_peer_allowed($peer)) {
            throw new CybershieldClientIdentityException('Relais réseau non autorisé.');
        }
        foreach ($headers as $header) {
            if (!isset($server[$header]) || !is_string($server[$header])) {
                throw new CybershieldClientIdentityException('Identité du relais réseau incomplète.');
            }
        }
        $rawIp = $server[$headers[0]];
        $clientIp = cybershield_canonical_client_ip($rawIp);
        $timestamp = $server[$headers[1]];
        $signature = $server[$headers[2]];
        $method = $server['REQUEST_METHOD'] ?? '';
        $uri = $server['REQUEST_URI'] ?? '';
        if ($clientIp === null || $clientIp !== $rawIp
            || !preg_match('/^[1-9][0-9]{8,11}$/D', $timestamp)
            || abs(time() - (int) $timestamp) > 30
            || !preg_match('/^[a-f0-9]{64}$/D', $signature)
            || !is_string($method) || !preg_match('/^[A-Z]{1,16}$/D', $method)
            || !is_string($uri) || $uri === '' || $uri[0] !== '/' || strlen($uri) > 16384
            || preg_match('/[\x00-\x20\x7f]/', $uri)) {
            throw new CybershieldClientIdentityException('Identité du relais réseau invalide ou expirée.');
        }
        $secretFile = getenv('CYBERSHIELD_LAN_PROXY_SECRET_FILE');
        if (!is_string($secretFile) || $secretFile === '' || !is_file($secretFile) || !is_readable($secretFile)) {
            throw new CybershieldClientIdentityException('Relais réseau non configuré.');
        }
        $secret = @file_get_contents($secretFile, false, null, 0, 4097);
        $secret = is_string($secret) ? trim($secret) : '';
        if (strlen($secret) < 32 || strlen($secret) > 4096) {
            throw new CybershieldClientIdentityException('Relais réseau non configuré.');
        }
        $signed = "v1\n" . $clientIp . "\n" . $timestamp . "\n" . $method . "\n" . $uri;
        if (!hash_equals(hash_hmac('sha256', $signed, $secret), $signature)) {
            throw new CybershieldClientIdentityException('Signature du relais réseau invalide.');
        }
        $identity = ['ip' => $clientIp, 'peer_ip' => $peer, 'authenticated_proxy' => true];
    }
    if ($useRequestCache) { $requestIdentity = $identity; }
    return $identity;
}

function cybershield_client_ip(?array $server = null): string
{
    return cybershield_client_identity($server)['ip'];
}

function cybershield_is_lan_proxy_request(?array $server = null): bool
{
    return cybershield_client_identity($server)['authenticated_proxy'];
}
