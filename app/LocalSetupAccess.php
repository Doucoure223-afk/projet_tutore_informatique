<?php
/** Allow local-only routes from loopback or the configured Docker Desktop host forwarder. */
function cybershield_local_request_allowed(array $server, ?bool $isCli = null, ?string $routeTable = null): bool
{
    if ($isCli ?? (PHP_SAPI === 'cli')) {
        return true;
    }

    $remoteIp = (string) ($server['REMOTE_ADDR'] ?? '');
    $packedIp = @inet_pton($remoteIp);
    if (in_array($remoteIp, ['127.0.0.1', '::1', '::ffff:127.0.0.1'], true)
        || (is_string($packedIp) && strlen($packedIp) === 4 && ord($packedIp[0]) === 127)) {
        return true;
    }

    if (getenv('CYBERSHIELD_CONTAINERIZED') !== '1' || getenv('CYBERSHIELD_APP_BIND_ADDRESS') !== '127.0.0.1') {
        return false;
    }

    $dockerSetupPeer = getenv('CYBERSHIELD_DOCKER_SETUP_PEER');
    if (is_string($dockerSetupPeer)
        && filter_var($dockerSetupPeer, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
        && hash_equals($dockerSetupPeer, $remoteIp)) {
        return true;
    }

    $gateway = cybershield_docker_default_gateway($routeTable);
    return is_string($gateway) && hash_equals($gateway, $remoteIp);
}

/** Read Docker's current default gateway from Linux routing data, whose subnet may change. */
function cybershield_docker_default_gateway(?string $routeTable = null): ?string
{
    $routeTable ??= @file_get_contents('/proc/net/route');
    if (!is_string($routeTable) || $routeTable === '') {
        return null;
    }
    $lines = preg_split('/\r?\n/', $routeTable);
    foreach (array_slice($lines ?: [], 1) as $line) {
        $columns = preg_split('/\s+/', trim($line));
        if (!is_array($columns) || count($columns) < 4 || $columns[1] !== '00000000'
            || !preg_match('/^[a-f0-9]{8}$/i', $columns[2]) || !ctype_xdigit($columns[3])) {
            continue;
        }
        if ((hexdec($columns[3]) & 0x3) !== 0x3) {
            continue;
        }
        $octets = array_reverse(str_split($columns[2], 2));
        $gateway = implode('.', array_map(static fn(string $octet): string => (string) hexdec($octet), $octets));
        if (filter_var($gateway, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $gateway;
        }
    }
    return null;
}

/** Backward-compatible name used by the first-run setup route. */
function cybershield_local_setup_allowed(array $server, ?bool $isCli = null): bool
{
    return cybershield_local_request_allowed($server, $isCli);
}
