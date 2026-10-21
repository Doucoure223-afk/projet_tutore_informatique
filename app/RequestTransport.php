<?php
declare(strict_types=1);

/** Transport trust is independent of client-IP forwarding and is disabled by default. */
final class RequestTransport
{
    public static function isHttps(?array $server = null): bool
    {
        $server ??= $_SERVER;
        $https = $server['HTTPS'] ?? '';
        if (is_string($https) && in_array(strtolower($https), ['on', '1'], true)) {
            return true;
        }
        $peer = $server['REMOTE_ADDR'] ?? '';
        $header = $server['HTTP_X_FORWARDED_PROTO'] ?? null;
        if (!is_string($peer) || !is_string($header) || $header !== 'https') { return false; }
        $packed = @inet_pton($peer);
        if ($packed === false) { return false; }
        foreach (explode(',', getenv('CYBERSHIELD_HTTPS_PROXY_PEERS') ?: '') as $candidate) {
            $trusted = @inet_pton(trim($candidate));
            if ($trusted !== false && hash_equals($trusted, $packed)) { return true; }
        }
        return false;
    }

    public static function requireSecureTransport(?array $server = null): bool
    {
        if (!filter_var(getenv('CYBERSHIELD_REQUIRE_HTTPS'), FILTER_VALIDATE_BOOLEAN)) { return true; }
        $server ??= $_SERVER;
        // The liveness endpoint is private and carries no application session.
        if (($server['SCRIPT_NAME'] ?? '') === '/app/health.php') { return true; }
        return self::isHttps($server);
    }

    public static function cookieOptions(?array $server = null): array
    {
        return ['lifetime' => 0, 'path' => '/', 'secure' => self::isHttps($server),
            'httponly' => true, 'samesite' => 'Lax'];
    }
}
