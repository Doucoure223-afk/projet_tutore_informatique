<?php
declare(strict_types=1);

/** Local, filesystem-backed login attempt window. Identities are not stored in clear text. */
final class LoginThrottle
{
    private string $stateFile;
    private const WINDOW_SECONDS = 900;
    private const MAX_ATTEMPTS = 5;

    public function __construct(string $directory)
    {
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Stockage local de limitation indisponible.');
        }
        $this->stateFile = rtrim($directory, '/\\') . DIRECTORY_SEPARATOR . 'login-attempts.json';
    }

    /** Count every submitted attempt atomically; a valid login clears its own window. */
    public function beginAttempt(string $username, string $ip): bool
    {
        return $this->update($username, $ip, static function (array $attempts, int $now): array {
            if (count($attempts) >= self::MAX_ATTEMPTS) {
                return [$attempts, false];
            }
            $attempts[] = $now;
            return [$attempts, true];
        });
    }

    public function clear(string $username, string $ip): void
    {
        $this->update($username, $ip, static function (): array { return [[], true]; });
    }

    private function update(string $username, string $ip, callable $change): bool
    {
        $handle = @fopen($this->stateFile, 'c+');
        if (!$handle) { throw new RuntimeException('Stockage local de limitation indisponible.'); }
        try {
            if (!flock($handle, LOCK_EX)) { throw new RuntimeException('Verrou de limitation indisponible.'); }
            rewind($handle);
            $state = json_decode(stream_get_contents($handle), true);
            $state = is_array($state) ? $state : [];
            $now = time();
            foreach ($state as $key => $timestamps) {
                $recent = is_array($timestamps) ? array_values(array_filter($timestamps,
                    static fn($time) => is_int($time) && $time > $now - self::WINDOW_SECONDS)) : [];
                if ($recent) { $state[$key] = $recent; } else { unset($state[$key]); }
            }
            $key = hash('sha256', strtolower(trim($username)) . "\0" . $ip);
            [$attempts, $result] = $change($state[$key] ?? [], $now);
            if ($attempts) { $state[$key] = $attempts; } else { unset($state[$key]); }
            // Bound disk use if a public login endpoint receives many distinct names.
            if (count($state) > 10000) { $state = array_slice($state, -10000, null, true); }
            $json = json_encode($state, JSON_UNESCAPED_SLASHES);
            if ($json === false) { throw new RuntimeException('État de limitation non sérialisable.'); }
            rewind($handle);
            if (!ftruncate($handle, 0) || fwrite($handle, $json) === false || !fflush($handle)) {
                throw new RuntimeException('Écriture de limitation incomplète.');
            }
            flock($handle, LOCK_UN);
            return (bool) $result;
        } finally {
            fclose($handle);
        }
    }
}
