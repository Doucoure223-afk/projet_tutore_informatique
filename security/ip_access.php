<?php
declare(strict_types=1);

/**
 * Local IP deny list shared by the request middleware and the security console.
 * The data file is kept beside the private JSONL logs, outside the web root.
 */
final class IpAccessControl
{
    private string $rulesFile;

    public function __construct(string $logDirectory)
    {
        $this->rulesFile = rtrim($logDirectory, '/\\') . DIRECTORY_SEPARATOR . 'blocked-ips.json';
    }

    public static function normalize(string $ip): string
    {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException('Adresse IP invalide.');
        }
        $packed = inet_pton($ip);
        $normalized = $packed === false ? false : inet_ntop($packed);
        if ($normalized === false) {
            throw new InvalidArgumentException('Adresse IP invalide.');
        }
        return strtolower($normalized);
    }

    public function isBlocked(string $ip): bool
    {
        try {
            $normalized = self::normalize($ip);
        } catch (InvalidArgumentException $error) {
            return false;
        }
        $rules = $this->readRules();
        return isset($rules[$normalized]);
    }

    /** @return list<array{ip_address: string, comment: string, created_at: string}> */
    public function listRules(): array
    {
        $rules = array_values($this->readRules());
        usort($rules, static fn(array $a, array $b): int => strcmp($a['ip_address'], $b['ip_address']));
        return $rules;
    }

    public function addRule(string $ip, string $comment = ''): void
    {
        $normalized = self::normalize($ip);
        $comment = trim(preg_replace('/[\\x00-\\x1f\\x7f]/u', ' ', $comment) ?? '');
        $commentLength = preg_match_all('/./us', $comment);
        if ($commentLength === false || $commentLength > 160) {
            throw new InvalidArgumentException('Le commentaire ne peut pas dépasser 160 caractères.');
        }

        $this->mutateRules(function (array &$rules) use ($normalized, $comment): void {
            if (!isset($rules[$normalized]) && count($rules) >= 500) {
                throw new RuntimeException('La liste de blocage a atteint sa limite de 500 adresses.');
            }
            $rules[$normalized] = [
                'ip_address' => $normalized,
                'comment' => $comment,
                'created_at' => gmdate('c'),
            ];
        });
    }

    public function removeRule(string $ip): bool
    {
        $normalized = self::normalize($ip);
        $removed = false;
        $this->mutateRules(function (array &$rules) use ($normalized, &$removed): void {
            if (isset($rules[$normalized])) {
                unset($rules[$normalized]);
                $removed = true;
            }
        });
        return $removed;
    }

    /** @return array<string, array{ip_address: string, comment: string, created_at: string}> */
    private function readRules(): array
    {
        if (!is_file($this->rulesFile)) {
            return [];
        }
        $contents = @file_get_contents($this->rulesFile);
        if ($contents === false) {
            throw new RuntimeException('La liste de blocage est illisible.');
        }
        try {
            $document = json_decode($contents, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw new RuntimeException('La liste de blocage est invalide.', 0, $error);
        }
        if (!is_array($document) || ($document['version'] ?? null) !== 1 || !is_array($document['rules'] ?? null)) {
            throw new RuntimeException('La liste de blocage est invalide.');
        }

        $rules = [];
        foreach ($document['rules'] as $row) {
            if (!is_array($row) || !is_string($row['ip_address'] ?? null)) {
                throw new RuntimeException('Une règle de blocage est invalide.');
            }
            try {
                $ip = self::normalize($row['ip_address']);
            } catch (InvalidArgumentException $error) {
                throw new RuntimeException('Une adresse de la liste de blocage est invalide.', 0, $error);
            }
            if (!is_string($row['comment'] ?? null) || !is_string($row['created_at'] ?? null)) {
                throw new RuntimeException('Une règle de blocage est invalide.');
            }
            $rules[$ip] = [
                'ip_address' => $ip,
                'comment' => $row['comment'],
                'created_at' => $row['created_at'],
            ];
        }
        return $rules;
    }

    private function mutateRules(callable $mutation): void
    {
        $directory = dirname($this->rulesFile);
        if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Impossible de créer le stockage privé des règles.');
        }
        $lock = @fopen($this->rulesFile . '.lock', 'c+');
        if ($lock === false) {
            throw new RuntimeException('Impossible de verrouiller la liste de blocage.');
        }
        @chmod($this->rulesFile . '.lock', 0600);
        $temporary = null;
        try {
            if (!flock($lock, LOCK_EX)) {
                throw new RuntimeException('Impossible de verrouiller la liste de blocage.');
            }
            $rules = $this->readRules();
            $mutation($rules);
            ksort($rules, SORT_STRING);
            $json = json_encode(
                ['version' => 1, 'rules' => array_values($rules)],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR
            ) . "\n";
            $temporary = tempnam($directory, '.blocked-ips-');
            if ($temporary === false || file_put_contents($temporary, $json, LOCK_EX) === false) {
                throw new RuntimeException('Impossible d’écrire la liste de blocage.');
            }
            @chmod($temporary, 0600);
            if (!@rename($temporary, $this->rulesFile)) {
                throw new RuntimeException('Impossible de publier la liste de blocage.');
            }
            $temporary = null;
        } finally {
            if (is_string($temporary) && is_file($temporary)) {
                @unlink($temporary);
            }
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
