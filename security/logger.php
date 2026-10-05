<?php
/** Append-only, structured security events. No database is required. */
class SecurityLogger
{
    private $logFile;
    private $accessFile;
    private $iaLogFile;
    private $errorLogFile;
    private $siemOutbox;
    private $requestId;
    private $loggedRequests = [];

    public function __construct($logFile = null)
    {
        $this->logFile = $logFile ?: __DIR__ . '/../logs/events.jsonl';
        $directory = dirname($this->logFile);
        if (!is_dir($directory) && !mkdir($directory, 0700, true) && !is_dir($directory)) {
            throw new RuntimeException('Impossible de créer le dossier des journaux.');
        }
        $this->accessFile = $directory . '/access.jsonl';
        $this->iaLogFile = $directory . '/ia_analysis.jsonl';
        $this->errorLogFile = $directory . '/errors.jsonl';
        $this->siemOutbox = $directory . '/siem-outbox';
        $this->requestId = bin2hex(random_bytes(16));
    }

    /** Call once, after all inputs and the optional AI analysis have a final decision. */
    public function logEvent(array $event)
    {
        $requestId = $this->clean($event['request_id'] ?? $this->requestId, 128);
        if (isset($this->loggedRequests[$requestId])) {
            return $this->loggedRequests[$requestId];
        }
        $action = strtoupper((string) ($event['action'] ?? 'ALLOWED'));
        $aliases = ['BLOCK' => 'BLOCKED', 'ALLOW' => 'ALLOWED', 'BLOCKED_BY_IA' => 'BLOCKED_BY_AI', 'MONITOR' => 'MONITORED'];
        $action = $aliases[$action] ?? $action;
        if (!in_array($action, ['BLOCKED', 'BLOCKED_BY_AI', 'ALLOWED', 'MONITORED'], true)) {
            throw new InvalidArgumentException('Seule une décision finale peut être journalisée.');
        }
        $parameter = $this->clean($event['parameter'] ?? '', 120);
        $rawPayload = is_scalar($event['payload'] ?? null) ? (string) $event['payload'] : '';
        // Never retain even an unsalted digest of credentials or payment data.
        // Such digests can be recovered by guessing common passwords or tokens.
        $sensitivePayload = preg_match('/pass(?:word)?|passwd|pwd|token|secret|authorization|cookie|session|csrf|card|carte|cvv|cvc|\bpin\b|\bpan\b|iban|api[_-]?key|totp|otp|one[_-]?time|verification[_-]?code/i', $parameter) === 1;
        $timestamp = isset($event['timestamp']) ? strtotime((string) $event['timestamp']) : false;
        $path = (string) ($event['path'] ?? ($_SERVER['REQUEST_URI'] ?? ''));
        // Query strings and fragments may contain passwords or tokens.
        $path = preg_split('/[?#]/', $path, 2)[0];
        $entry = [
            'id' => $this->clean($event['id'] ?? $requestId, 128),
            'request_id' => $requestId,
            'timestamp' => gmdate('c', $timestamp === false ? time() : $timestamp),
            'ip' => $this->clean($event['ip'] ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 64),
            'method' => $this->clean($event['method'] ?? ($_SERVER['REQUEST_METHOD'] ?? 'CLI'), 16),
            'path' => $this->clean($path, 500),
            'context' => $this->clean($event['context'] ?? '', 100),
            'parameter' => $parameter,
            'attack_type' => $this->clean($event['attack_type'] ?? $event['type'] ?? 'NONE', 100),
            'score' => max(0, min(100, (int) ($event['score'] ?? 0))),
            'risk' => isset($event['risk']) ? max(0, min(1, (float) $event['risk'])) : null,
            'confidence' => isset($event['confidence']) ? max(0, min(1, (float) $event['confidence'])) : null,
            'action' => $action,
            'source' => $this->clean($event['source'] ?? 'heuristic', 50),
            'reason' => $this->redact($event['reason'] ?? ''),
            'patterns' => $this->redact(is_array($event['patterns'] ?? null) ? $event['patterns'] : []),
            'payload' => $rawPayload === '' ? '' : ($sensitivePayload ? '[REDACTED]' : '[sha256:' . hash('sha256', $rawPayload) . ']'),
            'payload_hash' => ($rawPayload === '' || $sensitivePayload) ? '' : hash('sha256', $rawPayload),
            'latency_ms' => max(0, round((float) ($event['latency_ms'] ?? 0), 2)),
            'ai_status' => $this->clean($event['ai_status'] ?? 'not_requested', 50),
            'model_version' => $this->clean($event['model_version'] ?? '', 100),
        ];
        $this->writeJson($this->logFile, $entry);
        $siemUrl = getenv('CYBERSHIELD_SIEM_URL');
        if (is_string($siemUrl) && trim($siemUrl) !== '' &&
            ($action !== 'ALLOWED' || $entry['score'] >= 30 || ($entry['risk'] ?? 0) >= 0.75)) {
            try { $this->enqueueSiem($entry); }
            catch (Throwable $error) { error_log('CyberShield : file SIEM saturée ou indisponible; événement conservé localement.'); }
        }
        $this->loggedRequests[$requestId] = $entry;
        return $entry;
    }

    /** Queue only alerts and review-worthy events; the HTTP request never waits for the SIEM. */
    private function enqueueSiem(array $entry): void
    {
        if (!is_dir($this->siemOutbox) && !mkdir($this->siemOutbox, 0700, true) && !is_dir($this->siemOutbox)) {
            throw new RuntimeException('File SIEM indisponible.');
        }
        $queued = 0;
        foreach (new DirectoryIterator($this->siemOutbox) as $file) {
            if ($file->isFile() && preg_match('/^[a-f0-9]{64}\.json$/D', $file->getFilename())) {
                $queued++;
                if ($queued >= 10000) { throw new RuntimeException('File SIEM pleine.'); }
            }
        }
        $requestId = (string) ($entry['request_id'] ?? $entry['id'] ?? '');
        $target = $this->siemOutbox . '/' . hash('sha256', $requestId) . '.json';
        if (is_file($target)) { return; }
        $json = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false) { throw new RuntimeException('Événement SIEM non sérialisable.'); }
        $temporary = tempnam($this->siemOutbox, '.pending-');
        if ($temporary === false) { throw new RuntimeException('Fichier temporaire SIEM indisponible.'); }
        @chmod($temporary, 0600);
        try {
            $handle = @fopen($temporary, 'wb');
            if (!$handle) { throw new RuntimeException('Fichier temporaire SIEM non inscriptible.'); }
            try {
                $offset = 0;
                while ($offset < strlen($json)) {
                    $written = fwrite($handle, substr($json, $offset));
                    if ($written === false || $written === 0) { throw new RuntimeException('Écriture SIEM incomplète.'); }
                    $offset += $written;
                }
                if (!fflush($handle)) { throw new RuntimeException('Vidage de la file SIEM impossible.'); }
            } finally { fclose($handle); }
            if (!@rename($temporary, $target)) { throw new RuntimeException('Publication de l’événement SIEM impossible.'); }
        } finally {
            if (is_file($temporary)) { @unlink($temporary); }
        }
    }

    private function clean($value, $limit = 1024)
    {
        if (!is_scalar($value) && $value !== null) {
            return '';
        }
        return substr(preg_replace('/[\x00-\x1f\x7f]/', ' ', (string) $value), 0, $limit);
    }

    public function redact($value, $key = '', $depth = 0)
    {
        if (preg_match('/pass(?:word)?|passwd|pwd|token|secret|authorization|cookie|session|csrf|card|carte|cvv|cvc|\bpin\b|\bpan\b|iban|api[_-]?key|totp|otp|one[_-]?time|verification[_-]?code/i', (string) $key)) {
            return '[REDACTED]';
        }
        if ($depth > 8) {
            return '[TRUNCATED]';
        }
        if (is_array($value)) {
            $result = [];
            foreach (array_slice($value, 0, 100, true) as $name => $item) {
                $result[$this->clean($name, 120)] = $this->redact($item, (string) $name, $depth + 1);
            }
            return $result;
        }
        $text = $this->clean($value);
        $text = preg_replace('/\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]*/i', '$1: [REDACTED]', $text);
        $text = preg_replace('~\b(password|passwd|pwd|token|secret|csrf_token|api[_-]?key|cvv|cvc|card_number|totp(?:[_-]?code)?|otp(?:[_-]?code)?|one[_-]?time[_-]?(?:code|password)|verification[_-]?code)["\x27]?\s*([:=])\s*(?:"[^"]*"|\x27[^\x27]*\x27|[^&\s,;]+)~i', '$1$2[REDACTED]', $text);
        $text = preg_replace('/\b(?:\d[ -]?){13,19}\b/', '[REDACTED_CARD]', $text);
        return $text;
    }

    private function writeJson($file, array $entry)
    {
        $line = json_encode($entry, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($line === false) {
            throw new RuntimeException('Événement de sécurité non sérialisable.');
        }
        $handle = @fopen($file, 'ab');
        if (!$handle) {
            throw new RuntimeException('Impossible d’ouvrir le journal de sécurité.');
        }
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Impossible de verrouiller le journal de sécurité.');
            }
            $line .= "\n";
            $offset = 0;
            while ($offset < strlen($line)) {
                $written = fwrite($handle, substr($line, $offset));
                if ($written === false || $written === 0) {
                    throw new RuntimeException('Écriture incomplète du journal de sécurité.');
                }
                $offset += $written;
            }
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
    }

    private function readEvents($file)
    {
        if (!is_file($file)) {
            return [];
        }
        $handle = @fopen($file, 'rb');
        if (!$handle) {
            throw new RuntimeException('Impossible de lire le journal de sécurité.');
        }
        $events = [];
        try {
            if (!flock($handle, LOCK_SH)) {
                throw new RuntimeException('Impossible de verrouiller le journal de sécurité.');
            }
            while (($line = fgets($handle)) !== false) {
                $event = json_decode($line, true);
                if (is_array($event) && isset($event['timestamp'])) {
                    $events[] = $event;
                }
            }
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
        return $events;
    }

    /** Stream old JSONL rows away without holding the whole incident file in memory. */
    public function purgeExpiredEvents($days = 90)
    {
        $days = max(1, min(3660, (int) $days));
        if (!is_file($this->logFile)) { return 0; }
        $source = @fopen($this->logFile, 'c+');
        if (!$source) { throw new RuntimeException('Impossible d’ouvrir le journal pour la rétention.'); }
        $temporary = null;
        $removed = 0;
        try {
            if (!flock($source, LOCK_EX)) { throw new RuntimeException('Impossible de verrouiller le journal pour la rétention.'); }
            $temporaryPath = tempnam(dirname($this->logFile), '.events-retention-');
            if ($temporaryPath === false) { throw new RuntimeException('Impossible de créer le fichier temporaire de rétention.'); }
            $temporary = fopen($temporaryPath, 'w+b');
            if (!$temporary) { @unlink($temporaryPath); throw new RuntimeException('Impossible d’écrire le fichier de rétention.'); }
            rewind($source);
            $cutoff = time() - ($days * 86400);
            while (($line = fgets($source)) !== false) {
                $event = json_decode($line, true);
                $timestamp = is_array($event) && is_string($event['timestamp'] ?? null) ? strtotime($event['timestamp']) : false;
                if ($timestamp !== false && $timestamp < $cutoff) { $removed++; continue; }
                $offset = 0;
                while ($offset < strlen($line)) {
                    $written = fwrite($temporary, substr($line, $offset));
                    if ($written === false || $written === 0) { throw new RuntimeException('Écriture incomplète du journal temporaire.'); }
                    $offset += $written;
                }
            }
            if (!fflush($temporary)) { throw new RuntimeException('Vidage du journal temporaire impossible.'); }
            rewind($source);
            rewind($temporary);
            if (!ftruncate($source, 0)) { throw new RuntimeException('Réécriture du journal impossible.'); }
            stream_copy_to_stream($temporary, $source);
            fflush($source);
            flock($source, LOCK_UN);
            return $removed;
        } finally {
            if (is_resource($temporary)) {
                $temporaryPath = stream_get_meta_data($temporary)['uri'];
                fclose($temporary);
                if (is_file($temporaryPath)) { @unlink($temporaryPath); }
            }
            fclose($source);
        }
    }

    /** Newest first. limit=0 returns all matching events, including for exports. */
    public function getEvents(array $filters = [], $limit = 100)
    {
        $events = array_reverse($this->readEvents($this->logFile));
        $filtered = [];
        foreach ($events as $event) {
            if (!isset($event['action'], $event['attack_type'], $event['ip'], $event['timestamp'])) {
                continue;
            }
            if (!empty($filters['action']) && $event['action'] !== $filters['action']) { continue; }
            $type = $filters['type'] ?? $filters['attack_type'] ?? '';
            if ($type !== '' && $event['attack_type'] !== $type) { continue; }
            if (!empty($filters['ip']) && $event['ip'] !== $filters['ip']) { continue; }
            $day = substr($event['timestamp'], 0, 10);
            if (!empty($filters['from']) && $day < substr($filters['from'], 0, 10)) { continue; }
            if (!empty($filters['to']) && $day > substr($filters['to'], 0, 10)) { continue; }
            if (!empty($filters['search']) && stripos(json_encode($event, JSON_UNESCAPED_UNICODE), (string) $filters['search']) === false) { continue; }
            $filtered[] = $event;
            if ($limit > 0 && count($filtered) >= $limit) { break; }
        }
        return $filtered;
    }

    private function emptyStats()
    {
        return ['total' => 0, 'attacks' => 0, 'blocked' => 0, 'allowed' => 0, 'monitored' => 0, 'ai_analyzed' => 0, 'by_type' => [], 'top_ips' => []];
    }

    private function addStats(array &$stats, array $event)
    {
        $stats['total']++;
        $blocked = in_array($event['action'], ['BLOCKED', 'BLOCKED_BY_AI'], true);
        $stats['blocked'] += (int) $blocked;
        $stats['allowed'] += (int) ($event['action'] === 'ALLOWED');
        $stats['monitored'] += (int) ($event['action'] === 'MONITORED');
        $stats['ai_analyzed'] += (int) (isset($event['risk']) || strtolower($event['source'] ?? '') === 'ai');
        if ($blocked || $event['action'] === 'MONITORED' || ($event['score'] ?? 0) >= 30) {
            $stats['attacks']++;
            $type = $event['attack_type'];
            $stats['by_type'][$type] = ($stats['by_type'][$type] ?? 0) + 1;
            $stats['top_ips'][$event['ip']] = ($stats['top_ips'][$event['ip']] ?? 0) + 1;
        }
    }

    public function getStats($days = 7)
    {
        $days = max(1, min(3660, (int) $days));
        $stats = $this->emptyStats();
        foreach ($this->getEvents(['from' => gmdate('Y-m-d', strtotime('-' . ($days - 1) . ' days')), 'to' => gmdate('Y-m-d')], 0) as $event) {
            $this->addStats($stats, $event);
        }
        arsort($stats['top_ips']);
        arsort($stats['by_type']);
        $stats['block_rate'] = $stats['total'] ? round(100 * $stats['blocked'] / $stats['total'], 1) : 0;
        return $stats;
    }

    public function getDailyStats($days = 7)
    {
        $days = max(1, min(3660, (int) $days));
        $daily = [];
        for ($offset = $days - 1; $offset >= 0; $offset--) {
            $date = gmdate('Y-m-d', strtotime('-' . $offset . ' days'));
            $daily[$date] = ['date' => $date] + $this->emptyStats();
        }
        foreach ($this->getEvents(['from' => array_key_first($daily), 'to' => gmdate('Y-m-d')], 0) as $event) {
            $day = substr($event['timestamp'], 0, 10);
            if (isset($daily[$day])) {
                $this->addStats($daily[$day], $event);
            }
        }
        return array_values($daily);
    }

    public function exportCsv(array $filters = [])
    {
        $stream = fopen('php://temp', 'w+');
        $columns = ['timestamp', 'ip', 'method', 'path', 'attack_type', 'parameter', 'score', 'risk', 'action', 'source', 'reason', 'payload', 'id'];
        fputcsv($stream, $columns, ',', '"', '');
        foreach ($this->getEvents($filters, 0) as $event) {
            $row = [];
            foreach ($columns as $column) {
                $value = $event[$column] ?? '';
                $value = is_array($value) ? json_encode($value, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) : (string) $value;
                // Neutralize spreadsheet formulas in attacker-controlled cells.
                if (preg_match('/^[\s]*[=+@-]/', $value)) { $value = "'" . $value; }
                $row[] = $value;
            }
            fputcsv($stream, $row, ',', '"', '');
        }
        rewind($stream);
        $csv = stream_get_contents($stream);
        fclose($stream);
        return $csv;
    }

    /** JSON Lines export for SIEM ingestion; each line is one filtered event. */
    public function exportJsonLines(array $filters = []): string
    {
        $lines = [];
        foreach ($this->getEvents($filters, 0) as $event) {
            $line = json_encode($event, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($line === false) {
                throw new RuntimeException('Événement de sécurité non sérialisable.');
            }
            $lines[] = $line;
        }
        return $lines ? implode("\n", $lines) . "\n" : '';
    }

    // Legacy adapters kept for older demonstration pages.
    public function logAttack($ip, $attackType, $payload, $parameter = '', $score = 0, $patterns = [], $action = 'BLOCKED')
    {
        if ($action === 'PENDING_IA') { return false; }
        return $this->logEvent(['ip' => $ip, 'attack_type' => $attackType, 'payload' => $payload, 'parameter' => $parameter, 'score' => $score, 'patterns' => $patterns, 'action' => $action ?: 'BLOCKED']);
    }
    public function logIAnalysis($ip, $sqlQuery, $iaResult, $context = '')
    {
        $this->writeJson($this->iaLogFile, ['timestamp' => gmdate('c'), 'ip' => $this->clean($ip, 64), 'context' => $this->clean($context, 100), 'analysis' => $this->redact($iaResult)]);
        return true;
    }
    public function logAccess($username, $action, $status)
    {
        $this->writeJson($this->accessFile, ['timestamp' => gmdate('c'), 'ip' => $this->clean($_SERVER['REMOTE_ADDR'] ?? 'unknown', 64), 'user' => $this->redact($username), 'action' => $this->redact($action), 'status' => $this->redact($status)]);
        return true;
    }
    public function logError($message, $level = 'ERROR')
    {
        $this->writeJson($this->errorLogFile, ['timestamp' => gmdate('c'), 'level' => $this->clean($level, 16), 'message' => $this->redact($message)]);
        return true;
    }
    public function getLogFile() { return $this->logFile; }
    public function getLogContent() { return is_file($this->logFile) ? file_get_contents($this->logFile) : ''; }
    public function getIALogContent() { return is_file($this->iaLogFile) ? file_get_contents($this->iaLogFile) : ''; }
    public function getRecentAttacks($limit = 10) { return array_map(function ($entry) { return json_encode($entry, JSON_UNESCAPED_UNICODE); }, $this->getEvents([], $limit)); }
    public function getIALogs($limit = 10) { return array_map(function ($entry) { return json_encode($entry, JSON_UNESCAPED_UNICODE); }, array_slice(array_reverse($this->readEvents($this->iaLogFile)), 0, $limit)); }
}
