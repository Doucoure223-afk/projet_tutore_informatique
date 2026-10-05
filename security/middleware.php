<?php
require_once __DIR__ . '/hybrid_analyzer.php';
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/response_handler.php';

function cybershield_rate_allowed(array $config, string $ip): bool
{
    if (empty($config['rate_limiting']['enabled'])) { return true; }
    $directory = $config['log_dir'] . '/rate';
    if (!is_dir($directory) && !@mkdir($directory, 0700, true) && !is_dir($directory)) { throw new RuntimeException('Limiteur indisponible.'); }
    $handle = @fopen($directory . '/' . hash('sha256', $ip) . '.json', 'c+');
    if (!$handle) { throw new RuntimeException('Limiteur indisponible.'); }
    try {
        if (!flock($handle, LOCK_EX)) { throw new RuntimeException('Limiteur indisponible.'); }
        $now = time();
        $times = json_decode(stream_get_contents($handle), true);
        $times = is_array($times) ? array_values(array_filter($times, static fn($time) => is_int($time) && $time > $now - $config['rate_limiting']['window_seconds'])) : [];
        $allowed = count($times) < $config['rate_limiting']['max_requests'];
        if ($allowed) { $times[] = $now; }
        rewind($handle); ftruncate($handle, 0);
        if (fwrite($handle, json_encode($times)) === false) { throw new RuntimeException('Limiteur indisponible.'); }
        fflush($handle); flock($handle, LOCK_UN);
        return $allowed;
    } finally { fclose($handle); }
}

/** Enforce the 90-day policy at most once daily; retention errors never open the filter. */
function cybershield_retention(SecurityLogger $logger, array $config): void
{
    $directory = rtrim($config['log_dir'], '/\\');
    $marker = $directory . '/.retention-last-run';
    $lock = @fopen($directory . '/.retention.lock', 'c+');
    if (!$lock) { throw new RuntimeException('Contrôle de rétention indisponible.'); }
    try {
        if (!flock($lock, LOCK_EX)) { throw new RuntimeException('Verrou de rétention indisponible.'); }
        $today = gmdate('Y-m-d');
        if (is_file($marker) && trim((string) file_get_contents($marker)) === $today) { return; }
        $logger->purgeExpiredEvents($config['retention_days']);
        if (file_put_contents($marker, $today, LOCK_EX) === false) { throw new RuntimeException('Enregistrement de la rétention impossible.'); }
        flock($lock, LOCK_UN);
    } finally { fclose($lock); }
}

function cybershield_flatten_inputs(array $values, string $prefix, array &$flat, array $config, int $depth = 0): void
{
    if ($depth > 8) { throw new LengthException('Structure trop profonde.'); }
    foreach ($values as $key => $value) {
        $name = $prefix . '[' . $key . ']';
        if (is_array($value)) { cybershield_flatten_inputs($value, $name, $flat, $config, $depth + 1); continue; }
        if (!is_scalar($value) && $value !== null) { throw new LengthException('Valeur invalide.'); }
        if (count($flat) >= $config['max_parameters'] || strlen((string) $value) > $config['max_input_length']) { throw new LengthException('Taille excessive.'); }
        $flat[$name] = (string) $value;
    }
}

function cybershield_protect(): void
{
    $config = require __DIR__ . '/../config/security.php';
    $start = microtime(true);
    $requestId = bin2hex(random_bytes(16));
    $logger = null;
    $event = ['request_id' => $requestId, 'action' => 'ALLOWED', 'score' => 0, 'source' => 'heuristic', 'attack_type' => 'NONE'];
    $status = 403;
    header('X-CyberShield: active');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    try {
        $logger = new SecurityLogger(rtrim($config['log_dir'], '/\\') . '/events.jsonl');
        if (!cybershield_rate_allowed($config, $_SERVER['REMOTE_ADDR'] ?? 'unknown')) {
            $status = 429;
            header('Retry-After: 60');
            $event = array_merge($event, ['action' => 'BLOCKED', 'attack_type' => 'RATE_LIMIT', 'reason' => 'Limite de requêtes atteinte.']);
        } else {
            $contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
            if ($contentLength > $config['max_request_size'] || strlen($_SERVER['QUERY_STRING'] ?? '') > $config['max_request_size']) { throw new LengthException(); }
            // REST-style applications may route untrusted identifiers through the URL path.
            // Scan its path component too, while excluding query data (already parsed below).
            $requestPath = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
            if (!is_string($requestPath) || $requestPath === '') { $requestPath = '/'; }
            $requestPath = rawurldecode($requestPath);
            if (strlen($requestPath) > $config['max_input_length']) { throw new LengthException(); }
            $inputs = ['PATH' => $requestPath];
            cybershield_flatten_inputs($_GET, 'GET', $inputs, $config);
            cybershield_flatten_inputs($_POST, 'POST', $inputs, $config);
            cybershield_flatten_inputs($_COOKIE, 'COOKIE', $inputs, $config);
            if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === 0) {
                $raw = file_get_contents('php://input', false, null, 0, $config['max_request_size'] + 1);
                if (strlen($raw) > $config['max_request_size']) { throw new LengthException(); }
                $json = json_decode($raw, true, 16, JSON_THROW_ON_ERROR);
                if (!is_array($json)) { throw new JsonException(); }
                cybershield_flatten_inputs($json, 'JSON', $inputs, $config);
            }
            $filename = basename($_SERVER['SCRIPT_NAME'] ?? '');
            $context = match ($filename) {
                'login.php' => 'login', 'inscription.php' => 'register', 'dashboard.php' => 'admin', default => 'search',
            };
            $analyzer = new HybridAnalyzer();
            $aiCalls = 0;
            foreach ($inputs as $parameter => $payload) {
                $analysis = $analyzer->analyze($payload, $parameter, $context, $aiCalls < $config['max_ai_calls']);
                if ($analysis['needs_ai']) { $aiCalls++; }
                if ($analysis['score'] > $event['score'] || $analysis['would_block']) {
                    $event = array_merge($event, $analysis, ['parameter' => $parameter, 'context' => $context,
                        'payload' => $analysis['score'] >= $config['review_threshold'] ? $payload : '']);
                }
                if ($analysis['would_block']) { break; }
            }
        }
    } catch (LengthException $error) {
        $status = 413;
        $event = array_merge($event, ['action' => 'BLOCKED', 'attack_type' => 'REQUEST_SIZE', 'reason' => 'Entrée trop volumineuse ou trop complexe.']);
    } catch (JsonException $error) {
        $status = 400;
        $event = array_merge($event, ['action' => 'BLOCKED', 'attack_type' => 'INVALID_JSON', 'reason' => 'Corps JSON invalide.']);
    } catch (Throwable $error) {
        error_log('CyberShield : protection indisponible (' . get_class($error) . ').');
        ResponseHandler::blockRequest('PROTECTION_UNAVAILABLE', '', $requestId, 503);
    }
    $event['latency_ms'] = (microtime(true) - $start) * 1000;
    try { $logger->logEvent($event); }
    catch (Throwable $error) {
        error_log('CyberShield : journal indisponible.');
        ResponseHandler::blockRequest('LOG_UNAVAILABLE', '', $requestId, 503);
    }
    try { cybershield_retention($logger, $config); }
    catch (Throwable $error) { error_log('CyberShield : rétention différée.'); }
    if (in_array($event['action'], ['BLOCKED', 'BLOCKED_BY_AI'], true)) {
        ResponseHandler::blockRequest($event['attack_type'], '', $requestId, $status);
    }
}
