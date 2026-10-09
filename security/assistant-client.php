<?php
/** Shared local-only client and privacy boundary for the administrator assistant. */
require_once __DIR__ . '/logger.php';
require_once __DIR__ . '/ia_analyzer.php';
require_once __DIR__ . '/access.php';

function cybershield_assistant_url(): string
{
    return rtrim((string) (getenv('CYBERSHIELD_ASSISTANT_URL') ?: 'http://127.0.0.1:5100'), '/');
}

function cybershield_assistant_token_path(): string
{
    return (string) (getenv('CYBERSHIELD_ASSISTANT_TOKEN_FILE') ?: __DIR__ . '/../secrets/assistant_token.txt');
}

function cybershield_assistant_health(): array
{
    $health = ['status' => 'unavailable', 'model_ready' => false, 'model' => '', 'available' => false];
    if (!function_exists('curl_init')) { return $health; }
    $handle = curl_init(cybershield_assistant_url() . '/health');
    curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_CONNECTTIMEOUT => 2, CURLOPT_TIMEOUT => 3]);
    $body = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    if (is_string($body)) {
        $decoded = json_decode($body, true);
        if (is_array($decoded)) { $health = $decoded + $health; }
    }
    $health['available'] = $status === 200 && !empty($health['model_ready']);
    return $health;
}

function cybershield_assistant_clean_question($value): string
{
    if (!is_string($value)) { throw new InvalidArgumentException('Saisis une question en texte.'); }
    $question = trim($value);
    $length = function_exists('mb_strlen') ? mb_strlen($question, 'UTF-8') : strlen($question);
    if ($question === '' || $length > 1200) {
        throw new InvalidArgumentException('Saisis une question de 1 200 caractères maximum.');
    }
    $question = preg_replace('/\b(authorization|cookie|set-cookie)\s*:\s*[^\r\n]*/i', '$1: [REDACTED]', $question);
    $question = preg_replace('/\b(password|passwd|pwd|token|secret|api[_-]?key|csrf[_-]?token|totp|otp)\s*([:=])\s*(?:"[^"]*"|\x27[^\x27]*\x27|[^&\s,;]+)/i', '$1$2[REDACTED]', $question);
    $question = preg_replace('/\b(?:\d[ -]?){13,19}\b/', '[REDACTED_CARD]', $question);
    return is_string($question) ? $question : '[Question expurgée]';
}

function cybershield_assistant_context(string $page): array
{
    $allowedPages = ['dashboard', 'lab', 'ip-rules', 'assistant'];
    if (!in_array($page, $allowedPages, true)) { $page = 'console'; }

    $logger = console_logger();
    $stats = $logger->getStats(7);
    $recent = [];
    foreach ($logger->getEvents([], 8) as $event) {
        $action = strtoupper((string) ($event['action'] ?? ''));
        $source = strtolower((string) ($event['source'] ?? ''));
        $type = strtoupper((string) ($event['attack_type'] ?? 'OTHER'));
        $time = (string) ($event['timestamp'] ?? 'unknown');
        $recent[] = [
            'time' => preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/', $time) ? substr($time, 0, 25) : 'unknown',
            'action' => in_array($action, ['BLOCKED', 'BLOCKED_BY_AI', 'ALLOWED', 'MONITORED'], true) ? $action : 'OTHER',
            'type' => preg_match('/^[A-Z0-9_-]{1,40}$/D', $type) ? $type : 'OTHER',
            'source' => in_array($source, ['heuristic', 'ai', 'mlp', 'ip_policy'], true) ? $source : 'other',
            'score' => max(0, min(100, (int) ($event['score'] ?? 0))),
            'mlp_score' => isset($event['risk']) && is_numeric($event['risk']) ? max(0, min(1, (float) $event['risk'])) : null,
            'latency_ms' => max(0, min(60000, (float) ($event['latency_ms'] ?? 0))),
        ];
    }
    $securityConfig = require __DIR__ . '/../config/security.php';
    return [
        'page' => $page,
        'period_days' => 7,
        'block_mode' => (bool) ($securityConfig['block_mode'] ?? false),
        'mlp_available' => !empty(console_health()['model_loaded']),
        'totals' => [
            'events' => (int) ($stats['total'] ?? 0),
            'signals' => (int) ($stats['attacks'] ?? 0),
            'blocked' => (int) ($stats['blocked'] ?? 0),
            'allowed' => (int) ($stats['allowed'] ?? 0),
            'observed' => (int) ($stats['monitored'] ?? 0),
            'mlp_analyses' => (int) ($stats['ai_analyzed'] ?? 0),
        ],
        'recent' => $recent,
    ];
}

function cybershield_assistant_ask($rawQuestion, string $page): array
{
    try {
        $question = cybershield_assistant_clean_question($rawQuestion);
    } catch (InvalidArgumentException $error) {
        return ['ok' => false, 'status' => 400, 'error' => $error->getMessage()];
    }
    if (!function_exists('curl_init')) {
        return ['ok' => false, 'status' => 503, 'error' => 'L’extension cURL de PHP est nécessaire pour joindre l’assistant local.'];
    }

    $token = @file_get_contents(cybershield_assistant_token_path());
    $token = is_string($token) ? trim($token) : '';
    if (strlen($token) < 32) {
        return ['ok' => false, 'status' => 503, 'error' => 'Le jeton privé du service assistant est absent. Relance la configuration locale.'];
    }

    $payload = json_encode([
        'question' => $question,
        'context' => cybershield_assistant_context($page),
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if (!is_string($payload)) {
        return ['ok' => false, 'status' => 500, 'error' => 'Impossible de préparer la question.'];
    }

    if (session_status() === PHP_SESSION_ACTIVE) { session_write_close(); }
    $handle = curl_init(cybershield_assistant_url() . '/chat');
    curl_setopt_array($handle, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json', 'Authorization: Bearer ' . $token],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT => 95,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
    ]);
    $body = curl_exec($handle);
    $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
    curl_close($handle);
    $response = is_string($body) ? json_decode($body, true) : null;
    if ($status === 200 && is_array($response) && is_string($response['answer'] ?? null) && trim($response['answer']) !== '') {
        $answer = function_exists('mb_substr') ? mb_substr($response['answer'], 0, 6000, 'UTF-8') : substr($response['answer'], 0, 6000);
        return ['ok' => true, 'status' => 200, 'answer' => $answer];
    }
    error_log('CyberShield assistant unavailable; HTTP ' . $status . '.');
    if ($status === 429) {
        return ['ok' => false, 'status' => 429, 'error' => 'Trop de questions rapprochées. Réessaie dans une minute.'];
    }
    return ['ok' => false, 'status' => 503, 'error' => $status === 0
        ? 'Le service LangGraph ne répond pas. Vérifie Ollama et démarre l’assistant local.'
        : 'Le modèle local est indisponible ou n’a pas pu traiter la demande. Vérifie son état puis réessaie.'];
}
