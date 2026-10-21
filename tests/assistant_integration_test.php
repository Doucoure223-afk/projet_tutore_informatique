<?php
/** Read-only integration checks for the live, local assistant and its fast answers.
 * PowerShell: Get-Content -Raw .\tests\assistant_integration_test.php | docker compose exec -T web php
 * Also supports a copied file: php /tmp/assistant_integration_test.php
 * Optional: ASSISTANT_TEST_BASE_URL, ASSISTANT_TEST_PROJECT_ROOT, ASSISTANT_TEST_MAX_MS.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (!extension_loaded('curl')) {
    fwrite(STDERR, "FAIL L’extension PHP cURL est nécessaire.\n");
    exit(1);
}

$baseUrl = rtrim(getenv('ASSISTANT_TEST_BASE_URL') ?: 'http://127.0.0.1', '/');
$urlParts = parse_url($baseUrl);
if (!is_array($urlParts) || !in_array($urlParts['scheme'] ?? '', ['http', 'https'], true)
    || !in_array($urlParts['host'] ?? '', ['127.0.0.1', 'localhost', '[::1]', '::1'], true)
    || isset($urlParts['user']) || isset($urlParts['pass']) || isset($urlParts['query']) || isset($urlParts['fragment'])) {
    fwrite(STDERR, "FAIL ASSISTANT_TEST_BASE_URL doit désigner un serveur HTTP local.\n");
    exit(1);
}
$thresholdInput = getenv('ASSISTANT_TEST_MAX_MS');
$maxMs = $thresholdInput === false || $thresholdInput === '' ? 1500.0 : (float) $thresholdInput;
if (!is_finite($maxMs) || $maxMs <= 0 || $maxMs > 60000) {
    fwrite(STDERR, "FAIL ASSISTANT_TEST_MAX_MS doit être compris entre 0 et 60000 ms.\n");
    exit(1);
}
$root = getenv('ASSISTANT_TEST_PROJECT_ROOT') ?: dirname(__DIR__);
if (!is_file($root . '/security/logger.php') && is_file('/var/www/html/security/logger.php')) {
    $root = '/var/www/html';
}
$cookieFile = null;
$checks = 0;
$exitCode = 0;

function check_assistant(bool $condition, string $label): void
{
    global $checks;
    if (!$condition) { throw new RuntimeException($label); }
    $checks++;
    echo "OK $label\n";
}

/** No redirects, no external proxy, no application writes and no secret output. */
function assistant_http(string $path, ?array $form = null, ?string $rawJson = null): array
{
    global $baseUrl, $cookieFile, $maxMs;
    $handle = curl_init($baseUrl . $path);
    if ($handle === false) { throw new RuntimeException('Initialisation du client HTTP impossible.'); }
    try {
        $options = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => 2000,
            CURLOPT_TIMEOUT_MS => max(15000, (int) ceil($maxMs + 2000)),
            CURLOPT_COOKIEFILE => $cookieFile,
            CURLOPT_COOKIEJAR => $cookieFile,
            CURLOPT_PROXY => '',
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_HTTPHEADER => ['Accept: application/json, text/html'],
        ];
        if ($form !== null) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = http_build_query($form, '', '&', PHP_QUERY_RFC3986);
            $options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded;charset=UTF-8';
        } elseif ($rawJson !== null) {
            $options[CURLOPT_POST] = true;
            $options[CURLOPT_POSTFIELDS] = $rawJson;
            $options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/json';
        }
        curl_setopt_array($handle, $options);
        $started = hrtime(true);
        $body = curl_exec($handle);
        $elapsedMs = (hrtime(true) - $started) / 1_000_000;
        if (!is_string($body)) {
            // Avoid logging HTTP headers or cookies on a connection failure.
            throw new RuntimeException('Requête HTTP locale impossible (cURL ' . curl_errno($handle) . ').');
        }
        return [
            'status' => (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE),
            'content_type' => (string) curl_getinfo($handle, CURLINFO_CONTENT_TYPE),
            'body' => $body,
            'elapsed_ms' => $elapsedMs,
        ];
    } finally {
        curl_close($handle);
    }
}

function assistant_json(array $response): array
{
    $decoded = json_decode($response['body'], true);
    if (!is_array($decoded)) { throw new RuntimeException('L’assistant doit renvoyer un objet JSON valide.'); }
    return $decoded;
}

function assistant_stats(SecurityLogger $logger): array
{
    $stats = $logger->getStats(7);
    return array_map(static fn(string $key): int => max(0, min(10000000, (int) ($stats[$key] ?? 0))),
        ['total', 'blocked', 'monitored', 'allowed', 'attacks', 'ai_analyzed']);
}

function assistant_answer_counts(string $answer): array
{
    $answer = preg_replace('/(?<=\d)[\s\x{00A0}\x{202F}]+(?=\d)/u', '', $answer) ?? $answer;
    $counts = [];
    foreach (['événements consignés', 'bloqués', 'observés', 'autorisés', 'signaux', 'analyses MLP'] as $label) {
        if (!preg_match('/\b(\d+)\s+' . preg_quote($label, '/') . '/u', $answer, $match)) {
            throw new RuntimeException('Le bilan doit présenter ses six compteurs numériques.');
        }
        $counts[] = (int) $match[1];
    }
    return $counts;
}

try {
    $cookieFile = tempnam(sys_get_temp_dir(), 'cybershield-assistant-test-');
    if (!is_string($cookieFile)) { throw new RuntimeException('Création du cookie temporaire impossible.'); }
    @chmod($cookieFile, 0600);

    $page = assistant_http('/security/assistant.php');
    check_assistant($page['status'] === 200, 'Page assistant accessible en HTTP local');
    check_assistant(preg_match('/name="csrf_token"\s+value="([a-f0-9]{64})"/', $page['body'], $tokenMatch) === 1,
        'Page assistant fournit un jeton CSRF');
    $csrf = $tokenMatch[1];
    check_assistant(str_contains($page['body'], 'assistant-request.js') && str_contains($page['body'], 'assistant-page.js'),
        'Page assistant charge la soumission sans navigation');
    foreach (['assistant-request.js', 'assistant-page.js', 'assistant-widget.js', 'console.css'] as $asset) {
        $response = assistant_http('/security/' . $asset);
        check_assistant($response['status'] === 200 && trim($response['body']) !== '', 'Ressource disponible : ' . $asset);
    }

    $validForm = ['csrf_token' => $csrf, 'question' => 'salut', 'page' => 'assistant'];
    $hello = assistant_http('/security/assistant-chat.php', $validForm);
    $helloPayload = assistant_json($hello);
    check_assistant($hello['status'] === 200 && ($helloPayload['ok'] ?? false) === true
        && ($helloPayload['source'] ?? '') === 'local' && is_string($helloPayload['answer'] ?? null)
        && trim($helloPayload['answer']) !== '', 'Salutation répond localement sans génération LLM');
    check_assistant($hello['elapsed_ms'] < $maxMs,
        'Salutation en ' . number_format($hello['elapsed_ms'], 1, '.', '') . ' ms, sous ' . $maxMs . ' ms');

    if (!is_file($root . '/security/logger.php')) { throw new RuntimeException('Racine du projet introuvable pour lire les compteurs.'); }
    $logDirectory = rtrim(getenv('CYBERSHIELD_LOG_DIR') ?: $root . '/logs', '/\\');
    if (!is_dir($logDirectory)) { throw new RuntimeException('Dossier des journaux absent : aucun dossier ne sera créé par le test.'); }
    require_once $root . '/security/logger.php';
    $logger = new SecurityLogger($logDirectory . '/events.jsonl');
    $before = assistant_stats($logger);
    $summary = assistant_http('/security/assistant-chat.php', array_replace($validForm, ['question' => 'Fais le bilan de la supervision']));
    $after = assistant_stats($logger);
    $summaryPayload = assistant_json($summary);
    check_assistant($summary['status'] === 200 && ($summaryPayload['ok'] ?? false) === true
        && ($summaryPayload['source'] ?? '') === 'local' && is_string($summaryPayload['answer'] ?? null)
        && trim($summaryPayload['answer']) !== '', 'Bilan calculé localement à partir des traces');
    $counts = assistant_answer_counts($summaryPayload['answer']);
    check_assistant($counts === $before || $counts === $after, 'Six compteurs du bilan correspondent au journal réel sur sept jours');
    check_assistant($summary['elapsed_ms'] < $maxMs,
        'Bilan en ' . number_format($summary['elapsed_ms'], 1, '.', '') . ' ms, sous ' . $maxMs . ' ms');

    $missingCsrf = $validForm;
    unset($missingCsrf['csrf_token']);
    foreach (['absent' => $missingCsrf, 'incorrect' => array_replace($validForm, ['csrf_token' => 'invalid'])] as $label => $form) {
        $response = assistant_http('/security/assistant-chat.php', $form);
        $payload = assistant_json($response);
        check_assistant($response['status'] === 403 && ($payload['ok'] ?? true) === false, 'Jeton CSRF ' . $label . ' refusé');
    }
    $response = assistant_http('/security/assistant-chat.php', null, json_encode($validForm, JSON_THROW_ON_ERROR));
    check_assistant($response['status'] === 415 && (assistant_json($response)['ok'] ?? true) === false,
        'Corps JSON refusé par la route de formulaire');
    $response = assistant_http('/security/assistant-chat.php', array_replace($validForm, ['event_id' => '../invalid']));
    check_assistant($response['status'] === 400 && (assistant_json($response)['ok'] ?? true) === false,
        'Référence d’alerte invalide refusée');
    $response = assistant_http('/security/assistant-chat.php');
    check_assistant($response['status'] === 405 && (assistant_json($response)['ok'] ?? true) === false,
        'GET refusé sur la route des questions');
    echo "PASS $checks contrôles assistant ; aucune écriture dans les journaux ni dans la base.\n";
} catch (Throwable $error) {
    fwrite(STDERR, 'FAIL ' . $error->getMessage() . "\n");
    $exitCode = 1;
} finally {
    if (is_string($cookieFile) && is_file($cookieFile)) { @unlink($cookieFile); }
}
exit($exitCode);
