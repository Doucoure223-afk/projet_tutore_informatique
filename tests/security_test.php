<?php
/** Run: php -n tests/security_test.php */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../security/detector.php';
require_once __DIR__ . '/../security/logger.php';

$checks = 0;
$failures = [];
function check($condition, $message) {
    global $checks, $failures;
    $checks++;
    if (!$condition) { $failures[] = $message; }
}
$detector = new SQLInjectionDetector();
foreach (["' OR '1'='1", "1 OR 1=1", "1 UNION SELECT 1,2,3", "' UNION ALL SELECT password FROM users --", "'; DROP TABLE users", "1 OR SLEEP(5)", "1 AND 2<>3", "1 AND EXISTS(SELECT 1)", "' OR TRUE", "UN/**/ION SELECT 1", "1/**/OR/**/1=1", "/*!50000UNION*/ SELECT 1", "%2527%2520OR%2520%25271%2527%253D%25271", "UN%00ION SELECT 1", "1 AND updatexml(1,2,3)", "1; DELETE FROM users"] as $payload) {
    $result = $detector->analyzeWithScore($payload);
    check($result['block'] && $result['score'] >= 80 && $result['score'] <= 100, 'Malicious input not blocked: ' . $payload);
}
foreach (["clavier", "ordinateur", "C#", "Bonjour -- merci", "O'Reilly", "+223 (76) 12-34-56", "test@example.com", "0", "<script>alert('xss')</script>", "candy orange", "C++", "Une commande à Bamako"] as $payload) {
    $result = $detector->analyzeWithScore($payload);
    check(!$result['block'] && !$result['needs_ai'] && $result['score'] === 0, 'False positive: ' . $payload);
}
foreach (["admin' --", "admin' #", "SELECT name FROM users", "information_schema.tables"] as $payload) {
    $result = $detector->analyzeWithScore($payload);
    check(!$result['block'] && $result['needs_ai'] && $result['score'] >= 30 && $result['score'] < 80, 'Gray-zone routing failed: ' . $payload);
}
check($detector->analyzeWithScore('+223 76')['input_preview'] === '+223 76', 'Normalization destroys plus sign');
check($detector->analyzeWithScore('credential', 'password')['input_preview'] === '[REDACTED]', 'Sensitive preview exposed');
$detector->setBlockMode(false);
$result = $detector->analyzeWithScore('1 OR 1=1');
check(!$result['block'] && $result['would_block'] && $result['decision'] === 'MONITORED', 'Monitor mode still blocks');
$custom = new SQLInjectionDetector(null, ['block_threshold' => 60]);
check($custom->analyzeWithScore("admin' --")['block'], 'Configured threshold ignored');
check($detector->analyzeWithScore('1 UN/**/ION/**/SELECT 1')['would_block'], 'Mixed comment obfuscation evades detection');

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cybershield-test-' . bin2hex(random_bytes(8));
$file = $directory . DIRECTORY_SEPARATOR . 'events.jsonl';
try {
    $logger = new SecurityLogger($file);
    check($logger->getStats()['total'] === 0 && count($logger->getDailyStats()) === 7, 'Empty real stats are incorrect');
    $first = $logger->logEvent([
        'request_id' => 'blocked-1', 'action' => 'BLOCKED', 'attack_type' => 'SQL_INJECTION', 'score' => 90,
        'ip' => '::1', 'path' => '/app/login.php?password=path-secret', 'parameter' => 'password',
        'payload' => "super-secret\r\n[2099-01-01] forged event", 'reason' => "password=reason-secret\nblocked",
    ]);
    $duplicate = $logger->logEvent(['request_id' => 'blocked-1', 'action' => 'ALLOWED']);
    check($first === $duplicate && count($logger->getEvents()) === 1, 'Final event duplicated');
    check($first['payload'] === '[REDACTED]' && $first['path'] === '/app/login.php', 'Credential or query string leaked');
    $logger->logEvent([
        'request_id' => 'allowed-2', 'action' => 'ALLOWED', 'ip' => '127.0.0.1',
        'payload' => ['q' => "Bonjour\r\n[FORGED]", 'password' => 'nested-secret', 'csrf_token' => 'token-secret',
            'headers' => ['Cookie' => 'session-secret'], 'payment' => ['card_number' => '4111111111111111', 'cvv' => '123']],
    ]);
    $logger->logEvent(['request_id' => 'ai-3', 'action' => 'BLOCKED_BY_AI', 'attack_type' => 'COMMENT_INJECTION', 'score' => 60, 'risk' => 0.92, 'confidence' => 0.91, 'source' => 'ai', 'ip' => '::1', 'timestamp' => gmdate('c', strtotime('-1 day'))]);
    $logger->logEvent(['request_id' => 'monitor-4', 'action' => 'MONITORED', 'attack_type' => 'SQL_INJECTION', 'score' => 95]);
    $logger->logEvent(['request_id' => 'old-5', 'action' => 'BLOCKED', 'score' => 95, 'timestamp' => gmdate('c', strtotime('-8 days'))]);
    $logger->logEvent(['request_id' => 'csv-6', 'action' => 'ALLOWED', 'payload' => '=HYPERLINK("https://invalid.example")', 'reason' => '=HYPERLINK("https://invalid.example")']);
    $contents = file_get_contents($file);
    foreach (['super-secret', 'path-secret', 'reason-secret', 'nested-secret', 'token-secret', 'session-secret', '4111111111111111'] as $secret) {
        check(strpos($contents, $secret) === false, 'Secret leaked to log: ' . $secret);
    }
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    check(count($lines) === 6, 'CRLF forged extra event lines');
    foreach ($lines as $line) { check(is_array(json_decode($line, true)), 'Log entry is not valid JSON'); }
    $stats = $logger->getStats(7);
    check($stats['total'] === 5 && $stats['blocked'] === 2 && $stats['allowed'] === 2 && $stats['monitored'] === 1 && $stats['ai_analyzed'] === 1, 'Final-decision aggregate counts are incorrect');
    check(($stats['top_ips']['::1'] ?? 0) === 2, 'IPv6 aggregation failed');
    $daily = $logger->getDailyStats(7);
    check(count($daily) === 7 && array_sum(array_column($daily, 'total')) === 5 && $daily[0]['total'] === 0, 'Daily history contains invented data or misses real events');
    check(count($logger->getEvents(['action' => 'BLOCKED_BY_AI'])) === 1, 'Action filter failed');
    check(count($logger->getEvents(['type' => 'COMMENT_INJECTION', 'ip' => '::1'])) === 1, 'Type/IP filter failed');
    check(count($logger->getEvents(['from' => gmdate('Y-m-d'), 'to' => gmdate('Y-m-d')])) === 4, 'Date filter failed');
    check(count($logger->getEvents(['search' => 'COMMENT_INJECTION'])) === 1, 'Search filter failed');
    check(strpos($logger->exportCsv(), "'=HYPERLINK") !== false, 'CSV formula injection not neutralized');
    $csvEvent = $logger->getEvents(['search' => 'csv-6'], 1)[0];
    check($csvEvent['payload'] !== '=HYPERLINK("https://invalid.example")', 'Raw payload formula leaked into event');
    check(substr_count(trim($logger->exportCsv(['action' => 'BLOCKED_BY_AI'])), "\n") === 1, 'CSV export does not apply filters');
    try {
        $logger->logEvent(['request_id' => 'pending-7', 'action' => 'PENDING_IA']);
        check(false, 'Pending intermediate decision was accepted');
    } catch (InvalidArgumentException $expected) {
        check(true, 'Pending decision rejected');
    }
    check($logger->redact('token=abc&username=alice') === 'token=[REDACTED]&username=alice', 'Inline secret redaction failed');
    check($logger->redact('4111 1111 1111 1111') === '[REDACTED_CARD]', 'Card-number redaction failed');
    check(strpos($logger->redact('{"password":"json-secret"}'), 'json-secret') === false, 'Quoted JSON credential not redacted');
} finally {
    // Delete only the test file and the unique directory created above.
    if (is_file($file)) { unlink($file); }
    if (is_dir($directory)) { rmdir($directory); }
}
if ($failures) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    fwrite(STDERR, count($failures) . ' failure(s) / ' . $checks . ' checks' . PHP_EOL);
    exit(1);
}
echo 'OK: ' . $checks . ' security checks passed.' . PHP_EOL;
