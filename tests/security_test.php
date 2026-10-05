<?php
/** Run: php -n tests/security_test.php */
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require_once __DIR__ . '/../security/detector.php';
require_once __DIR__ . '/../security/logger.php';
require_once __DIR__ . '/../security/hybrid_analyzer.php';
require_once __DIR__ . '/../security/ip_access.php';
require_once __DIR__ . '/../security/middleware.php';
require_once __DIR__ . '/../app/AdminTotp.php';
require_once __DIR__ . '/../app/LoginThrottle.php';
require_once __DIR__ . '/../app/DatabasePassword.php';

$checks = 0;
$failures = [];
$hybridConfig = ['block_mode' => true, 'block_threshold' => 80, 'review_threshold' => 30];
$fakeAi = new class extends AIAnalyzer {
    public function __construct() {}
    public function analyze($input, $context = 'unknown'): array
    {
        return ['risk' => 0.90, 'confidence' => 0.90, 'model_version' => 'test-model'];
    }
    public function shouldBlock($result): bool { return $result['risk'] >= 0.75; }
};
$hybrid = new HybridAnalyzer(new SQLInjectionDetector(null, $hybridConfig), $fakeAi, $hybridConfig);
$lowRiskWithoutPrescreen = $hybrid->analyze('Bonjour Bamako', 'GET[q]', 'search', true, false);
check(!$lowRiskWithoutPrescreen['needs_ai'] && $lowRiskWithoutPrescreen['source'] === 'heuristic', 'Optional MLP pre-screen changed the rule-only path');
$lowRiskWithPrescreen = $hybrid->analyze('Bonjour Bamako', 'GET[q]', 'search', true, true);
check($lowRiskWithPrescreen['needs_ai'] && $lowRiskWithPrescreen['source'] === 'mlp' && $lowRiskWithPrescreen['block'], 'Bounded MLP pre-screen skipped an unflagged value');
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
check(cybershield_is_sensitive_parameter('POST[password_confirmation]'), 'Password confirmation marked sensitive');
check(cybershield_is_sensitive_parameter('POST[totp_code]'), 'One-time code marked sensitive');
check(cybershield_is_sensitive_parameter('COOKIE[PHPSESSID]'), 'Session cookie marked sensitive');
check(!cybershield_is_sensitive_parameter('GET[search]'), 'Normal search input remains eligible for analysis');
$oldContainerized = getenv('CYBERSHIELD_CONTAINERIZED');
putenv('CYBERSHIELD_CONTAINERIZED');
try {
    new AIAnalyzer(['url' => 'http://ai:5000']);
    check(false, 'Container-only AI hostname was accepted by the local Wamp configuration');
} catch (InvalidArgumentException $expected) {
    check(true, 'AI endpoint rejects non-loopback hosts outside Docker');
}
putenv('CYBERSHIELD_CONTAINERIZED=1');
try {
    new AIAnalyzer(['url' => 'http://ai:5000']);
    check(true, 'Private Compose AI service hostname was rejected');
} catch (InvalidArgumentException $unexpected) {
    check(false, 'Private Compose AI service hostname was rejected');
}
if ($oldContainerized === false) { putenv('CYBERSHIELD_CONTAINERIZED'); }
else { putenv('CYBERSHIELD_CONTAINERIZED=' . $oldContainerized); }
check(AdminTotp::codeAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59) === '287082', 'TOTP matches the RFC 6238 SHA-1 vector');
check(AdminTotp::verify('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '287082', 59), 'TOTP accepts current time step');
check(!AdminTotp::verify('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', '000000', 59), 'TOTP rejects an incorrect code');
check($detector->analyzeWithScore('123456', 'totp_code')['input_preview'] === '[REDACTED]', 'TOTP preview is redacted');

$directory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'cybershield-test-' . bin2hex(random_bytes(8));
$file = $directory . DIRECTORY_SEPARATOR . 'events.jsonl';
$ipDirectory = $directory . DIRECTORY_SEPARATOR . 'ip-policy';
$databaseSecretFile = $directory . DIRECTORY_SEPARATOR . 'db-password-test.txt';
try {
    $logger = new SecurityLogger($file);
    $originalPasswordFile = getenv('DB_PASSWORD_FILE');
    $originalPassword = getenv('DB_PASSWORD');
    file_put_contents($databaseSecretFile, "mounted-db-secret\r\n");
    putenv('DB_PASSWORD_FILE=' . $databaseSecretFile);
    check(cybershield_database_password() === 'mounted-db-secret', 'Mounted database password was not read safely');
    file_put_contents($databaseSecretFile, '');
    try {
        cybershield_database_password();
        check(false, 'Empty mounted database secret was accepted');
    } catch (RuntimeException $expected) {
        check(true, 'Empty mounted database secret fails closed');
    }
    if ($originalPasswordFile === false) { putenv('DB_PASSWORD_FILE'); }
    else { putenv('DB_PASSWORD_FILE=' . $originalPasswordFile); }
    if ($originalPassword === false) { putenv('DB_PASSWORD'); }
    else { putenv('DB_PASSWORD=' . $originalPassword); }
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
    $logger->logEvent(['request_id' => 'mfa-2b', 'action' => 'BLOCKED', 'parameter' => 'POST[totp_code]', 'payload' => '123456']);
    $logger->logEvent(['request_id' => 'ai-3', 'action' => 'BLOCKED_BY_AI', 'attack_type' => 'COMMENT_INJECTION', 'score' => 60, 'risk' => 0.92, 'confidence' => 0.91, 'source' => 'ai', 'ip' => '::1', 'timestamp' => gmdate('c', strtotime('-1 day'))]);
    $logger->logEvent(['request_id' => 'monitor-4', 'action' => 'MONITORED', 'attack_type' => 'SQL_INJECTION', 'score' => 95]);
    $logger->logEvent(['request_id' => 'old-5', 'action' => 'BLOCKED', 'score' => 95, 'timestamp' => gmdate('c', strtotime('-8 days'))]);
    $logger->logEvent(['request_id' => 'csv-6', 'action' => 'ALLOWED', 'payload' => '=HYPERLINK("https://invalid.example")', 'reason' => '=HYPERLINK("https://invalid.example")']);
    $contents = file_get_contents($file);
    foreach (['super-secret', 'path-secret', 'reason-secret', 'nested-secret', 'token-secret', 'session-secret', '4111111111111111', '123456'] as $secret) {
        check(strpos($contents, $secret) === false, 'Secret leaked to log: ' . $secret);
    }
    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    check(count($lines) === 7, 'CRLF forged extra event lines');
    foreach ($lines as $line) { check(is_array(json_decode($line, true)), 'Log entry is not valid JSON'); }
    $stats = $logger->getStats(7);
    check($stats['total'] === 6 && $stats['blocked'] === 3 && $stats['allowed'] === 2 && $stats['monitored'] === 1 && $stats['ai_analyzed'] === 1, 'Final-decision aggregate counts are incorrect');
    check(($stats['top_ips']['::1'] ?? 0) === 2, 'IPv6 aggregation failed');
    $daily = $logger->getDailyStats(7);
    check(count($daily) === 7 && array_sum(array_column($daily, 'total')) === 6 && $daily[0]['total'] === 0, 'Daily history contains invented data or misses real events');
    check(count($logger->getEvents(['action' => 'BLOCKED_BY_AI'])) === 1, 'Action filter failed');
    check(count($logger->getEvents(['type' => 'COMMENT_INJECTION', 'ip' => '::1'])) === 1, 'Type/IP filter failed');
    check(count($logger->getEvents(['from' => gmdate('Y-m-d'), 'to' => gmdate('Y-m-d')])) === 5, 'Date filter failed');
    check(count($logger->getEvents(['search' => 'COMMENT_INJECTION'])) === 1, 'Search filter failed');
    check(strpos($logger->exportCsv(), "'=HYPERLINK") !== false, 'CSV formula injection not neutralized');
    $csvEvent = $logger->getEvents(['search' => 'csv-6'], 1)[0];
    check($csvEvent['payload'] !== '=HYPERLINK("https://invalid.example")', 'Raw payload formula leaked into event');
    check(substr_count(trim($logger->exportCsv(['action' => 'BLOCKED_BY_AI'])), "\n") === 1, 'CSV export does not apply filters');
    $jsonlLines = array_values(array_filter(explode("\n", trim($logger->exportJsonLines(['action' => 'BLOCKED_BY_AI'])))));
    check(count($jsonlLines) === 1 && (json_decode($jsonlLines[0], true)['action'] ?? '') === 'BLOCKED_BY_AI', 'JSONL export does not preserve valid filtered events');
    $throttleDirectory = $directory . DIRECTORY_SEPARATOR . 'throttle';
    $throttle = new LoginThrottle($throttleDirectory);
    $throttleAllows = true;
    for ($attempt = 0; $attempt < 5; $attempt++) { $throttleAllows = $throttle->beginAttempt('admin@example.invalid', '192.0.2.25'); }
    check($throttleAllows && !$throttle->beginAttempt('admin@example.invalid', '192.0.2.25'), 'Login attempt limit did not activate on the sixth try');
    check($throttle->beginAttempt('admin@example.invalid', '192.0.2.26'), 'Login attempt limit crossed client IPs unexpectedly');
    check(strpos(file_get_contents($throttleDirectory . DIRECTORY_SEPARATOR . 'login-attempts.json'), 'admin@example.invalid') === false, 'Login throttle stored a clear-text identifier');
    $throttle->clear('admin@example.invalid', '192.0.2.25');
    check($throttle->beginAttempt('admin@example.invalid', '192.0.2.25'), 'Successful-login reset did not clear the attempt window');
    $oldSiemUrl = getenv('CYBERSHIELD_SIEM_URL');
    putenv('CYBERSHIELD_SIEM_URL=https://collector.example.invalid/events');
    $siemLog = $directory . DIRECTORY_SEPARATOR . 'siem-test' . DIRECTORY_SEPARATOR . 'events.jsonl';
    $siemLogger = new SecurityLogger($siemLog);
    $siemLogger->logEvent(['request_id' => 'd4e8cdb6258d4c59a6da152b2a9d459a', 'action' => 'BLOCKED', 'attack_type' => 'SQL_INJECTION',
        'score' => 95, 'parameter' => 'GET[q]', 'payload' => "' OR '1'='1 --"]);
    $siemQueue = $directory . DIRECTORY_SEPARATOR . 'siem-test' . DIRECTORY_SEPARATOR . 'siem-outbox';
    $queued = glob($siemQueue . DIRECTORY_SEPARATOR . '*.json') ?: [];
    check(count($queued) === 1 && (json_decode(file_get_contents($queued[0]), true)['action'] ?? '') === 'BLOCKED',
        'Security alert was not queued for asynchronous SIEM delivery');
    check(strpos(file_get_contents($queued[0]), "' OR '1'='1 --") === false,
        'SIEM queue included a raw request payload');
    $siemLogger->logEvent(['request_id' => '7cd0fd5522634f58abdf8b75bf8d2ab6', 'action' => 'ALLOWED', 'score' => 0]);
    check(count(glob($siemQueue . DIRECTORY_SEPARATOR . '*.json') ?: []) === 1, 'Low-risk allowed traffic was unnecessarily queued for SIEM');
    if ($oldSiemUrl === false) { putenv('CYBERSHIELD_SIEM_URL'); }
    else { putenv('CYBERSHIELD_SIEM_URL=' . $oldSiemUrl); }
    try {
        $logger->logEvent(['request_id' => 'pending-7', 'action' => 'PENDING_IA']);
        check(false, 'Pending intermediate decision was accepted');
    } catch (InvalidArgumentException $expected) {
        check(true, 'Pending decision rejected');
    }
    check($logger->redact('token=abc&username=alice') === 'token=[REDACTED]&username=alice', 'Inline secret redaction failed');
    check($logger->redact('4111 1111 1111 1111') === '[REDACTED_CARD]', 'Card-number redaction failed');
    check(strpos($logger->redact('{"password":"json-secret"}'), 'json-secret') === false, 'Quoted JSON credential not redacted');

    $ipAccess = new IpAccessControl($ipDirectory);
    check($ipAccess->listRules() === [], 'IP policy should start empty');
    $ipAccess->addRule('192.0.2.10', "repeat offender\ninternal note");
    check($ipAccess->isBlocked('192.0.2.10') && !$ipAccess->isBlocked('192.0.2.11'), 'IPv4 deny rule does not match exactly');
    check($ipAccess->listRules()[0]['comment'] === 'repeat offender internal note', 'IP rule comment was not sanitized');
    $ipAccess->addRule('2001:0db8::1', 'IPv6 test');
    check($ipAccess->isBlocked('2001:db8:0:0:0:0:0:1') && $ipAccess->listRules()[0]['ip_address'] === '192.0.2.10', 'IPv6 canonicalization or rule ordering failed');
    try {
        $ipAccess->addRule('192.0.2.10/24');
        check(false, 'CIDR range was accepted as an individual IP');
    } catch (InvalidArgumentException $expected) {
        check(true, 'CIDR range rejected');
    }
    check($ipAccess->removeRule('192.0.2.10') && !$ipAccess->isBlocked('192.0.2.10'), 'IP rule removal failed');
    file_put_contents($ipDirectory . DIRECTORY_SEPARATOR . 'blocked-ips.json', '{invalid');
    try {
        $ipAccess->isBlocked('192.0.2.10');
        check(false, 'Corrupt IP policy did not fail closed');
    } catch (RuntimeException $expected) {
        check(true, 'Corrupt IP policy fails closed');
    }
} finally {
    // Delete only the test file and the unique directory created above.
    if (is_file($file)) { unlink($file); }
    if (is_file($databaseSecretFile)) { unlink($databaseSecretFile); }
    foreach (['blocked-ips.json', 'blocked-ips.json.lock'] as $ipFile) {
        $path = $ipDirectory . DIRECTORY_SEPARATOR . $ipFile;
        if (is_file($path)) { unlink($path); }
    }
    $throttleFile = $directory . DIRECTORY_SEPARATOR . 'throttle' . DIRECTORY_SEPARATOR . 'login-attempts.json';
    if (is_file($throttleFile)) { unlink($throttleFile); }
    if (is_dir(dirname($throttleFile))) { rmdir(dirname($throttleFile)); }
    $siemTestDirectory = $directory . DIRECTORY_SEPARATOR . 'siem-test';
    $siemOutbox = $siemTestDirectory . DIRECTORY_SEPARATOR . 'siem-outbox';
    foreach (glob($siemOutbox . DIRECTORY_SEPARATOR . '*') ?: [] as $queuedFile) { if (is_file($queuedFile)) { unlink($queuedFile); } }
    if (is_dir($siemOutbox)) { rmdir($siemOutbox); }
    $siemEvents = $siemTestDirectory . DIRECTORY_SEPARATOR . 'events.jsonl';
    if (is_file($siemEvents)) { unlink($siemEvents); }
    foreach (['access.jsonl', 'ia_analysis.jsonl', 'errors.jsonl'] as $auxiliaryLog) {
        $path = $siemTestDirectory . DIRECTORY_SEPARATOR . $auxiliaryLog;
        if (is_file($path)) { unlink($path); }
    }
    if (is_dir($siemTestDirectory)) { rmdir($siemTestDirectory); }
    if (is_dir($ipDirectory)) { rmdir($ipDirectory); }
    if (is_dir($directory)) { rmdir($directory); }
}
if ($failures) {
    fwrite(STDERR, implode(PHP_EOL, $failures) . PHP_EOL);
    fwrite(STDERR, count($failures) . ' failure(s) / ' . $checks . ' checks' . PHP_EOL);
    exit(1);
}
echo 'OK: ' . $checks . ' security checks passed.' . PHP_EOL;
