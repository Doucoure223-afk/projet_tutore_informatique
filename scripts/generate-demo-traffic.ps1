param(
    [ValidateRange(1, 65535)] [int] $Port = 8080,
    [switch] $PreflightOnly
)

# Six real requests to this installation only. The script never writes security
# events itself and never clears existing data. Inferences are measured first.
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw 'Docker est absent du PATH. Demarre Docker Desktop puis relance ce script.'
}

function Invoke-DemoPhp([string] $Code) {
    # Read runtime events with their owning account. The hardened container's
    # root account intentionally cannot bypass the journal's 0600 permissions.
    $lines = @($Code | & docker compose exec --user www-data -T web php)
    if ($LASTEXITCODE -ne 0) { throw 'Le controle interne PHP a echoue. Aucun evenement artificiel ne sera ajoute.' }
    try { return ($lines -join "`n") | ConvertFrom-Json }
    catch { throw 'Le controle interne ne retourne pas un resultat JSON valide.' }
}

Push-Location $projectRoot
try {
    $preflightCode = @'
<?php
require '/var/www/html/security/hybrid_analyzer.php';
$config = require '/var/www/html/config/security.php';
$health = (new AIAnalyzer())->health();
$cases = [
    ['normal', 'Recherche ordinaire', 'casque', false, 'heuristic'],
    ['rule_boolean', 'Condition booleenne explicite', "' OR 1=1 -- ", true, 'heuristic'],
    ['rule_union', 'Signature UNION SELECT', '1 UNION SELECT 1,2,3', true, 'heuristic'],
    ['mlp_comment', 'Commentaire apres apostrophe', "admin'-- ", true, 'mlp'],
    ['mlp_catalog', 'Reference au catalogue systeme', 'information_schema.tables', true, 'mlp'],
    ['mlp_select', 'Lecture SQL soumise comme recherche', 'SELECT name FROM users', true, 'mlp'],
];
$analyzer = new HybridAnalyzer();
$scenarios = [];
foreach ($cases as [$name, $label, $payload, $expectedBlock, $expectedSource]) {
    $result = $analyzer->analyze($payload, 'GET[q]', 'search', true, true);
    $scenarios[] = [
        'name' => $name, 'label' => $label, 'payload' => $payload,
        'expected_block' => $expectedBlock, 'expected_source' => $expectedSource,
        'score' => $result['score'], 'source' => $result['source'],
        'risk' => $result['risk'], 'would_block' => $result['would_block'],
        'ai_status' => $result['ai_status'], 'model_version' => $result['model_version'],
    ];
}
echo json_encode([
    'block_mode' => $config['block_mode'],
    'model_loaded' => ($health['model_loaded'] ?? false) === true,
    'model_version' => $health['model_version'] ?? null,
    'scenarios' => $scenarios,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
'@
    $preflight = Invoke-DemoPhp $preflightCode
    if (-not $preflight.model_loaded) { throw 'Le MLP local est indisponible. Aucune requete de demonstration n a ete envoyee.' }
    foreach ($scenario in $preflight.scenarios) {
        if ($scenario.source -eq 'fail_safe' -or [bool] $scenario.would_block -ne [bool] $scenario.expected_block) {
            throw ('Precontrole inattendu pour ' + $scenario.name + '. Rien ne sera presente comme un blocage MLP non verifie.')
        }
        if ($scenario.expected_block -and $scenario.source -ne $scenario.expected_source) {
            throw ('La source de decision a change pour ' + $scenario.name + '. Verifie le modele et les regles avant la demonstration.')
        }
        if ($scenario.expected_source -eq 'mlp' -and ($scenario.ai_status -ne 'available' -or [double] $scenario.risk -lt 0.75)) {
            throw ('Le MLP ne confirme pas le scenario ' + $scenario.name + '. Aucune requete de demonstration envoyee.')
        }
    }
    Write-Host ('MLP disponible : ' + $preflight.model_version + '. Les six scenarios sont verifies sans journalisation pendant ce precontrole.')
    if ($PreflightOnly) {
        $preflight.scenarios | Select-Object name, score, source, risk, would_block | Format-Table -AutoSize
        Write-Host ('Mode blocage : ' + [bool] $preflight.block_mode + '. Aucun trafic HTTP genere.')
        return
    }
    if (-not $preflight.block_mode) {
        throw 'Le site est en observation. Active CYBERSHIELD_MODE=block et recree web avant de lancer les vraies requetes.'
    }

    Add-Type -AssemblyName System.Net.Http
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(10)
    $client.DefaultRequestHeaders.Accept.ParseAdd('application/json')
    $client.DefaultRequestHeaders.UserAgent.ParseAdd('CyberShield-Demo/1.0')
    $baseUrl = 'http://127.0.0.1:' + $Port
    $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $responses = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($scenario in $preflight.scenarios) {
            # q precedes the harmless marker so the same bounded AI-call budget
            # and input order are used on every request. No cookies/auth are sent.
            $url = $baseUrl + '/app/search.php?q=' + [Uri]::EscapeDataString([string] $scenario.payload) + '&cybershield_demo=' + [Uri]::EscapeDataString($runId)
            $response = $null
            try {
                $response = $client.GetAsync($url).GetAwaiter().GetResult()
                $status = [int] $response.StatusCode
                $requestId = ''
                if ($response.Headers.Contains('X-CyberShield-Request-ID')) {
                    $requestId = [string] (@($response.Headers.GetValues('X-CyberShield-Request-ID'))[0])
                }
                $bodyIncidentId = ''
                if ($status -eq 403) {
                    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    try { $bodyIncidentId = [string] (($body | ConvertFrom-Json).incident_id) } catch { }
                    if ($requestId -eq '') { $requestId = $bodyIncidentId }
                }
                $responses.Add([pscustomobject] @{
                    scenario = $scenario.name; label = $scenario.label
                    payload = $scenario.payload; http_status = $status
                    request_id = $requestId; response_incident_id = $bodyIncidentId
                    error = ''
                })
                Write-Host ($scenario.label + ' : HTTP ' + $status + ', reference ' + $requestId)
            } catch {
                $responses.Add([pscustomobject] @{
                    scenario = $scenario.name; label = $scenario.label
                    payload = $scenario.payload; http_status = 0; request_id = ''
                    response_incident_id = ''; error = $_.Exception.GetType().Name
                })
            } finally { if ($null -ne $response) { $response.Dispose() } }
        }
    } finally { $client.Dispose(); $handler.Dispose() }

    $ids = @($responses | Where-Object { $_.request_id -match '^[a-f0-9]{32}$' } | ForEach-Object { $_.request_id })
    $idsJson = ConvertTo-Json -InputObject $ids -Compress
    $encodedIds = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($idsJson))
    $readEventsCode = @'
<?php
$wanted = array_fill_keys(json_decode(base64_decode('__IDS__'), true, 8, JSON_THROW_ON_ERROR), true);
$config = require '/var/www/html/config/security.php';
$handle = fopen(rtrim($config['log_dir'], '/\\') . '/events.jsonl', 'rb');
if (!$handle || !flock($handle, LOCK_SH)) { throw new RuntimeException('Journal inaccessible.'); }
$fields = ['request_id','timestamp','ip','path','parameter','action','source','score','risk','ai_status','model_version','attack_type','rule_id'];
$events = [];
try {
    while (($line = fgets($handle)) !== false) {
        $event = json_decode($line, true);
        if (is_array($event) && isset($wanted[$event['request_id'] ?? ''])) {
            $events[$event['request_id']] = array_intersect_key($event, array_fill_keys($fields, true));
        }
    }
    flock($handle, LOCK_UN);
} finally { fclose($handle); }
echo json_encode((object) $events, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
'@
    $events = Invoke-DemoPhp ($readEventsCode.Replace('__IDS__', $encodedIds))
    $checks = [System.Collections.Generic.List[object]]::new()
    $allPassed = $true
    foreach ($response in $responses) {
        $scenario = @($preflight.scenarios | Where-Object { $_.name -eq $response.scenario })[0]
        $event = $null
        if ($response.request_id -match '^[a-f0-9]{32}$') {
            $property = $events.PSObject.Properties[$response.request_id]
            if ($null -ne $property) { $event = $property.Value }
        }
        $expectedStatus = if ($scenario.expected_block) { 403 } else { 200 }
        $expectedAction = if (-not $scenario.expected_block) { 'ALLOWED' } elseif ($scenario.expected_source -eq 'mlp') { 'BLOCKED_BY_AI' } else { 'BLOCKED' }
        $passed = $null -ne $event -and $response.http_status -eq $expectedStatus -and $event.action -eq $expectedAction -and $event.source -eq $scenario.expected_source -and $event.path -eq '/app/search.php'
        if ($scenario.expected_block) { $passed = $passed -and $response.response_incident_id -eq $response.request_id }
        if ($scenario.expected_source -eq 'mlp') { $passed = $passed -and $event.ai_status -eq 'available' -and [double] $event.risk -ge 0.75 -and $event.model_version -eq $preflight.model_version }
        if (-not $passed) { $allPassed = $false }
        $checks.Add([pscustomobject] @{
            scenario = $response.scenario; label = $response.label; payload = $response.payload
            passed = [bool] $passed; http_status = $response.http_status
            request_id = $response.request_id; expected_action = $expectedAction
            preflight = $scenario; event = $event; error = $response.error
        })
    }
    $report = [ordered] @{
        kind = 'controlled_demo_traffic'; run_id = $runId
        generated_at_utc = [DateTime]::UtcNow.ToString('o'); base_url = $baseUrl
        description = 'Requetes HTTP de test reelles. Decisions mesurees et rapprochees des evenements generes par le middleware. Aucun trafic client reel revendique.'
        passed = $allPassed; sent = $responses.Count
        blocked_by_rules = @($checks | Where-Object { $_.passed -and $_.event.action -eq 'BLOCKED' -and $_.event.source -eq 'heuristic' }).Count
        blocked_by_mlp = @($checks | Where-Object { $_.passed -and $_.event.action -eq 'BLOCKED_BY_AI' -and $_.event.source -eq 'mlp' }).Count
        allowed = @($checks | Where-Object { $_.passed -and $_.event.action -eq 'ALLOWED' }).Count
        checks = $checks.ToArray()
    }
    $reportDirectory = Join-Path $projectRoot 'tmp'
    [void] (New-Item -ItemType Directory -Force -Path $reportDirectory)
    $reportPath = Join-Path $reportDirectory ('demo-traffic-' + $runId + '.json')
    [IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Write-Host ('Rapport verifiable : ' + $reportPath)
    if (-not $allPassed) { throw 'Au moins une reponse ou sa trace ne correspond pas au scenario attendu. Consulte le rapport ; les evenements existants sont conserves.' }
    Write-Host 'Verification terminee : 1 autorisation, 2 blocages par regles et 3 blocages par le MLP local.'
    Write-Host ('Actualise ' + $baseUrl + '/security/dashboard.php puis ouvre les details des references affichees.')
} finally { Pop-Location }
