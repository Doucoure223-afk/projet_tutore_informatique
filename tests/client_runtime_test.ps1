param(
    [string] $CachedWebImage = '',
    [string] $CachedAiImage = '',
    [string] $CachedAssistantImage = '',
    [string] $ReportPath = (Join-Path $PSScriptRoot '../tmp/client-runtime-report.json'),
    [switch] $KeepRunning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tempParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char[]]@('\', '/'))
$runId = [guid]::NewGuid().ToString('N').Substring(0, 12)
$testRoot = Join-Path $tempParent ('CyberShield-acceptance-' + $runId)
New-Item -ItemType Directory -Path $testRoot | Out-Null
$cached = $CachedWebImage -ne '' -or $CachedAiImage -ne '' -or $CachedAssistantImage -ne ''
if ($cached -and ($CachedWebImage -eq '' -or $CachedAiImage -eq '' -or $CachedAssistantImage -eq '')) {
    throw 'Le mode cache exige les trois images web, MLP et assistant.'
}
$clients = @()
$checks = [System.Collections.Generic.List[string]]::new()
$passed = $false

function Assert-Test([bool] $condition, [string] $description) {
    if (-not $condition) { throw "ÉCHEC : $description" }
    $checks.Add($description)
    Write-Output "OK $description"
}

function Get-FreePort {
    $socket = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try { $socket.Start(); return ([System.Net.IPEndPoint]$socket.LocalEndpoint).Port }
    finally { $socket.Stop() }
}

function Invoke-TestCompose($client, [string[]] $arguments) {
    if ($client.compose_project -notmatch '^cybershield-accept-[a-f0-9]{12}-[ab]$' -or
        -not $client.working_directory.StartsWith($testRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Commande Docker refusée hors des installations jetables de cet essai.'
    }
    & docker compose --project-name $client.compose_project --project-directory $client.working_directory `
        --env-file (Join-Path $client.working_directory '.env') `
        -f (Join-Path $client.working_directory 'compose.yaml') -f $client.override_file @arguments
    if ($LASTEXITCODE -ne 0) { throw "Échec Compose dans $($client.compose_project)." }
}

function Get-HttpStatus([string] $url) {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.AllowAutoRedirect = $false
    $http = [System.Net.Http.HttpClient]::new($handler)
    $http.Timeout = [TimeSpan]::FromSeconds(5)
    try {
        $response = $http.GetAsync($url).GetAwaiter().GetResult()
        return [int]$response.StatusCode
    } finally { $http.Dispose(); $handler.Dispose() }
}

function Write-Report {
    $report = [ordered]@{
        schema_version = 1
        disposable = $true
        passed = $passed
        mode = $(if ($cached) { 'cached-runtime-with-current-package-source' } else { 'source-build-from-generated-packages' })
        kept_running = [bool]($passed -and $KeepRunning)
        root = $testRoot
        checks = @($checks.ToArray())
        clients = @($clients)
    }
    $destination = [System.IO.Path]::GetFullPath($ReportPath)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destination) | Out-Null
    [System.IO.File]::WriteAllText($destination, ($report | ConvertTo-Json -Depth 12), [System.Text.UTF8Encoding]::new($false))
}

try {
    foreach ($id in @('a', 'b')) {
        $port = Get-FreePort
        while ($port -in @(8080, 8081, 8082) -or @($clients | Where-Object { $_.port -eq $port }).Count -gt 0) { $port = Get-FreePort }
        $directory = Join-Path $testRoot ('client-' + $id)
        $composeProject = 'cybershield-accept-' + $runId + '-' + $id
        & (Join-Path $projectRoot 'scripts/new-client-deployment.ps1') -ClientId ('accept-' + $runId + '-' + $id) -Destination $directory -Port $port | Out-Host
        & (Join-Path $directory 'scripts/init-docker.ps1') | Out-Host
        $environmentPath = Join-Path $directory '.env'
        $environment = [System.IO.File]::ReadAllText($environmentPath)
        $environment = $environment -replace '(?m)^COMPOSE_PROJECT_NAME=.*$', ('COMPOSE_PROJECT_NAME=' + $composeProject)
        [System.IO.File]::WriteAllText($environmentPath, $environment, [System.Text.UTF8Encoding]::new($false))

        $testDirectory = Join-Path $directory 'tests'
        foreach ($name in @('store_money_test.php', 'orders_test.php', 'client_identity_test.php',
            'assistant_integration_test.php', 'cinetpay_test.php')) {
            $source = Join-Path $PSScriptRoot $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Test requis absent : $name" }
            Copy-Item -LiteralPath $source -Destination (Join-Path $testDirectory $name)
        }
        $testMount = @{ type = 'bind'; source = $testDirectory.Replace('\', '/'); target = '/var/www/html/tests'; read_only = $true }
        $services = @{
            web = @{ environment = @{ CYBERSHIELD_READINESS_DISPOSABLE = '1'; CYBERSHIELD_MODE = 'block'; CYBERSHIELD_DOCKER_SETUP_PEER = '' }; volumes = @($testMount) }
            assistant = @{ environment = @{ OLLAMA_BASE_URL = 'http://127.0.0.1:11434' } }
        }
        $fixtures = Join-Path $projectRoot 'scripts/perftests/fixtures'
        if (Test-Path -LiteralPath $fixtures -PathType Container) {
            $services.web.volumes += @{ type = 'bind'; source = $fixtures.Replace('\', '/'); target = '/var/www/html/__readiness'; read_only = $true }
        }
        if ($cached) {
            foreach ($image in @($CachedWebImage, $CachedAiImage, $CachedAssistantImage)) {
                & docker image inspect $image --format '{{.Id}}' | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "Image de cache absente : $image" }
            }
            $services.web.image = $CachedWebImage
            foreach ($folder in @('app', 'security', 'config')) {
                $services.web.volumes += @{ type = 'bind'; source = (Join-Path $directory $folder).Replace('\', '/'); target = ('/var/www/html/' + $folder); read_only = $true }
            }
            foreach ($file in @('index.php', '.htaccess')) {
                $services.web.volumes += @{ type = 'bind'; source = (Join-Path $directory $file).Replace('\', '/'); target = ('/var/www/html/' + $file); read_only = $true }
            }
            $services.ai = @{ image = $CachedAiImage; volumes = @() }
            foreach ($file in @('service.py', 'features.py')) {
                $services.ai.volumes += @{ type = 'bind'; source = (Join-Path $directory ('ia/' + $file)).Replace('\', '/'); target = ('/opt/cybershield/ia/' + $file); read_only = $true }
            }
            $services.assistant.image = $CachedAssistantImage
            $services.assistant.volumes = @()
            foreach ($file in @('assistant_core.py', 'assistant_graph.py', 'assistant_service.py')) {
                $services.assistant.volumes += @{ type = 'bind'; source = (Join-Path $directory ('ia/' + $file)).Replace('\', '/'); target = ('/opt/cybershield-assistant/' + $file); read_only = $true }
            }
        }
        $override = Join-Path $directory 'compose.acceptance.json'
        [System.IO.File]::WriteAllText($override, (@{ services = $services } | ConvertTo-Json -Depth 12), [System.Text.UTF8Encoding]::new($false))
        $client = [ordered]@{
            id = $id; port = $port; base_url = "http://127.0.0.1:$port"
            compose_project = $composeProject; working_directory = $directory; override_file = $override
            containers = @{ web = "$composeProject-web-1"; ai = "$composeProject-ai-1"; db = "$composeProject-db-1"; assistant = "$composeProject-assistant-1" }
        }
        $clients += $client
        if (-not $cached) { Invoke-TestCompose $client @('--profile', 'assistant', 'build', 'web', 'ai', 'assistant') | Out-Host }
        Invoke-TestCompose $client @('up', '-d', '--no-build', 'db', 'ai', 'web') | Out-Host
        # Fast local assistant replies need the actual LangGraph service, not a downloaded LLM.
        Invoke-TestCompose $client @('--profile', 'assistant', 'up', '-d', '--no-build', '--no-deps', 'assistant') | Out-Host

        $ready = $false
        for ($attempt = 0; $attempt -lt 120; $attempt++) {
            try { if ((Get-HttpStatus ($client.base_url + '/app/search.php')) -eq 200) { $ready = $true; break } } catch { }
            Start-Sleep -Milliseconds 500
        }
        Assert-Test $ready "Client $id : catalogue HTTP disponible sur une base neuve"
        Assert-Test ((Get-HttpStatus ($client.base_url + '/app/setup.php')) -eq 200) "Client $id : configuration initiale locale disponible"
        Assert-Test ((Get-HttpStatus ($client.base_url + '/security/dashboard.php')) -eq 200) "Client $id : console et identité client disponibles"

        foreach ($test in @('store_money_test.php', 'orders_test.php', 'client_identity_test.php', 'cinetpay_test.php')) {
            Invoke-TestCompose $client @('exec', '--user', 'www-data', '-T', 'web', 'php', ('/var/www/html/tests/' + $test)) | Out-Host
            Assert-Test $true "Client $id : $test"
        }
        Invoke-TestCompose $client @('exec', '--user', 'www-data', '-T', 'web', 'php', '/var/www/html/tests/orders_test.php', '--database') | Out-Host
        Assert-Test $true "Client $id : commandes et stock avec tables SQL temporaires"
        Invoke-TestCompose $client @('exec', '--user', 'www-data', '-T', 'web', 'php', '/var/www/html/tests/assistant_integration_test.php') | Out-Host
        Assert-Test $true "Client $id : assistant HTTP, ressources, CSRF et réponses rapides réelles"
    }

    $hashA = (Get-FileHash -LiteralPath (Join-Path $clients[0].working_directory 'secrets/db_password.txt')).Hash
    $hashB = (Get-FileHash -LiteralPath (Join-Path $clients[1].working_directory 'secrets/db_password.txt')).Hash
    Assert-Test ($hashA -ne $hashB) 'Les mots de passe des deux bases jetables sont distincts'
    # Write an explicit, inert fixture into A and verify B never sees it.
    $markerPhp = '$db=new mysqli(getenv("DB_HOST"),getenv("DB_USER"),trim(file_get_contents(getenv("DB_PASSWORD_FILE"))),getenv("DB_NAME"));$db->query("CREATE TABLE acceptance_isolation_fixture (id INT PRIMARY KEY)");$db->query("INSERT INTO acceptance_isolation_fixture VALUES (1)");'
    Invoke-TestCompose $clients[0] @('exec', '-T', 'web', 'php', '-r', $markerPhp) | Out-Host
    $isolationPhp = '$db=new mysqli(getenv("DB_HOST"),getenv("DB_USER"),trim(file_get_contents(getenv("DB_PASSWORD_FILE"))),getenv("DB_NAME"));$r=$db->query("SHOW TABLES LIKE ".chr(39)."acceptance_isolation_fixture".chr(39));exit($r->num_rows===0?0:1);'
    Invoke-TestCompose $clients[1] @('exec', '-T', 'web', 'php', '-r', $isolationPhp) | Out-Host
    Assert-Test $true 'Une table témoin créée dans la base A est absente de B'
    foreach ($client in $clients) {
        $volumes = @(& docker volume ls --filter ('label=com.docker.compose.project=' + $client.compose_project) --format '{{.Name}}')
        Assert-Test ($volumes.Count -ge 3 -and @($volumes | Where-Object { -not $_.StartsWith($client.compose_project + '_') }).Count -eq 0) "Client $($client.id) : volumes exclusivement préfixés par son projet jetable"
    }
    $passed = $true
    Write-Output "PASS $($checks.Count) contrôles sur deux installations indépendantes. Mode : $(if ($cached) { 'runtime en cache avec code livré actuel (aucun build source complet revendiqué)' } else { 'construction source des paquets générés' })."
} finally {
    Write-Report
    if (-not ($passed -and $KeepRunning)) {
        foreach ($client in $clients) {
            # Every target is validated against this run's unpredictable project prefix.
            try { Invoke-TestCompose $client @('--profile', 'assistant', 'down', '--volumes', '--remove-orphans') | Out-Host }
            catch { Write-Warning "Nettoyage Docker à vérifier pour $($client.compose_project)." }
        }
        $resolved = [System.IO.Path]::GetFullPath($testRoot).TrimEnd([char[]]@('\', '/'))
        if ([System.IO.Path]::GetDirectoryName($resolved) -eq $tempParent -and
            [System.IO.Path]::GetFileName($resolved) -match '^CyberShield-acceptance-[a-f0-9]{12}$') {
            Remove-Item -LiteralPath $resolved -Recurse -Force
        } else { throw 'Nettoyage de fichiers refusé : dossier temporaire inattendu.' }
    }
}
