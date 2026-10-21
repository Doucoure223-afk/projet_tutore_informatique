$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$generator = Join-Path $projectRoot 'scripts/new-client-deployment.ps1'
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) { throw 'Le CLI Docker Compose est requis pour ce test (aucun démarrage de conteneur n''est effectué).' }

$tempParent = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd([char[]]@('\', '/'))
$tempLeaf = 'CyberShield-deployment-test-' + [guid]::NewGuid().ToString('N')
$tempRoot = Join-Path $tempParent $tempLeaf
New-Item -ItemType Directory -Path $tempRoot | Out-Null
$oldDockerConfig = $env:DOCKER_CONFIG
$testDockerConfig = Join-Path $tempRoot 'docker-config'
New-Item -ItemType Directory -Path $testDockerConfig | Out-Null
$env:DOCKER_CONFIG = $testDockerConfig

function Get-FreeLoopbackPort {
    $probe = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $probe.Start()
        return ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port
    } finally {
        $probe.Stop()
    }
}

function Assert-ComposeConfig([string] $folder, [string] $projectName, [int] $expectedPort, [bool] $withOptionalServices) {
    Push-Location $folder
    try {
        if ($withOptionalServices) {
            $configLines = & docker compose --profile assistant -f compose.yaml -f compose.siem.yaml config --format json
        } else {
            $configLines = & docker compose config --format json
        }
        if ($LASTEXITCODE -ne 0) { throw "La configuration Compose est invalide pour $projectName." }
        $configuration = ($configLines -join [System.Environment]::NewLine) | ConvertFrom-Json
        if ($configuration.name -ne $projectName) { throw "Le nom Compose généré n'isole pas $projectName." }
        $resourceNames = @($configuration.volumes.PSObject.Properties | ForEach-Object { $_.Value.name })
        foreach ($volume in @('mariadb-data', 'cybershield-runtime', 'siem-outbox')) {
            if ($resourceNames -notcontains ($projectName + '_' + $volume)) {
                throw "Le volume $volume n'est pas préfixé par le projet $projectName."
            }
        }
        $published = [int]$configuration.services.web.ports[0].published
        if ($published -ne $expectedPort) { throw "Le port $expectedPort n'est pas publié dans $projectName." }
    } finally {
        Pop-Location
    }
}

function Get-SecretHash([string] $path) {
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

function Assert-PackageCompleteness([string] $folder) {
    $verify = Join-Path $folder 'scripts/verify-client-deployment.ps1'
    & $verify -PackageRoot $folder | Out-Host
    $manifestPath = Join-Path $folder 'package-manifest.json'
    $original = [System.IO.File]::ReadAllText($manifestPath)
    # Remove a file AND its manifest entry: COPY/mount reference checks must still fail.
    foreach ($relative in @('security/client_identity.php', 'security/assistant-page.js',
        'security/assistant-request.js', 'database/orders.sql')) {
        $asset = Join-Path $folder $relative
        $bytes = [System.IO.File]::ReadAllBytes($asset)
        $manifest = $original | ConvertFrom-Json
        $manifest.files = @($manifest.files | Where-Object { $_.path -ne $relative })
        [System.IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
        Remove-Item -LiteralPath $asset
        $rejected = $false
        try { & $verify -PackageRoot $folder | Out-Null } catch { $rejected = $true }
        finally {
            [System.IO.File]::WriteAllBytes($asset, $bytes)
            [System.IO.File]::WriteAllText($manifestPath, $original, [System.Text.UTF8Encoding]::new($false))
        }
        if (-not $rejected) { throw "La suppression de $relative n'est pas détectée." }
    }
    $tampered = Join-Path $folder 'security/assistant-widget.js'
    $bytes = [System.IO.File]::ReadAllBytes($tampered)
    [System.IO.File]::AppendAllText($tampered, "`n/* test-only alteration */`n")
    $rejected = $false
    try { & $verify -PackageRoot $folder | Out-Null } catch { $rejected = $true }
    finally { [System.IO.File]::WriteAllBytes($tampered, $bytes) }
    if (-not $rejected) { throw 'Une altération de fichier public doit invalider le manifeste.' }
    & $verify -PackageRoot $folder | Out-Host
    Write-Output 'OK : quatre fichiers de construction manquants et une altération sont détectés.'
}

try {
    $portA = Get-FreeLoopbackPort
    $portB = Get-FreeLoopbackPort
    while ($portB -eq $portA) { $portB = Get-FreeLoopbackPort }

    $instanceA = Join-Path $tempRoot 'client-a'
    $instanceB = Join-Path $tempRoot 'client-b'
    & $generator -ClientId client-a -Destination $instanceA -Port $portA | Out-Host
    & $generator -ClientId client-b -Destination $instanceB -Port $portB | Out-Host

    if ((Get-Content -LiteralPath (Join-Path $instanceA '.env') -Raw) -notmatch "(?m)^APP_PORT=$portA\r?$" -or
        (Get-Content -LiteralPath (Join-Path $instanceB '.env') -Raw) -notmatch "(?m)^APP_PORT=$portB\r?$" -or
        (Get-Content -LiteralPath (Join-Path $instanceA '.env') -Raw) -notmatch '(?m)^COMPOSE_PROJECT_NAME=cybershield-client-a\r?$' -or
        (Get-Content -LiteralPath (Join-Path $instanceB '.env') -Raw) -notmatch '(?m)^COMPOSE_PROJECT_NAME=cybershield-client-b\r?$') {
        throw 'Les ports et noms de projet distincts ne sont pas inscrits dans les fichiers .env.'
    }

    foreach ($instance in @($instanceA, $instanceB)) {
        $envText = Get-Content -LiteralPath (Join-Path $instance '.env') -Raw
        if ($envText -notmatch '(?m)^APP_BIND_ADDRESS=127\.0\.0\.1$' -or
            $envText -notmatch '(?m)^CYBERSHIELD_MODE=monitor$' -or
            $envText -match '(?im)^\s*(DB_PASSWORD|DB_ROOT_PASSWORD|SIEM_TOKEN|ASSISTANT_TOKEN)=') {
            throw "Le .env généré n'est pas privé et en mode pilote : $instance"
        }

        $logNames = @(Get-ChildItem -LiteralPath (Join-Path $instance 'logs') -Force | ForEach-Object Name | Sort-Object)
        if (($logNames -join ',') -ne '.gitkeep,.htaccess') { throw "Des journaux source ont été copiés dans $instance." }

        $secretNames = @(Get-ChildItem -LiteralPath (Join-Path $instance 'secrets') -Force | ForEach-Object Name | Sort-Object)
        if (($secretNames -join ',') -ne '.htaccess') { throw "Des secrets source ont été copiés dans $instance." }
        if ((Get-Content -LiteralPath (Join-Path $instance 'secrets/.htaccess') -Raw) -notmatch '(?m)^Require all denied\s*$') {
            throw "Le dossier de secrets n'est pas interdit à Apache dans $instance."
        }
        if (-not (Test-Path -LiteralPath (Join-Path $instance 'DEPLOYMENT.md'))) { throw "DEPLOYMENT.md absent de $instance." }
        if (-not (Test-Path -LiteralPath (Join-Path $instance 'docs/DEPLOIEMENT_CLIENTS_ET_INTEGRATION_PHP.md'))) {
            throw "Le guide d'intégration est absent de $instance."
        }
    }

    Assert-PackageCompleteness $instanceA
    Assert-PackageCompleteness $instanceB

    foreach ($instance in @($instanceA, $instanceB)) {
        $powerShellExe = (Get-Process -Id $PID).Path
        & $powerShellExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $instance 'scripts/init-docker.ps1') | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "L'initialisation des secrets a échoué dans $instance." }
    }

    $secretFiles = @('db_root_password.txt', 'db_password.txt', 'siem_token.txt', 'assistant_token.txt')
    foreach ($name in $secretFiles) {
        $hashA = Get-SecretHash (Join-Path $instanceA ('secrets/' + $name))
        $hashB = Get-SecretHash (Join-Path $instanceB ('secrets/' + $name))
        if ($hashA -eq $hashB) { throw "Le secret $name a été réutilisé entre clients." }
    }

    Assert-ComposeConfig $instanceA 'cybershield-client-a' $portA $false
    Assert-ComposeConfig $instanceA 'cybershield-client-a' $portA $true
    Assert-ComposeConfig $instanceB 'cybershield-client-b' $portB $false
    Assert-ComposeConfig $instanceB 'cybershield-client-b' $portB $true

    Write-Output "OK : deux copies isolées, ports $portA/$portB, secrets distincts, aucun journal source, Compose valide (base + assistant/SIEM)."
    Write-Output 'Aucun conteneur n''a été démarré dans ce test.'
} finally {
    if ($null -eq $oldDockerConfig) { Remove-Item Env:DOCKER_CONFIG -ErrorAction SilentlyContinue }
    else { $env:DOCKER_CONFIG = $oldDockerConfig }
    $resolvedTempRoot = [System.IO.Path]::GetFullPath($tempRoot).TrimEnd([char[]]@('\', '/'))
    $resolvedParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $resolvedTempRoot)).TrimEnd([char[]]@('\', '/'))
    $resolvedLeaf = Split-Path -Leaf $resolvedTempRoot
    if ([string]::Equals($resolvedParent, $tempParent, [System.StringComparison]::OrdinalIgnoreCase) -and
        $resolvedLeaf -match '^CyberShield-deployment-test-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolvedTempRoot -Recurse -Force
    } else {
        throw "Nettoyage annulé : le chemin temporaire sort du dossier prévu ($resolvedTempRoot)."
    }
}
