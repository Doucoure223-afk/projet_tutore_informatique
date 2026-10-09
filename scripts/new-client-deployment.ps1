param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-z0-9][a-z0-9_-]{0,30}$')]
    [string] $ClientId,

    [Parameter(Mandatory = $true)]
    [string] $Destination,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1024, 65535)]
    [int] $Port
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$sourceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd([char[]]@('\', '/'))
$destinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Destination)
$destinationFull = [System.IO.Path]::GetFullPath($destinationPath)
$destinationRoot = [System.IO.Path]::GetPathRoot($destinationFull)
if ([string]::Equals($destinationFull, $destinationRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'La destination ne peut pas être la racine d''un disque.'
}
$destinationFull = $destinationFull.TrimEnd([char[]]@('\', '/'))
$sourcePrefix = $sourceRoot + [System.IO.Path]::DirectorySeparatorChar
$composeProject = "cybershield-$ClientId"

if ([string]::Equals($destinationFull, $sourceRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
    $destinationFull.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'La destination doit être hors du dossier source du projet.'
}
if (Test-Path -LiteralPath $destinationFull) {
    throw "La destination existe déjà; aucune donnée n'a été remplacée : $destinationFull"
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
try {
    $listener.Start()
} catch [System.Net.Sockets.SocketException] {
    throw "Le port local $Port est déjà utilisé. Choisissez un autre port libre."
} finally {
    $listener.Stop()
}

$destinationParent = Split-Path -Parent $destinationFull
if ([string]::IsNullOrWhiteSpace($destinationParent)) {
    throw 'La destination doit être un chemin de dossier absolu ou relatif valide.'
}
New-Item -ItemType Directory -Force -Path $destinationParent | Out-Null
$stagingPath = Join-Path $destinationParent ('.cybershield-stage-' + $ClientId + '-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $stagingPath | Out-Null

function Copy-ClientFile([string] $relativePath) {
    $source = Join-Path $sourceRoot $relativePath
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Fichier source requis absent : $relativePath"
    }
    $target = Join-Path $stagingPath $relativePath
    $targetDirectory = Split-Path -Parent $target
    New-Item -ItemType Directory -Force -Path $targetDirectory | Out-Null
    Copy-Item -LiteralPath $source -Destination $target
}

function Copy-ClientDirectory([string] $relativePath) {
    $source = Join-Path $sourceRoot $relativePath
    if (-not (Test-Path -LiteralPath $source -PathType Container)) {
        throw "Dossier source requis absent : $relativePath"
    }
    $target = Join-Path $stagingPath $relativePath
    New-Item -ItemType Directory -Force -Path $target | Out-Null
    Get-ChildItem -LiteralPath $source -Force | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $target -Recurse -Force
    }
}

try {
    # These two directories contain only application/build assets; runtime state is excluded below.
    Copy-ClientDirectory 'app'
    Copy-ClientDirectory 'docker'

    $files = @(
        '.dockerignore', '.env.example', '.htaccess', 'compose.yaml', 'compose.siem.yaml', 'index.php',
        'config/.htaccess', 'config/ai.php', 'config/logger.php', 'config/security.php',
        'database/.htaccess', 'database/schema.sql', 'database/seed_products.sql',
        'logs/.htaccess', 'logs/.gitkeep', 'secrets/.htaccess', 'scripts/.htaccess',
        'scripts/init-docker.ps1', 'scripts/siem_forwarder.py',
        'security/access.php', 'security/bootstrap.php', 'security/dashboard.php', 'security/detector.php',
        'security/explanations.php', 'security/hybrid_analyzer.php', 'security/ia_analyzer.php',
        'security/ip-rules.php', 'security/ip_access.php', 'security/lab.php', 'security/logger.php',
        'security/assistant.php', 'security/assistant-client.php', 'security/assistant-chat.php',
        'security/assistant-widget.js', 'security/middleware.php', 'security/response_handler.php',
        'security/console.css',
        'ia/assistant-requirements.txt', 'ia/assistant_core.py', 'ia/assistant_graph.py',
        'ia/assistant_service.py', 'ia/features.py', 'ia/requirements.txt', 'ia/service.py', 'ia/train.py',
        'tests/fixtures/HttpParamsDataset/payload_train.csv',
        'docs/DEPLOIEMENT_CLIENTS_ET_INTEGRATION_PHP.md'
    )
    foreach ($file in $files) { Copy-ClientFile $file }

    # Start with public defaults only. The client host creates its own secrets later.
    $environment = Get-Content -LiteralPath (Join-Path $stagingPath '.env.example') -Raw
    $settings = [ordered]@{
        APP_BIND_ADDRESS = '127.0.0.1'
        APP_PORT = [string]$Port
        CYBERSHIELD_MODE = 'monitor'
    }
    foreach ($key in $settings.Keys) {
        $pattern = '(?m)^' + [regex]::Escape($key) + '=.*$'
        if ([regex]::Matches($environment, $pattern).Count -ne 1) {
            throw "La valeur $key doit figurer exactement une fois dans .env.example."
        }
        $environment = [regex]::Replace($environment, $pattern, "$key=$($settings[$key])")
    }
    if ($environment -match '(?m)^\s*COMPOSE_PROJECT_NAME=') {
        throw 'COMPOSE_PROJECT_NAME doit être ajouté par le générateur, pas hérité des valeurs par défaut.'
    }
    $crlf = [string][char]13 + [char]10
    $newLine = if ($environment.Contains($crlf)) { $crlf } else { [string][char]10 }
    $environment = $environment.TrimEnd([char[]]@(13, 10)) +
        $newLine + "COMPOSE_PROJECT_NAME=$composeProject" + $newLine
    [System.IO.File]::WriteAllText((Join-Path $stagingPath '.env'), $environment, [System.Text.UTF8Encoding]::new($false))

    $safeDestination = $destinationFull.Replace("'", "''")
    $readmeLines = @(
        '# Déploiement CyberShield — client ' + $ClientId,
        '',
        ("Cette copie est indépendante : projet Compose {0}, port local {1}, base, journaux et secrets propres à ce client. Elle a été préparée sans secrets ni journaux source." -f $composeProject, $Port),
        '',
        '## Premier démarrage (Windows + Docker Desktop)',
        '',
        'Depuis PowerShell :',
        '',
        ("    Set-Location '{0}'" -f $safeDestination),
        '    powershell -ExecutionPolicy Bypass -File .\scripts\init-docker.ps1',
        ("    docker compose --project-name {0} up --build -d" -f $composeProject),
        '',
        'Le script d''initialisation doit être exécuté sur la machine du client. Il crée ses clés aléatoires dans secrets/ sans les afficher. Ne transmettez pas ces fichiers par courriel et ne partagez pas ce dossier avec une autre installation.',
        '',
        ("Ouvrir http://127.0.0.1:{0}/app/setup.php depuis l''hôte, créer un administrateur dédié et activer son MFA. L''application reste liée à la boucle locale; pour un accès distant, placer un reverse proxy avec TLS et authentification devant elle, puis revoir explicitement la configuration réseau." -f $Port),
        '',
        'Le mode initial est monitor. Laissez-le actif pendant le pilote, vérifiez les alertes et les faux positifs, puis n''activez block qu''après accord du client. docker compose down conserve les volumes; n''utilisez pas down -v sauf pour effacer volontairement toutes les données.',
        '',
        '## Assistant local (facultatif)',
        '',
        'Installer Ollama sur l''hôte et télécharger le modèle autorisé : ollama pull qwen2.5:7b-instruct. Puis démarrer le profil :',
        '',
        ("    docker compose --project-name {0} --profile assistant up --build -d" -f $composeProject),
        '',
        'L''assistant local est facultatif et séparé du filtre SQLi. Ne lui transmettez pas de secrets ou de données personnelles.',
        '',
        '## Intégration à une application PHP existante',
        '',
        'Le filtre est un middleware PHP, pas un WAF réseau. Avec l''accord du propriétaire de l''application, inclure security/bootstrap.php tout au début du point d''entrée PHP, avant toute sortie ou traitement des paramètres. Garder security/, config/ et le service MLP de la même version CyberShield; commencer en mode observation. Le guide DEPLOIEMENT_CLIENTS_ET_INTEGRATION_PHP.md décrit les prérequis et limites. Cette copie ne modifie pas automatiquement le code d''une application tierce et ne fournit pas de connecteur SSO.',
        '',
        '## Exploitation',
        '',
        'Sauvegarder ensemble la base, les journaux/runtime et les secrets de cette instance, avec des droits réservés aux administrateurs de ce client. Pour le SIEM, définir son URL HTTPS dans .env puis lancer :',
        '',
        ("    docker compose --project-name {0} -f compose.yaml -f compose.siem.yaml up --build -d" -f $composeProject),
        '',
        'Le jeton SIEM créé dans cette installation ne doit être communiqué qu''au collecteur autorisé.'
    )
    $clientReadme = $readmeLines -join [System.Environment]::NewLine
    [System.IO.File]::WriteAllText((Join-Path $stagingPath 'DEPLOYMENT.md'), $clientReadme, [System.Text.UTF8Encoding]::new($false))

    if (Test-Path -LiteralPath $destinationFull) {
        throw "La destination vient d'apparaître; aucune donnée n'a été remplacée : $destinationFull"
    }
    [System.IO.Directory]::Move($stagingPath, $destinationFull)
    Write-Output "Copie client créée : $destinationFull"
    Write-Output "Projet Compose : $composeProject | Port local : $Port | Mode : monitor"
    Write-Output "Étape suivante sur la machine du client : exécuter scripts/init-docker.ps1 puis docker compose --project-name cybershield-$ClientId up --build -d."
} catch {
    Write-Error "Création interrompue. Le dossier temporaire peut être inspecté puis supprimé manuellement : $stagingPath"
    throw
}
