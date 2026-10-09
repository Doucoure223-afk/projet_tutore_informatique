$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$secretDirectory = Join-Path $projectRoot 'secrets'

New-Item -ItemType Directory -Force -Path $secretDirectory | Out-Null

# Restrict this webroot subdirectory to the current Windows user and system admins.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls $secretDirectory /inheritance:r /grant:r `
    "${identity}:(OI)(CI)F" `
    '*S-1-5-18:(OI)(CI)F' `
    '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Impossible de protéger les permissions du dossier des secrets.' }

function New-SecretFile([string] $path, [int] $minimumLength = 32) {
    if (Test-Path -LiteralPath $path) {
        if ((Get-Item -LiteralPath $path).Length -lt $minimumLength) {
            throw "Le secret existant est trop court : $path. Remplacez-le manuellement avant de continuer."
        }
        return
    }
    $bytes = [byte[]]::new(48)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    $secret = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    [System.IO.File]::WriteAllText($path, $secret, [System.Text.Encoding]::ASCII)
}

New-SecretFile (Join-Path $secretDirectory 'db_root_password.txt')
New-SecretFile (Join-Path $secretDirectory 'db_password.txt')
New-SecretFile (Join-Path $secretDirectory 'siem_token.txt') 16
New-SecretFile (Join-Path $secretDirectory 'assistant_token.txt')

$environmentFile = Join-Path $projectRoot '.env'
if (-not (Test-Path -LiteralPath $environmentFile)) {
    Copy-Item -LiteralPath (Join-Path $projectRoot '.env.example') -Destination $environmentFile
}
$environmentText = Get-Content -LiteralPath $environmentFile -Raw
$modelCache = if ($env:OLLAMA_MODELS) { $env:OLLAMA_MODELS } else { Join-Path $env:USERPROFILE '.ollama\models' }
$modelCache = $modelCache.Replace('\', '/')
if ($environmentText -notmatch '(?m)^\s*OLLAMA_MODELS_PATH=') {
    Add-Content -LiteralPath $environmentFile -Value "OLLAMA_MODELS_PATH=$modelCache"
} elseif ($environmentText -match '(?m)^\s*OLLAMA_MODELS_PATH\s*=\s*(|\./ollama-models)\s*$') {
    $environmentText = [regex]::Replace($environmentText, '(?m)^\s*OLLAMA_MODELS_PATH\s*=.*$', "OLLAMA_MODELS_PATH=$modelCache")
    [System.IO.File]::WriteAllText($environmentFile, $environmentText, [System.Text.UTF8Encoding]::new($false))
}
if ($environmentText -notmatch '(?m)^\s*CYBERSHIELD_ASSISTANT_MODEL=') {
    Add-Content -LiteralPath $environmentFile -Value 'CYBERSHIELD_ASSISTANT_MODEL=qwen2.5:7b-instruct'
}

Write-Output 'Secrets locaux créés ou conservés; leurs valeurs ne sont pas affichées.'
Write-Output 'Démarrer le pilote : docker compose up --build -d'
