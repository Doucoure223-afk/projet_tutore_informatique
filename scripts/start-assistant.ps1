param([string] $Model = 'qwen2.5:7b-instruct')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $root '.runtime\python\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Python local absent. Lance scripts/install-python.ps1 avant.' }
if ($Model -notmatch '^[A-Za-z0-9._:-]{1,80}$') { throw 'Nom de modèle Ollama invalide.' }
if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
    throw 'Ollama non installé ou absent du PATH. Installe Ollama puis redémarre PowerShell.'
}

Push-Location $root
$oldTokenPath = $env:CYBERSHIELD_ASSISTANT_TOKEN_FILE
$oldOllamaUrl = $env:OLLAMA_BASE_URL
$oldModel = $env:CYBERSHIELD_ASSISTANT_MODEL
try {
    $tokenPath = Join-Path $root 'secrets\assistant_token.txt'
    if (-not (Test-Path -LiteralPath $tokenPath)) {
        & (Join-Path $PSScriptRoot 'init-docker.ps1') | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Impossible de préparer les secrets locaux.' }
    }
    if ((Get-Item -LiteralPath $tokenPath).Length -lt 32) { throw 'Le jeton assistant local est trop court.' }

    try {
        $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3
    } catch {
        throw 'Ollama ne répond pas sur 127.0.0.1:11434. Démarre Ollama avant de lancer cet assistant.'
    }
    $availableModels = @($tags.models | ForEach-Object { [string]$_.name })
    if ($availableModels -notcontains $Model) {
        throw "Le modèle '$Model' est absent d Ollama. Lance : ollama pull $Model"
    }

    & $python -c 'from importlib.metadata import version; assert version("flask") == "3.1.2" and version("waitress") == "3.0.2" and version("langgraph") == "1.2.12"'
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Installation des dépendances LangGraph locales…'
        & $python -m pip install --disable-pip-version-check -r ia/assistant-requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Installation des dependances de l assistant echouee.' }
    }

    $env:CYBERSHIELD_ASSISTANT_TOKEN_FILE = $tokenPath
    $env:CYBERSHIELD_ASSISTANT_MODEL = $Model
    $env:OLLAMA_BASE_URL = 'http://127.0.0.1:11434'
    $healthy = $false
    try {
        $health = Invoke-RestMethod -Uri 'http://127.0.0.1:5100/health' -TimeoutSec 3
        $healthy = $health.service -eq 'CyberShield LangGraph assistant' -and $health.model_ready -and $health.model -eq $Model
    } catch { }
    if ($healthy) {
        Write-Host "Assistant LangGraph '$Model' déjà actif sur 127.0.0.1:5100."
        return
    }
    & (Join-Path $PSScriptRoot 'stop-assistant.ps1')
    $logDir = Join-Path $env:TEMP 'cybershield-assistant'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $process = Start-Process -FilePath $python -ArgumentList "ia/assistant_service.py --model $Model" `
        -WorkingDirectory $root -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $logDir 'stdout.log') `
        -RedirectStandardError (Join-Path $logDir 'stderr.log') -PassThru
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        Start-Sleep -Milliseconds 500
        try {
            $health = Invoke-RestMethod -Uri 'http://127.0.0.1:5100/health' -TimeoutSec 2
            if ($health.service -eq 'CyberShield LangGraph assistant' -and $health.model_ready -and $health.model -eq $Model) {
                Write-Host "Assistant LangGraph actif (PID $($process.Id), modèle $Model)."
                return
            }
        } catch { }
        if ($process.HasExited) { break }
    }
    throw "L assistant n a pas demarre. Consulte les journaux dans $logDir"
} finally {
    $env:CYBERSHIELD_ASSISTANT_TOKEN_FILE = $oldTokenPath
    $env:CYBERSHIELD_ASSISTANT_MODEL = $oldModel
    $env:OLLAMA_BASE_URL = $oldOllamaUrl
    Pop-Location
}
