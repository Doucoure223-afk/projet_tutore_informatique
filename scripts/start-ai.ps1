$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.runtime/python/python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Python local absent. Lancez le script d installation dans scripts.'
}
Push-Location $root
try {
    & $python -c 'import flask, sklearn, numpy, joblib, waitress'
    if ($LASTEXITCODE -ne 0) {
        & $python -m pip install --disable-pip-version-check -r ia/requirements.txt
        if ($LASTEXITCODE -ne 0) { throw 'Installation des dépendances IA échouée.' }
    }
    $model = Join-Path $root 'ia/models/model.joblib'
    if (-not (Test-Path -LiteralPath $model)) {
        Write-Host 'Entraînement initial du MLP sur le corpus synthétique local…'
        & $python ia/train.py
        if ($LASTEXITCODE -ne 0) { throw 'Entraînement du MLP échoué.' }
    }
    try {
        $health = Invoke-RestMethod -Uri 'http://127.0.0.1:5000/health' -TimeoutSec 2
        if ($health.model_loaded -and $health.analysis_method -eq 'MLP') {
            Write-Host "Le modèle $($health.model_version) est déjà actif sur 127.0.0.1:5000."
            return
        }
    } catch { }
    $logDir = Join-Path $env:TEMP 'cybershield-ai'
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $process = Start-Process -FilePath $python -ArgumentList 'ia/service.py' -WorkingDirectory $root `
        -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDir 'stdout.log') `
        -RedirectStandardError (Join-Path $logDir 'stderr.log') -PassThru
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        Start-Sleep -Milliseconds 250
        try {
            $health = Invoke-RestMethod -Uri 'http://127.0.0.1:5000/health' -TimeoutSec 2
            if ($health.model_loaded -and $health.analysis_method -eq 'MLP') {
                Write-Host "CyberShield MLP actif (PID $($process.Id), version $($health.model_version))."
                return
            }
        } catch { }
    }
    throw "Le service n'a pas démarré. Journaux : $logDir"
} finally { Pop-Location }
