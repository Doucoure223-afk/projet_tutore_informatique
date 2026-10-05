$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = (Resolve-Path (Join-Path $root '.runtime/python/python.exe') -ErrorAction SilentlyContinue).Path
$escaped = [regex]::Escape($root)
$processes = @()
try {
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
        Where-Object { $_.CommandLine -match $escaped -and $_.CommandLine -match 'ia[\/]service\.py' })
} catch {
    # Some managed Windows profiles deny WMI process queries. Fall back to the
    # local health identity and the listener PID; never stop an unknown app.
    $healthContent = $null
    try {
        $response = Invoke-WebRequest -Uri 'http://127.0.0.1:5000/health' -TimeoutSec 2
        $healthContent = $response.Content
    } catch {
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $healthContent = $reader.ReadToEnd()
                $reader.Dispose()
            } catch { }
        }
    }
    $health = $null
    if ($healthContent) {
        try { $health = $healthContent | ConvertFrom-Json } catch { }
    }
    $cyberShieldHealth = $health -and $health.analysis_method -eq 'MLP' -and (
        $health.service -eq 'CyberShield AI' -or
        $health.model_version -like 'cybershield-mlp-*' -or
        $health.status -eq 'model_unavailable'
    )
    if ($cyberShieldHealth -and $python) {
        $listener = netstat -ano -p tcp | Where-Object { $_ -match '^\s*TCP\s+\S+:5000\s+\S+\s+LISTENING\s+(\d+)\s*$' } | Select-Object -First 1
        if ($listener -match '\s(\d+)\s*$') {
            $targetProcess = Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue
            if ($targetProcess -and $targetProcess.Path -and $targetProcess.Path -ieq $python) {
                $processes = @([pscustomobject]@{ ProcessId = $targetProcess.Id })
            }
        }
    }
}
if (-not $processes) { Write-Host 'Aucun service CyberShield IA démarré depuis ce dossier.'; exit 0 }
foreach ($process in $processes) {
    Stop-Process -Id $process.ProcessId -ErrorAction Stop
    Write-Host "Service local arrêté (PID $($process.ProcessId))."
}
