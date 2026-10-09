$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = (Resolve-Path (Join-Path $root '.runtime\python\python.exe') -ErrorAction SilentlyContinue).Path
$escaped = [regex]::Escape($root)
$processes = @()
try {
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
        Where-Object { $_.CommandLine -match $escaped -and $_.CommandLine -match 'ia[\\/]assistant_service\.py' })
} catch {
    $healthBody = $null
    try { $healthBody = (Invoke-WebRequest -Uri 'http://127.0.0.1:5100/health' -TimeoutSec 2).Content } catch {
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $healthBody = $reader.ReadToEnd()
                $reader.Dispose()
            } catch { }
        }
    }
    if ($healthBody -and $healthBody.Contains('CyberShield LangGraph assistant') -and $python) {
        $listener = netstat -ano -p tcp | Where-Object { $_ -match '^\s*TCP\s+\S+:5100\s+\S+\s+LISTENING\s+(\d+)\s*$' } | Select-Object -First 1
        if ($listener -match '\s(\d+)\s*$') {
            $target = Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue
            if ($target -and $target.Path -and $target.Path -ieq $python) {
                $processes = @([pscustomobject]@{ ProcessId = $target.Id })
            }
        }
    }
}
if (-not $processes) { Write-Host 'Aucun assistant LangGraph démarré depuis ce dossier.'; exit 0 }
foreach ($process in $processes) {
    Stop-Process -Id $process.ProcessId -ErrorAction Stop
    Write-Host "Assistant local arrêté (PID $($process.ProcessId))."
}
