$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$escaped = [regex]::Escape($root)
$processes = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" |
    Where-Object { $_.CommandLine -match $escaped -and $_.CommandLine -match 'ia[\\/]service\.py' }
if (-not $processes) { Write-Host 'Aucun service CyberShield IA démarré depuis ce dossier.'; exit 0 }
foreach ($process in $processes) {
    Stop-Process -Id $process.ProcessId -ErrorAction Stop
    Write-Host "Service local arrêté (PID $($process.ProcessId))."
}
