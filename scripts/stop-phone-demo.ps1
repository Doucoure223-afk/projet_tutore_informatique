param([switch] $KeepBlockMode)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$stateFile = Join-Path $projectRoot '.runtime/phone-demo/state.json'
if (Test-Path -LiteralPath $stateFile) {
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    $relayScript = Join-Path $PSScriptRoot 'lan-proxy.py'
    $relayProcess = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$state.process_id) -ErrorAction SilentlyContinue
    if ($relayProcess -and $relayProcess.CommandLine.Contains($relayScript)) { Stop-Process -Id $relayProcess.ProcessId }
    Remove-Item -LiteralPath $stateFile
    $ruleName = 'CyberShield-Phone-Demo-' + [int]$state.port
    try { Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop }
    catch { Write-Warning 'Le relais est ferme. Retirer sa regle de pare-feu dans un PowerShell administrateur si elle existe.' }
}
Push-Location $projectRoot
try {
    $previousMode = $env:CYBERSHIELD_MODE
    if ($KeepBlockMode) { $env:CYBERSHIELD_MODE = 'block' }
    try { & docker compose up -d --no-deps web; if ($LASTEXITCODE -ne 0) { throw 'Restauration du profil local Docker impossible.' } }
    finally { if ($KeepBlockMode) { $env:CYBERSHIELD_MODE = $previousMode } }
} finally { Pop-Location }
Write-Host 'Acces telephone ferme. Les commandes, les regles IP et les journaux sont conserves.'
