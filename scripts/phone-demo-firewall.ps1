param([ValidateSet('Open','Close')] [string] $Action = 'Open', [ValidateRange(1024,65535)] [int] $Port = 8082)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$stateFile = Join-Path $projectRoot '.runtime/phone-demo/state.json'
$state = if (Test-Path -LiteralPath $stateFile) { Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json } else { $null }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Cette regle de pare-feu ciblee necessite un PowerShell administrateur.' }
$ruleName = 'CyberShield-Phone-Demo-' + $(if ($state) { [int]$state.port } else { $Port })
if ($Action -eq 'Close') {
    Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host 'Regle du relais telephone retiree.'
    exit
}
if (-not $state) { throw 'Demarre le relais avant de configurer son pare-feu.' }
$binding = Get-NetIPAddress -AddressFamily IPv4 -IPAddress ([string]$state.listen_address)
$network = Get-NetConnectionProfile -InterfaceIndex $binding.InterfaceIndex
$profile = switch ([string]$network.NetworkCategory) { 'Private' { 'Private' } 'DomainAuthenticated' { 'Domain' } default { 'Public' } }
$addressBytes = ([IPAddress]::Parse([string]$state.listen_address)).GetAddressBytes()
$prefixLength = [int]$binding.PrefixLength
if ($prefixLength -lt 8 -or $prefixLength -gt 30) { throw 'Le sous-reseau doit etre controle manuellement avant ouverture.' }
for ($index=0; $index -lt 4; $index++) { $bits = [Math]::Max(0,[Math]::Min(8,$prefixLength - 8*$index)); $addressBytes[$index] = $addressBytes[$index] -band (256 - [Math]::Pow(2,8-$bits)) }
$subnet = ([IPAddress]::new($addressBytes)).ToString() + '/' + $prefixLength
Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -Name $ruleName -DisplayName 'CyberShield - telephone sur reseau local' -Direction Inbound -Action Allow -Protocol TCP -LocalPort ([int]$state.port) -LocalAddress ([string]$state.listen_address) -RemoteAddress $subnet -InterfaceAlias ([string]$binding.InterfaceAlias) -Profile $profile -EdgeTraversalPolicy Block | Out-Null
Write-Host ('Acces autorise uniquement sur ' + $binding.InterfaceAlias + ', port ' + $state.port + ', sous-reseau ' + $subnet + '.')
