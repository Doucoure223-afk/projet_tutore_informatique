param([string] $ListenAddress = '', [ValidateRange(1024,65535)] [int] $Port = 8082)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$runtimeDirectory = Join-Path $projectRoot '.runtime/phone-demo'
New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
$stateFile = Join-Path $runtimeDirectory 'state.json'
$relayScript = Join-Path $PSScriptRoot 'lan-proxy.py'
$pythonCommand = Get-Command python -ErrorAction Stop
$networks = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4Address.IPAddress -notmatch '^(127\.|169\.254\.)' })
if ($ListenAddress -eq '') {
    if ($networks.Count -ne 1) { throw 'Plusieurs reseaux actifs : precise -ListenAddress avec l IPv4 du Wi-Fi partage avec le telephone.' }
    $ListenAddress = [string] $networks[0].IPv4Address.IPAddress
}
$binding = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ListenAddress -ErrorAction Stop
if ([IPAddress]::Parse($ListenAddress).AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or $ListenAddress -match '^(127\.|0\.|169\.254\.)') { throw 'Utilise une IPv4 locale du Wi-Fi ou Ethernet.' }
if (Test-Path -LiteralPath $stateFile) {
    $oldState = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    $oldProcess = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int] $oldState.process_id) -ErrorAction SilentlyContinue
    if ($oldProcess -and $oldProcess.CommandLine.Contains($relayScript)) { Stop-Process -Id $oldProcess.ProcessId -ErrorAction Stop }
}
$existingListener = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
if ($existingListener.Count) { throw "Le port $Port est deja utilise. Aucun autre programme n a ete arrete." }
$secretDirectory = Join-Path $projectRoot 'docker-secrets'
New-Item -ItemType Directory -Path $secretDirectory -Force | Out-Null
$secretPath = Join-Path $secretDirectory 'lan_proxy_key.txt'
if (-not (Test-Path -LiteralPath $secretPath)) {
    $keyBytes = New-Object byte[] 32
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($keyBytes) } finally { $generator.Dispose() }
    $keyText = -join ($keyBytes | ForEach-Object { $_.ToString('x2') })
    [IO.File]::WriteAllText($secretPath, $keyText, [Text.Encoding]::ASCII)
    $keyBytes = $null; $keyText = $null
    $principal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    & icacls $secretPath /inheritance:r /grant:r "${principal}:(R)" '*S-1-5-18:(R)' '*S-1-5-32-544:(R)' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Protection du fichier de relais impossible.' }
}
Push-Location $projectRoot
try {
    & docker compose -f compose.yaml -f compose.phone-demo.yaml up -d --no-deps web
    if ($LASTEXITCODE -ne 0) { throw 'Le profil telephone Docker ne demarre pas.' }
    $processArguments = @(('"{0}"' -f $relayScript), '--bind', $ListenAddress, '--port', ([string]$Port), '--upstream-port', '8080', '--secret-file', ('"{0}"' -f $secretPath))
    $relayProcess = Start-Process -FilePath $pythonCommand.Source -ArgumentList $processArguments -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtimeDirectory 'proxy.stdout.log') -RedirectStandardError (Join-Path $runtimeDirectory 'proxy.stderr.log') -PassThru
    $phoneUrl = 'http://' + $ListenAddress + ':' + $Port + '/app/client-ip.php'
    $ready = $false
    for ($attempt = 0; $attempt -lt 12; $attempt++) {
        if ($relayProcess.HasExited) { throw 'Le relais ne demarre pas. Consulter .runtime/phone-demo/proxy.stderr.log.' }
        try {
            Add-Type -AssemblyName System.Net.Http
            $probeHandler = [System.Net.Http.HttpClientHandler]::new()
            $probeHandler.UseProxy = $false
            $probeClient = [System.Net.Http.HttpClient]::new($probeHandler)
            $probeClient.Timeout = [TimeSpan]::FromSeconds(3)
            try {
                $probeResponse = $probeClient.GetAsync($phoneUrl).GetAwaiter().GetResult()
                try {
                    $probeBody = $probeResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    if ([int]$probeResponse.StatusCode -eq 200 -and $probeBody.Contains($ListenAddress)) { $ready = $true; break }
                } finally { $probeResponse.Dispose() }
            } finally { $probeClient.Dispose(); $probeHandler.Dispose() }
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $ready) { Stop-Process -Id $relayProcess.Id; throw 'Le relais ne confirme pas l adresse du client. Aucun acces telephone fiable ne peut etre annonce.' }
    $state = [ordered]@{ process_id=$relayProcess.Id; listen_address=$ListenAddress; port=$Port; phone_url=$phoneUrl; interface_alias=$binding.InterfaceAlias; prefix_length=$binding.PrefixLength; started_at=[DateTime]::UtcNow.ToString('o') }
    $state | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding utf8
    Write-Host ('Adresse telephone : ' + $phoneUrl)
    Write-Host 'Console ordinateur : http://127.0.0.1:8080/security/ip-rules.php'
    Write-Host 'Mode blocage actif. Le port Docker reste limite a cet ordinateur.'
    Write-Host 'Le pare-feu Windows doit autoriser le port du relais sur ce reseau uniquement. Utilise scripts/phone-demo-firewall.ps1 en administrateur si necessaire.'
} finally { Pop-Location }
