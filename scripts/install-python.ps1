$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$runtimeDir = Join-Path $projectRoot '.runtime'
$pythonDir = Join-Path $runtimeDir 'python'
New-Item -ItemType Directory -Force -Path $pythonDir | Out-Null
$archive = Join-Path $runtimeDir 'python.zip'
if (-not (Test-Path (Join-Path $pythonDir 'python.exe'))) {
    Invoke-WebRequest 'https://www.python.org/ftp/python/3.13.15/python-3.13.15-embed-amd64.zip' -OutFile $archive -TimeoutSec 120
    $expected = 'd1f04d990aee1253d8569e8e5104e30fa9f5fa830899f14843448872d936a2cf'
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Empreinte Python incorrecte.' }
    Expand-Archive -LiteralPath $archive -DestinationPath $pythonDir -Force
}
@('python313.zip', '.', '../../', '../../ia', 'Lib/site-packages', 'import site') | Set-Content -LiteralPath (Join-Path $pythonDir 'python313._pth') -Encoding ascii
$pythonExe = Join-Path $pythonDir 'python.exe'
if (-not (Test-Path (Join-Path $pythonDir 'Lib/site-packages/pip'))) {
    $bootstrap = Join-Path $runtimeDir 'get-pip.py'
    Invoke-WebRequest 'https://bootstrap.pypa.io/get-pip.py' -OutFile $bootstrap -TimeoutSec 120
    & $pythonExe $bootstrap --no-warn-script-location --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) { throw 'Installation pip échouée.' }
}
& $pythonExe --version
Set-Content -LiteralPath (Join-Path $pythonDir '.htaccess') -Value 'Require all denied' -Encoding ascii
Write-Output 'Python local prêt. Aucun changement du PATH système.'
