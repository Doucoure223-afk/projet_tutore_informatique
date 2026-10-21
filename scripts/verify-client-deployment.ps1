param([string] $PackageRoot = (Join-Path $PSScriptRoot '..'))

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$packagePath = [System.IO.Path]::GetFullPath($PackageRoot).TrimEnd([char[]]@('\', '/'))
$prefix = $packagePath + [System.IO.Path]::DirectorySeparatorChar

function Resolve-PublicAsset([string] $relative) {
    $relative = $relative.Replace('\', '/')
    $relativeLower = $relative.ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($relative) -or [System.IO.Path]::IsPathRooted($relative) -or
        $relative -match '(^|/)\.\.(/|$)' -or $relative -match '(^|/)(\.git|\.runtime|docker-secrets)(/|$)' -or
        $relativeLower -eq '.env' -or $relativeLower -eq 'config/local.php' -or
        ($relativeLower.StartsWith('secrets/') -and $relativeLower -ne 'secrets/.htaccess') -or
        ($relativeLower.StartsWith('logs/') -and $relativeLower -notin @('logs/.htaccess', 'logs/.gitkeep'))) {
        throw "Chemin public interdit dans le manifeste : $relative"
    }
    $resolved = [System.IO.Path]::GetFullPath((Join-Path $packagePath $relative))
    if (-not $resolved.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Le fichier sort du paquet : $relative"
    }
    return $resolved
}

$manifestPath = Join-Path $packagePath 'package-manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw 'package-manifest.json absent.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema_version -ne 1 -or @($manifest.files).Count -lt 1) { throw 'Manifeste de paquet invalide.' }
$seen = @{}
foreach ($asset in $manifest.files) {
    $relative = [string]$asset.path
    if ($seen.ContainsKey($relative)) { throw "Fichier dupliqué dans le manifeste : $relative" }
    $seen[$relative] = $true
    $file = Resolve-PublicAsset $relative
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Fichier du manifeste absent : $relative" }
    if (((Get-Item -LiteralPath $file).Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Les liens symboliques ne sont pas admis dans un paquet : $relative"
    }
    if ((Get-Item -LiteralPath $file).Length -ne [long]$asset.size -or
        (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256) {
        throw "Intégrité du paquet incorrecte : $relative"
    }
}

# Check local COPY/ADD sources of every shipped Dockerfile, including optional profiles.
# Multi-stage --from inputs are produced by Docker itself, not host package assets.
$copyCount = 0
foreach ($dockerfile in Get-ChildItem -LiteralPath (Join-Path $packagePath 'docker') -Filter Dockerfile -Recurse -File) {
    $dockerText = (Get-Content -LiteralPath $dockerfile.FullName -Raw) -replace '\\\r?\n', ' '
    foreach ($line in ($dockerText -split '\r?\n')) {
        if ($line -notmatch '^\s*(?:COPY|ADD)\s+(.+)$') { continue }
        $arguments = $Matches[1].Trim()
        if ($arguments -match '^--from(?:=|\s)') { continue }
        $arguments = $arguments -replace '^--(?:chown|chmod|link)(?:=\S+)?\s+', ''
        if ($arguments.StartsWith('[')) {
            $tokens = @($arguments | ConvertFrom-Json)
        } else {
            $tokens = @([regex]::Matches($arguments, '"[^"]*"|''[^'']*''|\S+') | ForEach-Object { $_.Value.Trim([char[]]@('"', "'")) })
        }
        if ($tokens.Count -lt 2) { throw "Instruction Docker non reconnue : $($dockerfile.Name)" }
        foreach ($source in $tokens[0..($tokens.Count - 2)]) {
            if ($source -match '^https?://') { throw 'Un téléchargement ADD distant doit être examiné explicitement.' }
            $sourcePath = Resolve-PublicAsset (([string]$source) -replace '^\./', '')
            if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($sourcePath)) {
                if (@(Get-ChildItem -Path $sourcePath -ErrorAction SilentlyContinue).Count -eq 0) { throw "Source Docker absente : $source" }
            } elseif (-not (Test-Path -LiteralPath $sourcePath)) {
                throw "Source Docker absente : $source ($($dockerfile.FullName))"
            }
            $inputs = if (Test-Path -LiteralPath $sourcePath -PathType Container) {
                @(Get-ChildItem -LiteralPath $sourcePath -Recurse -Force -File)
            } else { @(Get-Item -Path $sourcePath) }
            foreach ($inputFile in $inputs) {
                $inputRelative = $inputFile.FullName.Substring($packagePath.Length + 1).Replace('\', '/')
                if (-not $seen.ContainsKey($inputRelative)) { throw "Source Docker hors manifeste : $inputRelative" }
            }
            $copyCount++
        }
    }
}

# Local Compose bind sources are declared explicitly. Check file mounts before init;
# secrets and the optional Ollama host cache are runtime inputs and remain private.
$bindCount = 0
foreach ($compose in Get-ChildItem -LiteralPath $packagePath -Filter 'compose*.yaml' -File) {
    foreach ($line in Get-Content -LiteralPath $compose.FullName) {
        if ($line -match '^\s*-\s*["'']?(\./[^:"'']+):/[^\s"'']+') {
            $relative = $Matches[1].Substring(2)
        } elseif ($line -match '^\s*source:\s*["'']?(\./[^\s"'']+)') {
            $relative = $Matches[1].Substring(2)
        } else { continue }
        if ($relative.StartsWith('secrets/')) { continue }
        $assetPath = Resolve-PublicAsset $relative
        if (-not (Test-Path -LiteralPath $assetPath)) {
            throw "Fichier monté par Compose absent : $relative ($($compose.Name))"
        }
        $bindCount++
    }
}
Write-Output "OK : $($seen.Count) fichiers intègres, $copyCount sources Docker et $bindCount montages Compose locaux présents. Aucun secret lu."
