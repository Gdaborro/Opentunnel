param([Parameter(Mandatory=$true)][string]$OutputDirectory)
# Explicit private companion build; does not publish, deploy or sign.
$ErrorActionPreference = 'Stop'
if (-not [IO.Path]::IsPathFullyQualified($OutputDirectory)) { throw 'Use an absolute output directory outside the public repository' }
$root = [IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if ($OutputDirectory.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or $OutputDirectory.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'Companion artifacts must stay outside the public source repository' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$original = @{}
foreach ($name in @('GOOS', 'GOARCH', 'CGO_ENABLED')) { $original[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
Push-Location (Join-Path $root 'companions\xray')
try {
    Remove-Item Env:GOOS, Env:GOARCH -ErrorAction SilentlyContinue
    & go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Companion dependency integrity failed' }
    & go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Companion vet failed' }
    & go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
    if ($LASTEXITCODE -ne 0) { throw 'Companion vulnerability gate failed' }
    $env:CGO_ENABLED = '0'
    foreach ($target in @(@('windows','amd64','otu-xray-windows-amd64.exe'), @('linux','amd64','otu-xray-linux-amd64'), @('linux','arm64','otu-xray-linux-arm64'))) {
        $env:GOOS = $target[0]; $env:GOARCH = $target[1]
        & go build -buildvcs=false -trimpath -ldflags='-s -w' -o (Join-Path $OutputDirectory $target[2]) .
        if ($LASTEXITCODE -ne 0) { throw ('Companion cross-build failed: ' + $target[2]) }
        $file = Join-Path $OutputDirectory $target[2]
        Write-Output ($target[2] + ' sha256: ' + (Get-FileHash $file).Hash.ToLowerInvariant())
    }
    Copy-Item -LiteralPath 'README.md' -Destination (Join-Path $OutputDirectory 'SOURCE-AND-LICENSE-NOTICE.md')
} finally {
    Pop-Location
    foreach ($name in $original.Keys) { [Environment]::SetEnvironmentVariable($name, $original[$name], 'Process') }
}
