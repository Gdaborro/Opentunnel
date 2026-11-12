param([switch]$SkipInstall, [switch]$NoBackup)
# Reproducible SPA build. Keep dependencies/caches and unknown embedded assets;
# never recursively delete another developer's files as a build side effect.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$npm = if (Get-Command npm.cmd -ErrorAction SilentlyContinue) { 'npm.cmd' } else { 'npm' }
Push-Location (Join-Path $root 'panel-ui')
try {
    if (-not $SkipInstall) {
        & $npm ci --ignore-scripts --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    }
    & $npm run build
    if ($LASTEXITCODE -ne 0) { throw 'frontend build failed' }
} finally { Pop-Location }

$src = Join-Path $root 'panel-ui\dist'
$dst = Join-Path $root 'internal\panel\ui\dist'
if (-not (Test-Path (Join-Path $src 'index.html'))) { throw 'build index missing' }
if ((Test-Path $dst) -and (-not $NoBackup)) {
    $backupRoot = Join-Path ([IO.Path]::GetTempPath()) 'opencode'
    $backup = Join-Path $backupRoot ('panel-embed-backup-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    Copy-Item -LiteralPath $dst -Destination $backup -Recurse
    Write-Output "Previous embedded assets preserved at $backup"
}
New-Item -ItemType Directory -Path $dst -Force | Out-Null
# Copy and hash-check all assets before publishing the new index. Old hashed
# assets are retained so open tabs and user-added files are not discarded.
$files = Get-ChildItem -LiteralPath $src -Recurse -File | Where-Object { $_.Name -ne 'index.html' }
foreach ($file in $files) {
    $relative = $file.FullName.Substring($src.Length + 1)
    $target = Join-Path $dst $relative
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $target -Force
    if ((Get-FileHash $file.FullName).Hash -ne (Get-FileHash $target).Hash) { throw 'embedded asset copy failed digest check' }
}
Copy-Item -LiteralPath (Join-Path $src 'index.html') -Destination (Join-Path $dst 'index.html') -Force
Write-Output 'Embedded SPA refreshed; rebuild Go binaries to include it.'
