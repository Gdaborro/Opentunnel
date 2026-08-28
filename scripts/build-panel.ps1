# Rebuilds the admin SPA and refreshes the embedded copy used by go:embed.
# Requires the portable Node SDK at $env:LOCALAPPDATA\node-sdk\node.
# Note: npm writes notices to stderr; do not use ErrorActionPreference=Stop here.
$root = Split-Path -Parent $PSScriptRoot
$env:PATH = "$env:LOCALAPPDATA\node-sdk\node;$env:PATH"
$env:npm_config_cache = "$env:TEMP\opencode\npm-cache"

Push-Location (Join-Path $root "panel-ui")
try {
    npm install --no-audit --no-fund 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "npm install failed" }
    npm run build 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "npm build failed" }
} finally {
    Pop-Location
}

$dst = Join-Path $root "internal\panel\ui\dist"
if (Test-Path -LiteralPath $dst) { Remove-Item -LiteralPath $dst -Recurse -Force }
Copy-Item -LiteralPath (Join-Path $root "panel-ui\dist") -Destination $dst -Recurse

# Reclaim storage: dependencies can be reinstalled on the next build.
Remove-Item -LiteralPath (Join-Path $root "panel-ui\node_modules") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "$env:TEMP\opencode\npm-cache" -Recurse -Force -ErrorAction SilentlyContinue

Write-Output "panel dist refreshed at internal/panel/ui/dist - run go build to pick it up"
