#requires -Version 7.0
param(
    [Parameter(Mandatory=$true)][string]$GoExecutable,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9][a-z0-9-]{0,63}$')][string]$PreviewID,
    [string]$PrivateIdentityResetDirectory = ''
)

# Local preview packaging only. This command neither signs nor publishes,
# chooses a release floor, reads installed configs/identities, nor runs a client.
# Only state-free version/build/default-configuration preflights are executed.
$ErrorActionPreference = 'Stop'
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (-not [IO.Path]::IsPathRooted($OutputDirectory) -or $output -ne $OutputDirectory -or
    $output.StartsWith($source + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Use a new absolute output directory outside the source checkout.'
}
if (Test-Path -LiteralPath $output) { throw 'Output already exists; preserve old packages.' }
if (-not (Test-Path -LiteralPath $GoExecutable -PathType Leaf)) { throw 'Explicit Go toolchain executable not found.' }
New-Item -ItemType Directory -Path $output | Out-Null
Set-Location -LiteralPath $source
$oldGOOS, $oldGOARCH, $oldCGO, $oldLocalAppData = $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:LOCALAPPDATA
$env:GOOS, $env:GOARCH, $env:CGO_ENABLED = 'windows', 'amd64', '0'
$env:LOCALAPPDATA = Join-Path $output 'state-free-preflight-only'

function Write-NewText([string]$Path, [string]$Text) {
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($bytes); $file.Flush($true) } finally { $file.Dispose() }
}

try {
    $sourceFiles = @(& git ls-files --cached --others --exclude-standard) | Sort-Object -Unique
    if ($LASTEXITCODE -ne 0) { throw 'Could not capture local source inventory.' }
    $inventory = @($sourceFiles | ForEach-Object {
        $file = Join-Path $source $_
        $info = Get-Item -LiteralPath $file
        if ($info.PSIsContainer -or (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Nonregular source inventory member.' }
        [ordered]@{ path = $_; bytes = $info.Length; sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    Write-NewText (Join-Path $output 'source-inventory.json') (($inventory | ConvertTo-Json -Depth 5) + "`n")
    $inventoryHash = (Get-FileHash -LiteralPath (Join-Path $output 'source-inventory.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    $baseCommit = ((& git rev-parse HEAD) -join '').Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not read base commit.' }
    foreach ($edition in @('aborro','generic')) {
        $folderName = 'OpenTunnel-' + $edition + '-preview-' + $PreviewID
        $package = Join-Path $output $folderName
        New-Item -ItemType Directory -Path $package | Out-Null
        $binary = Join-Path $package 'otu-client.exe'
        $flags = '-s -w -buildid= -X opentunnel/internal/version.LocalPreview=' + $PreviewID
        $arguments = @('build','-buildvcs=false','-trimpath','-pgo=off',('-ldflags=' + $flags),'-o',$binary)
        if ($edition -eq 'generic') { $arguments += '-tags=genericclient' }
        $arguments += './cmd/otu-client'
        & $GoExecutable @arguments
        if ($LASTEXITCODE -ne 0) { throw 'Client edition build failed; incomplete output retained.' }
        $infoRaw = (& $binary --build-info) -join "`n"
        if ($LASTEXITCODE -ne 0) { throw 'State-free edition preflight failed.' }
        $info = $infoRaw | ConvertFrom-Json
        if ($info.edition -ne $edition -or $info.unreleased_local_preview -ne $PreviewID) { throw 'Built client has a different edition/preview stamp.' }
        if (Test-Path -LiteralPath $env:LOCALAPPDATA) { throw 'Version/build preflight unexpectedly created state.' }
        $defaults = ((& $binary --print-default-config) -join "`n") + "`n"
        if ($LASTEXITCODE -ne 0) { throw 'State-free defaults preflight failed.' }
        if ($edition -eq 'aborro' -and -not $defaults.Contains('server_addr = "cdn.aborro.dev:443"')) { throw 'Hosted endpoint is not embedded.' }
        if ($edition -eq 'generic' -and ($defaults.Contains('aborro.dev') -or -not $defaults.Contains('server_addr = ""'))) { throw 'Generic client has a hosted or implicit endpoint.' }
        Write-NewText (Join-Path $package 'client.toml') $defaults
        $launcher = "@echo off`r`nsetlocal`r`necho UNRELEASED local preview - not a signed public release.`r`n`"%~dp0otu-client.exe`" -c `"%~dp0client.toml`" --auto-proxy`r`nendlocal`r`n"
        Write-NewText (Join-Path $package 'START-CLIENT.bat') $launcher
        $stop = "@echo off`r`nsetlocal`r`necho Close the client window with Ctrl+C first and wait for cleanup.`r`necho This helper does not force-kill other installations or clear their identities.`r`npause`r`n`"%~dp0otu-client.exe`" --restore`r`nif errorlevel 1 (echo Recovery refused or incomplete. Keep all journals and review the message.)`r`npause`r`nendlocal`r`n"
        Write-NewText (Join-Path $package 'stop-otu.bat') $stop
        $restore = "@echo off`r`nsetlocal`r`n`"%~dp0otu-client.exe`" --restore`r`nif errorlevel 1 (echo Recovery refused or incomplete. Keep all journals and review the message.)`r`npause`r`nendlocal`r`n"
        Write-NewText (Join-Path $package 'RESTORE-NETWORK.bat') $restore
        [IO.File]::Copy((Join-Path $source 'LICENSE'), (Join-Path $package 'LICENSE'), $false)
        $readme = @"
# OpenTunnel $edition - UNRELEASED local preview $PreviewID

This is an unsigned local testing package, not the public hardening release.
Automatic updates are disabled in the executable. Hashes/build metadata below
identify bytes and declared settings; they are NOT authenticated provenance.

Extract into a NEW folder. Do not overwrite an installed client or config.
Close any existing client first. Double-click START-CLIENT.bat (or the EXE).
Press Ctrl+C in its window to stop; use RESTORE-NETWORK.bat only if cleanup needs
a retry. Network-only recovery preserves identities, bans and update evidence.

Protected scope is application HTTP/SOCKS proxying, NOT a system-wide VPN.
Corporate browser/network restrictions remain enforced. Do not disable TLS/SSH
checks, change script execution policy or run as another user to force access.
Approval and listener startup are not proof that tunnel traffic is working.

Local preview acceptance does not replace 72-hour mixed-device/carrier testing,
native Linux/least-privilege acceptance, rollback/signing and independent review.
"@
        if ($edition -eq 'aborro' -and $PrivateIdentityResetDirectory -ne '') {
            $reset = Join-Path $package 'IDENTITY-RESET-ONLY-FOR-THE-TWO-COPIED-PCS'
            New-Item -ItemType Directory -Path $reset | Out-Null
            # PC-specific names/credentials/backups never belong in public source.
            # Copy only the separately reviewed scripts-only private package.
            foreach ($name in @('RESET-CLONED-IDENTITY.bat','reset-cloned-identity.ps1','README.md')) {
                $inputFile = Join-Path $PrivateIdentityResetDirectory $name
                $inputInfo = Get-Item -LiteralPath $inputFile
                if ($inputInfo.PSIsContainer -or $inputInfo.Length -gt 64KB -or (($inputInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Private reset input is not a bounded ordinary file.' }
                [IO.File]::Copy($inputFile, (Join-Path $reset $name), $false)
            }
        }
        if ($edition -eq 'aborro') {
            $readme += @"


## Your cdn.aborro.dev edition

The HTTPS endpoint and known public TLS pin are preconfigured. SSH fallback uses
the device's own key and the existing git.aborro.dev forwarding host, subject to
separate administrator authorization. No token/private key is shipped.

The original default identity remains under LOCALAPPDATA\opentunnel. Existing
client.toml files are not edited or imported by this package builder.

If a private targeted reset package was explicitly supplied to the builder,
it appears in IDENTITY-RESET-ONLY-FOR-THE-TWO-COPIED-PCS. Follow its reviewed
instructions ONLY on the affected PCs with all clients stopped. Reset is never
automatic and does not approve a device, clear bans, rename Windows or securely
erase disk. Each new identity still needs a separate console review/approval.
"@
        } else {
            $readme += @"


## Generic self-hosted edition

Edit client.toml BEFORE starting. Fill server_addr with YOUR operator's endpoint
and fingerprint with its independently verified public certificate SHA256.
The default endpoint/pin are blank; startup is refused until configured. The
server operator must separately approve this device's generated identity.

Credentials/status/update trust are stored under LOCALAPPDATA\opentunnel-generic,
not the original operator's identity directory. Both editions share the user's
network-recovery lease/journals because they change the same Windows proxy.
For multiple independent operators, use explicitly trusted signed pool profiles.

No identity-reset tool or another person's configuration/credential is included.
Do NOT distribute this preview as the signed public release.
"@
        }
        Write-NewText (Join-Path $package 'README.md') ($readme + "`n")
        $binaryHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
        $metadata = [ordered]@{ schema_version=1; edition=$edition; local_preview=$PreviewID; public_release=$false; signing='not signed'; base_commit=$baseCommit; source_tree='local uncommitted hardening edits; not frozen'; source_inventory_sha256=$inventoryHash; executable_sha256=$binaryHash; executable_bytes=(Get-Item -LiteralPath $binary).Length; build_declaration=$info; trust='consistency declarations only, not authenticated build provenance'; generated_at=[DateTime]::UtcNow.ToString('o') }
        Write-NewText (Join-Path $package 'LOCAL-PREVIEW-BUILD.json') (($metadata | ConvertTo-Json -Depth 6) + "`n")
        $hashes = @(Get-ChildItem -LiteralPath $package -Recurse -File | Sort-Object FullName | ForEach-Object {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() + '  ' + [IO.Path]::GetRelativePath($package,$_.FullName).Replace('\','/')
        })
        Write-NewText (Join-Path $package 'SHA256SUMS.txt') (($hashes -join "`n") + "`n")
        Compress-Archive -LiteralPath $package -DestinationPath (Join-Path $output ($folderName + '.zip')) -CompressionLevel Optimal
    }
    $afterFiles = @(& git ls-files --cached --others --exclude-standard) | Sort-Object -Unique
    if ($LASTEXITCODE -ne 0 -or @((Compare-Object $sourceFiles $afterFiles)).Count -ne 0) { throw 'Source inventory changed during packaging; keep incomplete evidence and do not distribute.' }
    $changed = @($inventory | Where-Object { (Get-FileHash -LiteralPath (Join-Path $source $_.path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $_.sha256 })
    if ($changed.Count -ne 0 -or (Test-Path -LiteralPath $env:LOCALAPPDATA)) { throw 'Source changed or read-only preflight created runtime state; keep incomplete evidence and do not distribute.' }
    Write-Output 'Built local preview packages only. Nothing signed, installed, uploaded or released.'
    Get-ChildItem -LiteralPath $output -Filter '*.zip' | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash
} finally {
    $env:GOOS, $env:GOARCH, $env:CGO_ENABLED, $env:LOCALAPPDATA = $oldGOOS, $oldGOARCH, $oldCGO, $oldLocalAppData
}
