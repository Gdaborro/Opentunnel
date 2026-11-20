# Client editions (local pre-1.2 implementation, not released)

The coordinated hardening release is still gated by `PRE-1.2-HARDENING.md`.
Unsigned local previews are not the public release and cannot auto-update.

## Preconfigured operator edition

The default build embeds the existing `cdn.aborro.dev:443` endpoint/public TLS pin,
uses each device's own identity and needs separate administrator approval.
Existing configs and `%LOCALAPPDATA%\opentunnel` identity files are preserved.
The historical update asset name stays `otu-client-windows-amd64.exe` so released
clients do not update into another edition or change identity directories.

No private device token, SSH key, Windows settings backup or operator credentials
belong in any package. The copied-identity reset tool is an explicit separate
action only for the two affected PCs; it privately archives five copied files,
refuses the original laptop/ban markers, and does not approve or rename a device.
That PC-specific scripts-only package remains private, outside public source.
Supply it explicitly through `PrivateIdentityResetDirectory` when building the
operator package; generic packages never include it.

## Generic self-hosted edition

Build with `-tags=genericclient`. The EXE contains no hosted endpoint or public pin.
Set `server_addr` and the server operator's independently verified `fingerprint`
in its `client.toml` before starting. Blank/malformed pins or insecure bootstrap
are refused before credentials or proxy settings are created. The operator must
approve the device separately; listener startup is not successful connectivity.

Generic identity/status/update trust uses `%LOCALAPPDATA%\opentunnel-generic`.
Generic Windows updates use `otu-client-generic-windows-amd64.exe`; its asset role
and compile-time tag must be included in the signed, reviewed build inventory.
For independent multiple operators, use explicitly trusted signed pool profiles.

Both editions share the user's network-recovery journals/lease because they
modify the same Windows proxy. This shares no credentials and cannot restore a
live owner's settings. Never run both editions concurrently to bypass ownership.

## Local preview packaging

Use `scripts/build-client-packages.ps1` with an explicit Go executable, new
absolute external output directory and `PreviewID`. It never reads installed
configurations/identities, signs/publishes, or starts a runtime client. Only pure
version/build/defaults queries run. Packages carry unsigned-preview metadata,
exact payload hashes, README/license and safe network-only recovery launchers.

`--build-info`, `--print-default-config`, hashes and source inventories are
consistency declarations, not authenticated provenance or release acceptance.
Stable publication still needs frozen/reproducible artifacts, scoped signing,
real host/device/rollback/soak evidence and independent external review.
