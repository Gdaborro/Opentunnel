# Restricted Xray companion build

This is a separate Go module for a minimal Xray distribution, pinned to
upstream commit `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` (v26.11.9).
It uses Go 1.27.4+ and patched compression/crypto dependencies. It excludes the
upstream general CLI, HTTP config fetch, Lua, TUN, optional carrier stack and
API servers. It accepts only a local bounded JSON config and never prints
key-bearing config parser errors.

Build and scan from this directory:

```text
go mod verify
go vet ./...
go build -trimpath -o <private-output-directory>/otu-xray .
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Generated runtime configs are further restricted by opentunnel's typed
REALITY builder/validator and fixed-target rules. Digest verification and
process supervision are required before launching. This directory contains no
carrier credentials, no selected cover-site list and no production config.

The imported Xray-core and REALITY implementation are MPL-2.0; see upstream
source/license and ship required notices/source references with any binary
distribution. This wrapper does not change those obligations or provide a
license opinion. No binaries are published automatically from this module.
