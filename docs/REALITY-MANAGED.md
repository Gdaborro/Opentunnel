# Managed Xray/REALITY carrier

This integration is additive and opt-in. It does not replace the WS/SSH/H3
carriers, install binaries, change DNS/firewalls, or claim every network is
bypassable. REALITY changes the outer transport; the destination IP remains
visible. A cover name must match its TLS fallback target and work on the
intended network. Keep operator measurements, candidate lists and credentials
outside public source/documentation.

## Implementation and trust boundaries

`companions/xray` is a separate restricted Xray distribution pinned to upstream
v26.11.9's exact source commit. It is built with Go 1.27.4+ and patched crypto/
compression dependencies. The official upstream release binary is **not** the
managed default: symbol-level scanning found unpatched runtime/compression
advisories in that artifact. Scan the resulting restricted build too.

The host verifies an explicit executable SHA-256, privately stages it, checks
its exact companion version/config, and launches it without inherited config,
proxy, PATH or key-log environment. Runtime config uses a private directory and
Windows protected ACLs. Child failures share a supervisor/backoff instead of
spawning per browser request; teardown kills/reaps only the owned child.
Windows Job Objects enforce child cleanup and bounds; Linux parent-death
signaling and service resource limits cover the server process.

Client SOCKS listens only on a literal loopback endpoint, requires a private
per-run password, denies UDP, and routes only the exact TCP relay ingress.
Server VLESS/REALITY accepts configured users but routes only that same exact
target, denying everything else; freedom egress also rewrites the final target
and applies final allow/deny rules. A stolen carrier credential is therefore
not intended to be a general-purpose egress proxy. Opentunnel device-key
admission remains separately required.

The typed builders/validators reject extra DNS, API, logging, direct egress,
reverse, sniffing and unreviewed transport options. Wrong UUID, REALITY access
parameter, short ID and local authentication must fail. Ordinary TLS fallback
showing the cover certificate does not prove authenticated throughput.

REALITY fallback can still consume relay/fallback-target resources. Optional
`fallback-bps` introduces randomized per-config rate bounds, but shaping is an
observable tradeoff, not invisibility. Vision is not enabled by default: the
opaque opentunnel AEAD/mux stream does not automatically receive its origin-TLS
splice optimization.

## Explicit provisioning

Build the companion outside the public repo using `scripts/build-xray.ps1`.
This script runs module verification, vet, pinned vulnerability scanning and
Windows/Linux amd64/arm64 cross-builds; it does not publish or deploy.

Build `cmd/otu-reality` as the provisioning/server supervision tool. Its
`provision` subcommand requires explicit endpoint, listener, matching cover,
fixed ingress and absolute private output directory. It writes a private
`client-profile.json` and restricted `server.json` without printing UUIDs,
keys, passwords or short IDs. Existing files are not overwritten. The tool
does not start the listener during provisioning.

Example **placeholders**, not a live configuration:

```text
otu-reality provision -endpoint RELAY_HOST:PILOT_PORT \
  -listen RELAY_BIND:PILOT_PORT -cover VERIFIED_COVER:443 \
  -server-name VERIFIED_COVER -target 127.0.0.1:8082 \
  -out-dir ABSOLUTE_PRIVATE_DIRECTORY
```

Stage the server config and exact reviewed binary digest privately. `serve`
validates and supervises an explicitly chosen listener. `deploy/otu-reality.service`
is an uninstalled opt-in pilot template; check existing use before choosing a
port and never treat this template as permission to take over 443.

Client TOML opt-in (placeholders; credential profile is not committed):

```toml
[reality]
enabled = true
executable = "PRIVATE_PATH/otu-xray"
sha256 = "EXACT_REVIEWED_BINARY_SHA256"
profile = "PRIVATE_PATH/client-profile.json"
socks_listen = "127.0.0.1:19090"
```

Use `transport="carrier"` in the root table to force the managed carrier,
or leave `transport="wstls"`/`profile="auto"` to add it before H3/SSH. An
explicit primary carrier does not silently fall back to unconfigured public
carriers. Managed REALITY and external `carrier_socks` cannot be configured at
the same time. No automatic companion downloader is present.

Relay TOML adds only an explicit fixed loopback ingress:

```toml
listen_carrier_internal = "127.0.0.1:8082"
```

The carrier ingress excludes admin routes. Bootstrap/control uses the managed
local auth in memory, not a persisted local SOCKS password in TOML. Original
source IP attribution through a fixed loopback forward is limited; client
headers are not promoted to trusted network identity.

## Optional independent inner mutual TLS

REALITY/SSH/CDN endpoints are normally inside the transport trust boundary.
For an independent relay anchor, the optional inner channel uses standard
TLS 1.3 mutual authentication, fresh ephemeral session keys and no session
tickets/0-RTT. The enrolled Ed25519 device key signs a short-lived client
certificate. The client pins the relay's SHA-256 SPKI; the encrypted confirmation
waits for server-side certificate/admission acceptance before tunnel setup.
The following v5 token/key must match that identity and generation.

`otu-reality inner-identity` generates a separate private relay key/certificate
and prints only its public-key pin. Provision that pin independently of the
outer carrier. Relay config uses `inner_tls_cert`, `inner_tls_key` and optional
`require_inner_tls=true`; clients opt in with `inner_tls_pins=[...]`. There is
no fallback to an unpinned inner session after an inner-TLS failure. Enable
requirement only after adoption has been checked. Legacy carrier compatibility
is preserved while the requirement is disabled.

TLS-over-TLS adds overhead and metadata/endpoint compromise are still relevant.
This is standard TLS protection, not a novel claim that the existing token-
derived AEAD secretly gained forward secrecy by adding a carrier.

## Validation before fleet enablement

- Scan/build provenance, matching version and per-platform binary digest.
- Authenticated throughput/control/data policy, wrong-credential rejection and
  ordinary-TLS fallback independently.
- Client and modified-client **server-side** arbitrary-destination denial;
  UDP denial, fixed redirect and no admin-plane reachability.
- Kill-switch, expiry/rekey, original-IP limitations and traffic accounting.
- Startup/config/digest failures, occupied local port, child death, restart,
  process containment, cancellation and no leaked children/listeners.
- Real intended-network tests and companion/update rollout/rollback. Lab
  loopback tests cannot establish DPI survivability or universal censorship bypass.

Xray-core/REALITY use MPL-2.0. Keep source/version references and license notices
with companion distributions; this is not a change to the host project license
or a legal conclusion about packaging. The separate module includes no private
operator config or network-measurement pool.
