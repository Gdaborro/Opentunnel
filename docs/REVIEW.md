# Reliability and security review

Reviewed 2026-11-11. This is a code review and regression-test record, not
a claim that the transport is undetectable or that every network has been tested.
Network-specific measurements, operator credentials, and deployment inventory
belong in private operational records, not this repository.

## Highest-value changes in v1.1.5

| Finding | Change | Main code |
| --- | --- | --- |
| net/http standard-library crash advisory GO-2026-6859 | Require Go 1.27.4 or newer and select that minimum in CI | `go.mod`, CI |
| Public re-registration could overwrite an approved key; auto-accept could turn this into takeover | Preserve existing identities, return a conflict, require authenticated administrator rekey plus separate approval | `internal/panel/handler.go` |
| A bad signature could auto-kick the named legitimate device | Keep the device connected, alert, and rate-limit sustained failures at the source instead | `internal/server/sentinel.go` |
| Losing a public-key cache silently regenerated the private identity | Derive the public cache from the existing private key; private-key loss requires explicit recovery | `internal/client/token.go` |
| Concurrent key-file updates could lose entries or create duplicates | Serialize read-modify-write; deduplicate; sync a unique temporary file before rename | `internal/panel/sshkeys.go` |
| SSH connect timeout did not bound the handshake/forwarding stage | Use a context-aware TCP dial, socket setup deadline, and explicit lifetime ownership | `internal/transport/ssh.go` |
| Rotated mux selection modified the list while traversing it | Stable round-robin indexing, preserving session identity | `internal/client/mux.go` |
| Capacity replacement killed active streams; waiting callers could stampede | Graceful bounded drain, capped sessions, one shared setup result, no extra handshake on waiter timeout | `internal/client/mux.go` |
| Successful sessions inherited the first request's cancellation | Pool-owned session lifetime; request cancellation only applies during setup | `internal/client/mux.go` |
| Rebuilding cached clients left workers and transports alive | Drain old pools and cancel their workers/transports; close DB and health workers cleanly | client and panel lifecycle code |
| Hostile-mode requests retried dead QUIC ahead of already-working SSH | Sticky selection, shared data/control/probe cooldowns, occasional recovery probes | `internal/client/adaptive.go` |
| Every profile used balanced shaping | Use the actual fast/balanced/stealth settings | `internal/client/adaptive.go` |
| QUIC kept startup pins and the initial entry after rotation | Build H3 from the current adaptive entry and learned pins | client adaptive and startup wiring |
| HTTPS throughput probes sent plaintext HTTP on port 443 and counted raw chunk framing | Use a bounded, verified HTTP(S) client through the tunnel, check status, decode bodies | `internal/client/adaptive.go` |
| Probe failures never aged out of the reported loss window | Track the latest probe outcomes, including successful recovery | `internal/client/health.go` |
| Concurrent encrypted writes could reorder nonces/frames; partial writes were accepted | Serialize complete frame writes and reject short writes | `internal/protocol/crypt.go` |
| Cached TLS sessions could skip the current pin check | Verify pins at connection verification, including resumption | `internal/transport/` |
| Proxy headers were trusted from arbitrary direct panel callers | Accept proxy identity/original-host headers only from the loopback proxy boundary | `internal/panel/handler.go` |
| Console inline scripts were blocked by the existing CSP | Allow exact shipped script hashes, not unrestricted inline scripts | `internal/panel/page_csp.go` |
| Replacement client could start before the old client released its ports | Wait for the old process before single-instance detection | client update and startup code |
| Update tags, metadata, and download destinations were loosely parsed | Canonical version parsing, bounded metadata, scoped artifact URLs, duplicate detection, manifest status checks | `internal/client/update.go` |
| Keyless legacy rows bypassed the configured v5 migration deadline | Require a registered verification key after that deadline | `internal/server/server.go` |

The recovery console is `/admin/ssh-keys`. Public keys and their fingerprints
must be verified directly with the device owner before replacement. Do not
paste private keys into the panel. Key replacement returns the device to
pending; approval is intentionally separate, including during auto-accept.

## Verification scope

Regression coverage includes carrier timeout/cancellation, sticky fallback,
control/probe backoff, stable identity creation, key-file concurrency,
public rekey refusal, authenticated recovery, TLS pin checks, CSP script
hashes, rolling telemetry recovery, HTTPS/chunked probes, and updater handoff.

A synthetic SSH forwarder runs the real SSH -> WebSocket -> AEAD -> mux
stack with repeated 2 MiB, 20 MiB, and 2 MiB transfers, checking hashes and
warm-session reuse. It also exercises a legacy-only WS listener.
This is not a throughput benchmark against a production firewall, nor proof
of the cause of every previously reported client exit.

Release gates: `gofmt`, `go vet ./...`, `go test ./...`, race tests on Linux
and Windows CI, and `govulncheck`. Published client artifacts require both
the tag-bound manifest signature and the legacy bare signature.

## Remaining priorities

1. **Protocol v6 design:** server challenges, signed ephemeral key exchange,
   and independent session secrets. Current inner keys derive from token +
   salt visible to the trusted carrier terminator. V5 proof of possession
   authenticates a device; it does not give the inner stream independent
   forward secrecy from that endpoint.
2. **Replay-cache pressure:** avoid evicting unexpired entries under a flood,
   or move to a challenge-based handshake with appropriately bounded replay
   state. Age-ordered eviction is not a complete replay defense at capacity.
3. **Update freshness:** the version floor prevents installing older releases
   but does not prove that the release feed is current. Design signed
   freshness metadata and recovery paths for unavailable mirrors/clocks;
   ensure bandwidth-saving modes cannot indefinitely defer critical updates.
4. **Credential isolation:** an operation-scoped local broker limits accidental
   disclosure; a malicious same-user shell can still access backups or DPAPI.
   Strong isolation needs a separately owned service and operator approval.
5. **Telemetry and attribution:** authenticate direct posture updates and
   carefully forward original source addresses for sidecar ingress. An SSH
   loopback hop otherwise hides the network address from travel detection.
6. **Operational hygiene:** retire legacy shared SSH keys only after fleet
   adoption is verified; improve stale-device revocation/reconciliation;
   rotate previously exposed tokens and protect backup material.
7. **Measured traffic behavior:** compare captures against real clients before
   changing pacing/padding. A browser UA or OpenSSH banner alone is not an
   exact implementation fingerprint. Avoid promises of undetectability.
8. **Extra carrier pilot:** see [Xray/REALITY assessment](XRAY-REALITY.md).

No production kill-switch, admission, bandwidth, or firewall policy should
be silently changed as part of a code-quality release.
