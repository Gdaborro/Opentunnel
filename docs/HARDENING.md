# Unreleased hardening and acceptance gates

This describes unreleased source changes based on v1.1.5, reviewed on 2026-11-11/12.
It is not a published release, a universal-bypass claim or a production-readiness
certificate. No network-specific measurements or fleet credentials belong here.

## Shared invariants

- Only an effectively approved device may send data. Pending, expired,
  unknown, revoked and failed policy reads deny data.
- A handshake binds the session to the enrolled key and identity generation.
  Rekey/unban/expiry followed by approval does not revive an old session.
- Live TCP and UDP policy watchers act without client cooperation, including
  downstream-only traffic. Healthy policy changes normally take roughly one
  or two seconds; a slow/failed DB read adds its bounded read budget.
- Status/control remains separate from data denial. This is not a client-side
  ban switch masquerading as server enforcement.
- Limits are shared across a device's sessions, streams, directions and
  carriers. There are also global/device stream caps and setup deadlines.
- Healthy long transfers have no fixed setup deadline left armed.
- EOF propagates through TCP and smux write halves. Errors/cancellation close
  both endpoints and join both copy workers.

## Accounting and storage

The relay obtains a consistent SQL snapshot of admission, identity, schedules,
quotas, kill-switch state/allowlist and SSH containment policy. Caches belong to
one handler/database, not to a global token namespace. New-stream admission
and reservations read authority directly; only hot-path checks use bounded caching.

Payload writes are durably reserved before transmission. Quotas are aggregate,
not a per-stream completion estimate. SSH daily usage is stored in
`ingress_usage` and survives a relay restart. An interrupted reserved write may
conservatively overcount an in-flight chunk; this is not delivery-acknowledged
billing. Refunds are generation- and accounting-day-bound.

Additive schema changes include `approval_required`, `auth_epoch`,
`ingress_usage` and `relay_metrics`. Concurrent relay/panel migration is
serialized with a database write lock. Operator settings and their audit event
are committed atomically after validating the entire request.

Rekeys require explicit separate approval even during an auto-accept window.
New enrollment requires an Ed25519 key. Production bootstrap defaults require
pinned TLS or an explicitly managed authenticated carrier. The recovery-only
`allow_untrusted_bootstrap` flag requires independent enrollment verification;
it must not be mistaken for safe automatic enrollment through intercepted TLS.

Public health/heartbeat writes now require a device-key proof binding method,
path, timestamp, nonce and exact request bytes. Legacy read-only status remains
compatible. Signed self-reported posture is still not hardware attestation.

## Local proxies and Windows recovery

The HTTP proxy uses the standard parser/framing for bodies, persistent requests,
CONNECT buffering and upgrades. Headers, idle setup and listener counts are
bounded. SOCKS UDP consumes the complete request address, follows TCP control
EOF and pins replies to the first valid association owner. Malformed packets
cannot replace it. Relay UDP accepts replies only from recently contacted
destinations and applies pacing/accounting in both directions.

Windows snapshots preserve value existence and type, including a missing
`ProxyEnable`. Journaling completes before mutation, partial apply rolls back,
and readback verifies both application and restoration. Any failed restore
retains its recovery journal. A cross-process settings
lease prevents concurrent writers. A separate same-executable helper confirms
parent readiness before automatic settings are applied, then attempts recovery
after parent termination. Next-start recovery remains the final backstop.

Concurrent changes by another application are treated as conflicts rather than
overwritten. An explicit `--restore-from` is the operator's force-restore path.
The OS can prevent helper execution, registry writes or disk access; power-off
and killing all recovery processes cannot be covered by an absolute promise.

Local proxy and internal carrier listeners require literal loopback endpoints
by default. `allow_non_loopback_proxy` is an explicit unsafe sharing choice,
not authenticated LAN proxy support. H3 honors the configured TCP listener's
host and can be disabled with `h3=false`.

## Transport and camouflage boundaries

Pinned WS/uTLS, H3, ECH and SSH remain available. Browser-shaped ClientHello is
not proof of indistinguishability; QUIC is not Chrome-shaped, SSH is observable,
and a decoy page alone is not strong active-probe resistance.

The opt-in external adapter is configured with:

```toml
# Client: disabled unless explicitly provided
carrier_socks = "127.0.0.1:19090"
carrier_target = "127.0.0.1:8082"
# transport = "carrier" # explicit primary carrier, or leave the adaptive fallback

# Relay: separate ingress, disabled unless explicitly provided
listen_carrier_internal = "127.0.0.1:8082"
```

The external adapter is not an Xray/REALITY implementation. It does not download, launch,
configure or attest a companion. The operator must verify the companion and
its authenticated outer transport, and confine server-side carrier requests to
exactly the fixed loopback target, denying other targets and UDP. The carrier
terminator remains inside the trust boundary. It gets its own ingress marker,
not SSH-specific containment by accident.

A separate opt-in managed implementation now builds restricted RAW/VLESS/REALITY
configs, verifies a privately staged patched companion and supervises its process.
Client and server both deny arbitrary targets and UDP; the server also fixes the
final egress target. Carrier credentials are separate from enrolled device keys.
Optional pinned TLS 1.3 mutual authentication supplies independent ephemeral
session secrecy and encrypted admission confirmation. Pool teardown sends the
WebSocket closure before canceling its session, preventing forwarded session leaks.
See [REALITY-MANAGED.md](REALITY-MANAGED.md) and [XRAY-REALITY.md](XRAY-REALITY.md).

REALITY still requires a pilot with matching cover identity/target, authenticated
throughput, wrong-credential rejection, unknown-client fallback, confinement,
failure/rollback and real-network tests. Vision's direct TLS-splice optimization
does not automatically apply to an opaque opentunnel AEAD/mux stream.

## Updates, observability and build tooling

Updates retain tag/hash signature verification and the version floor. Direct
TLS/HTTP route failures can fall back to SOCKS, thin-mode deferral is bounded,
staging files are unique and flushed, and failed replacement/launch restores
the old path without deleting an existing backup. Signed-binary version
preflight is not full post-start readiness. A private same-executable helper now
waits for graceful parent exit, verifies replacement readiness/stability, checks
rollback and supports digest-verified next-start recovery. New v1.1.6+ targets
also require signed, time-bounded freshness metadata and a private rollback
checkpoint, including when the feed claims the installed version is current.
See [UPDATE-TRANSACTION.md](UPDATE-TRANSACTION.md). Real-device update acceptance
remains required; source publication is not a signed fleet update.

The split panel reads an explicitly stale-aware relay heartbeat rather than
its own process-local session counter. Heartbeat freshness is not an end-to-end
tunnel health check. Source-country changes alert for review; country-only GeoIP
inference no longer automatically kicks a legitimate roaming device.

Frontend assets are rebuilt from React source, pages are lazy-loaded, setup
accepts the bootstrap token, and saving kill-switch details does not re-submit
a stale switch value. Unused scaffolding dependencies were removed; needed
static CSS utilities are retained with their MIT notice. Build tooling preserves
previous/user-added assets and caches rather than recursively deleting them.
CI actions and the Go scanner are pinned; frontend build/audit/parity gates are
defined, including explicit review-branch triggers. Local test results and remote
CI results must be reported separately; workflow existence is not a CI pass.

Host `x/net` and `x/crypto` are patched, with the required `x/sys`/`x/text`
versions updated as well; uTLS remains pinned to preserve the selected hello.
Artifact scans are required in addition to source call-graph scans: symbols
linked into an executable can reveal findings a source reachability scan omits.

## Acceptance checklist before publication

1. Review the complete local diff and additive database migration; preserve
   operational policy and make a consistent backup of **all** DB writers.
2. Pass fresh vet, race, vulnerability, frontend build/audit and cross-build
   gates on the intended OS/toolchains. Windows tests do not establish Linux
   runtime behavior merely because cross-compilation succeeds.
3. Run real-device restore tests: normal exit, forced parent termination,
   denied/partial registry writes, logoff/shutdown, competing proxy software
   and update handoff. Lab fake-store tests must not touch a user's actual proxy.
4. Validate authenticated mixed-traffic reliability and liveness on the intended
   network. A loopback soak is not a production-firewall soak.
5. Validate companion provenance, fixed-target confinement, source attribution
   limitations and rollback before enabling a REALITY pilot or fleet defaults.
6. Review update freshness/post-start rollback, resource-pressure behavior and
   privacy/retention. Never claim universal bypass or unconditional recovery.
7. Publish/deploy only after operator approval. Retire legacy shared keys only
   after actual fleet adoption has been verified, not from download counts.
