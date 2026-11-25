# Changelog

## v1.1.13 - R7 hardening

- Add a separate 256-row unauthenticated pending budget for login-free signed
  pools and default bootstrap, with transactional concurrency checks and no
  change to account quotas or approval behavior.
- Authenticate relay-to-panel forwarded metadata with fresh, expiring, single-use
  HMAC proofs bound to client IP, original host/scheme, method, URI and body.
  Reject forged, replayed or failed handoffs instead of trusting loopback headers
  or demoting them to direct loopback identity; preserve direct access and the
  mutually authenticated central-authority path.
- Update Gorilla WebSocket to the GO-2026-6278-fixed revision for cryptographic
  mask-key generation without changing the reviewed Xray/REALITY source commit.
- Add bounded, review-only duplicate-identity detection across approved and
  pending devices. Canonical key reuse and hardware-fingerprint reuse raise
  throttled `security` warnings without changing either identity, creating bans,
  or treating a clone, reinstall, or spoof as proven.
- Show signed-pool enrollment conflicts and other security findings in Sentinel.
  Bad-signature/downgrade attempts no longer trigger automatic source-IP bans;
  generic malformed/unknown-token brute-force protection remains enabled.
- Add Sentinel as an integrated main-console tab, including stale-read warnings,
  mode read-back, and a link to deliberate administrator rekey. The legacy
  `/admin/sentinel` bookmark redirects to `/admin/#sentinel`.
- Preserve the last-known-good cryptographic identity during anomaly review.
  There is no automatic HWID-based reset/restoration, rekey, or ban. Hardware
  fingerprints remain risk evidence rather than hardware attestation; recovery
  still requires expected-key verification, out-of-band confirmation, and
  separate administrator approval.

Version and update floor raised to v1.1.13. The candidate channel remains at 0%
automatic rollout with the existing root-1 trust anchor. This remains a
Windows/Linux application-proxy release, not a system-wide VPN/TUN driver. The
72-hour pilot, independent-host/load acceptance, full real-device lifecycle
acceptance and independent external security review remain separate gates.

## v1.1.11 - pre-1.2 hardening

- Add explicit `transport = "h3"` selection using the existing pinned HTTP/3
  transport and stream-rotation bounds. UDP-blocked networks still fail over to
  WS-TLS/SSH rather than weakening certificate or host-key checks.
- Keep the canonical `v` tag in the client's `--version` output and signed-update
  preflight so both v1.1.10 and newer clients accept a correctly stamped upgrade.
  Server/panel display versions remain unprefixed.
- Fix signed-update display-version preflight, restrict the update helper to the
  exact private journal before any ACL/lock work, and recover the crash window
  where the old executable was moved but the staged one was not installed.
- Parse recovery arguments by actual flag semantics, make plain bootstrap a
  first-run-only operation with fail-closed approval state, and replace global
  image-name termination with PID/creation/path-verified `--stop` recovery.
- Reject root rotations issued after predecessor expiry, off-recipe ARM64 client
  artifacts and malformed legacy freshness timestamps; fail closed for unknown
  sources when anti-abuse source maps saturate instead of discarding punishment.
- Fail closed on stale/failed policy, authority and accounting reads; bind usage
  to authenticated identities and complete managed SSH desired-state
  reconciliation without deleting unrelated administrator keys.
- Add optional, independently pinned mutual TLS 1.3 channel authentication and
  fresh v6 connection proofs with durable downgrade latches. Migration is
  explicit: existing configurations are not silently made more restrictive.
- Correct automatic HTTP/SOCKS setup, transfer cancellation/drain ownership and
  network-change handling. Preserve orphan proxy journals, retry explicit
  `--restore`/`--restore-from` across the forced-stop lease window, and keep
  double-click startup failures visible instead of looking like instant crashes.
- Add a narrowly authenticated central authority for independent relay nodes,
  with per-node credentials, conservative aggregate reservations and denial of
  new work during authority loss. Relays cannot open the authority database or
  administrator sessions.
- Add read-only secret-free client status, opt-in minimal telemetry and bounded
  retention controls without silently removing monitoring, bans or accounting.
- Separate hosted and generic client identity/update state while retaining the
  released hosted asset name and sharing only the Windows network-recovery lease.
- Add signed release-bundle inventory, candidate/canary/stable channel policy,
  root-rotation verification, fixed source/build provenance and least-privilege
  reference service units. These contracts do not themselves authorize a release.
- Add repeatable authority, rollback, transport and mixed-traffic soak harnesses,
  native executable acceptance, frontend gates and exact-source artifact checks.
- Stamp the fixed release recipe's display version without the canonical `v`
  tag prefix while keeping `v` on the update tag and compatibility floor. The
  previous stamp made staged `--version` smoke output inconsistent and blocked
  the release build job.
- Normalize checkout roots before the link check, so a trailing separator or
  final `/.` cannot make `Lstat` follow a linked repository root. Added symlink
  and junction regressions.
- Describe a saved-device-name mismatch as a likely copied identity and direct
  the operator to the separate identity-reset package; never reset credentials
  automatically.

Version and update floor raised to v1.1.11. This remains a Windows/Linux
application-proxy release, not a system-wide VPN/TUN driver. Existing admission,
privacy, pool and listener settings are preserved; optional channel/pool features
still require explicit provisioning and approval. See `docs/PRE-1.2-HARDENING.md`
and `docs/HARDENING-ACCEPTANCE.md` for the evidence required before promotion.

## v1.1.10 - trusted server pools and enrollment accounts

- Add explicitly imported, Ed25519-signed, credential-free self-hosted profiles
  with bounded expiry, rollback protection and explicit operator consent.
- Choose the lowest measured verified latency within the selected pool; bounded
  setup failover never changes operator or retries a password to another entry.
- Isolate each operator's device key, token, fingerprint, approvals and bans;
  imported pools do not inherit default SSH/carrier credentials or learned trust.
- Add separate password-gated enrollment user accounts. Login permits enrollment
  only; a device still needs administrator approval and registered-key tunnel
  authentication. Protected pools have no unsigned legacy downgrade exception.
- Bind each pool to a single local approval/accounting authority, add signed
  status and durable bounded HTTP-proof replay protection, and provide the
  `otu-pool` source tool for dedicated operator keys and profile export.
- Preserve orphan Windows proxy-journal recovery when selected pool state is
  invalid; retain the existing default configuration and device identity until
  an operator profile is explicitly selected.
- Cover trust, account/admin separation, approval/revocation, ranking/failover,
  cancellation, scoped identities and registry-free executable acceptance.

Version and update floor raised to v1.1.10. Updating clients and server/panel
does not enable a pool, change admission/kill-switch settings, open a listener,
or force device reenrollment. Multiple entries must share one local database;
independent remote databases are not synchronized federation. Known limitations
from the separate audit remain; this release is not a production-readiness or
stealth certification. See `docs/TRUSTED-SERVER-POOLS.md` for provisioning and
`docs/UPDATE-TRANSACTION.md` for delivery and supervised-update behavior.
Offline or auto-update-disabled devices need reconnection/manual delivery;
publishing an update is not proof of fleet adoption.

## v1.1.9 - Windows recovery ownership fixes

- Skip unknown or conflicting optional browser-policy bundles without treating
  unreadable originals as absent or terminating valid WinINET startup.
- Preserve failed optional cleanup in private per-session records; retry across
  restarts without blocking mandatory startup or recapturing stale policy values.
- Scope legacy WinINET/Chromium custom-bypass migration to journal-owned applied
  bundles, and preserve v1.1.5's exact-address contaminated-original recovery rule.
- Journal partial/explicit restoration, retain corrupt/persistence-failed evidence
  and expose nonfatal apply/cleanup warnings without promising browser routing.
- Add synthetic recovery regressions, fixture-only Windows `--auto-proxy` legacy
  handoff acceptance and CI triggers for `fix/*` branches.

Version and update floor raised to v1.1.9. No transport, authentication, admission
policy or listener enablement changes. Server/panel deployment is not required
for this Windows client recovery update. See `docs/WINDOWS-RECOVERY.md` for
pending-cleanup behavior, older-client compatibility and acceptance boundaries.

## v1.1.8 - update-handoff recovery fix

### Fixed
- The client no longer exits during `--auto-proxy` startup when
  `HKCU\Software\Policies` browser policy keys are read-only. Policy-key
  apply and restore are best-effort again, matching v1.1.5; the WinINET
  system proxy write remains mandatory.
- Update handoff from v1.1.5 now recovers its legacy settings journal. The
  old journal recorded the applied proxy server but not the config-specific
  bypass list, so v1.1.6+ mistook the applied bypass for a third-party
  change and refused to start. Recovery now restores the bypass list while
  still refusing to overwrite a genuinely replaced proxy server.
- Added regression coverage for read-only policy apply, mandatory proxy
  write failure, best-effort policy restore and legacy-journal recovery.

No transport, authentication, protocol or admission behavior changed.
Version and update floor raised to v1.1.8. Supersedes the withdrawn v1.1.7
prerelease.

## v1.1.7 - managed-PC proxy startup fix

### Fixed
- The client no longer exits during `--auto-proxy` startup when
  `HKCU\Software\Policies` browser policy keys are read-only. Policy-key
  apply and restore are best-effort again, matching v1.1.5; the WinINET
  system proxy write remains mandatory.
- Added regression coverage for read-only policy apply, mandatory proxy
  write failure and best-effort policy restore.

No transport, authentication, protocol or admission behavior changed.
Version and update floor raised to v1.1.7.

## v1.1.6 - relay hardening and supervised updates

### Security and recovery
- New streams and traffic reservations use fresh authoritative policy; pending,
  revoked, expired and failed policy reads deny data. Identity generations bind
  warm sessions; bans remain durable after device deletion.
- Device rates/quotas are aggregate across sessions, carriers and directions.
  SQLite writer transactions lock before snapshot reads to prevent stale
  read-to-write upgrades interrupting legitimate transfers.
- Updates preserve existing signature compatibility and add signed, bounded
  freshness metadata. Replacement is supervised for readiness/stability, with
  verified rollback and interrupted-transaction recovery.
- Windows proxy recovery verifies readback, retains conflict/failure journals
  and uses an independent parent-exit helper. Recovery remains subject to OS,
  disk and permission limitations.
- Host networking/crypto dependencies are patched; source and release-binary
  vulnerability scans are required independently.

### Reliability and panel
- Forwarded WebSocket/mux closure is delivered before cancellation, avoiding
  orphaned relay sessions. HTTP/3 uses native stream deadlines and checked flush.
- HTTP/SOCKS proxy buffering, half-close, upgrades and UDP association teardown
  are bounded and regression-tested.
- The first-run panel setup API works with the SPA. Kill-switch detail saves
  preserve concurrent operator toggles and refresh the displayed state.
- Telemetry proofs, relay-heartbeat metrics, auth/session bounds, frontend
  dependency audit and source/embed reproducibility are strengthened.

### Optional additions and rollout
- Managed fixed-target RAW/VLESS/REALITY companion and independent pinned
  mutual TLS 1.3 are available **only when explicitly provisioned and enabled**.
  This release does not automatically download Xray, open a new public listener,
  change DNS/firewalls, require inner TLS, or change existing admission policy.
- Version and update floor raised to v1.1.6. Legacy signature assets remain
  available for the first upgrade; offline or auto-update-disabled clients need
  reconnection/manual delivery. Upload success is not proof of fleet adoption.
- See `docs/HARDENING.md`, `docs/REALITY-MANAGED.md` and
  `docs/UPDATE-TRANSACTION.md` for validation and rollout boundaries.

## v1.1.5 - carrier reliability and identity hardening

### Security
- Minimum Go toolchain raised to 1.27.4 for the net/http crash advisory
  GO-2026-6859; CI follows the patched minimum in `go.mod`.
- Public bootstrap requests can no longer replace an approved device key or
  use auto-accept to approve a conflicting identity. Administrator-assisted
  replacement at `/admin/ssh-keys` requires separate approval.
- Invalid-signature and downgrade attempts still raise critical alerts but
  cannot auto-kick their named victim; sustained failures target the source.
- TLS pins are rechecked during connection verification, including cached
  sessions. Direct callers cannot spoof trusted panel proxy headers.
- The configured v5 enforcement deadline now applies to keyless legacy rows.
- Update tags and asset destinations are parsed strictly, metadata is bounded,
  duplicate assets are refused, and manifest HTTP failures are checked.

### Reliability
- SSH setup is bounded beyond the TCP connect; legacy WS retry gets a fresh
  forwarding channel. Losing the public-key cache does not regenerate identity.
- Mux selection no longer corrupts its session list. Capacity drains active
  streams gracefully, waiters share setup instead of stampeding, and warm
  sessions outlive the request that created them.
- Sticky SSH is not preceded by dead QUIC on every request. Control/probes
  share backoff, profiles use their actual shaping settings, and H3 follows
  current entries and learned pins.
- Old pools, transports, telemetry loops and database workers shut down cleanly.
- Throughput probes perform verified HTTPS and decode HTTP bodies; old loss
  samples age out correctly. Encrypted frame writes are serialized and short
  writes are rejected.
- Updated clients wait for the old process before checking proxy-port ownership.
- Standalone console scripts are hash-allowed by CSP without unsafe inline
  scripting. The read-only device-limits endpoint works again.

### Review and verification
- Added reliability/security regression coverage, including repeated large
  transfers through a synthetic authenticated SSH/WS/AEAD/mux stack.
- Documented findings and the decision-gated Xray/REALITY carrier pilot in
  `docs/REVIEW.md` and `docs/XRAY-REALITY.md`.
- Version and update floor raised to v1.1.5. No new carrier is enabled and no
  operational admission or kill-switch setting is changed by this release.

## v1.1.4 - dependency security pins
- Updated Brotli and klauspost/compress to fixed releases for reachable
  decompression advisories; uTLS version unchanged.

## v1.1.3 - SSH-tier recovery
- Added startup authorized-key reconciliation, per-device SSH-key preference,
  rejection backoff and reduced health/ECH log noise.
- The public re-registration behavior introduced here is superseded by the
  administrator-only replacement workflow in v1.1.5.

## v1.1.1 — sentinel console + hostile-network intel

### Added
- **Standalone sentinel console** at `/admin/sentinel` (same pattern as
  the kill-switch page — no SPA rebuild): switch the response mode
  (`off` | `alert` | `respond`) and watch recent findings, auto-refreshing.
- **Client-side hostile-network reporting**: the client's adaptive stealth
  already latches when a network intercepts TLS; health reports now carry
  that signal in-band, and the relay sentinel raises a throttled
  per-device alert — the operator sees which networks are actively
  MITM'ing devices.

### Changed
- Update floor raised to v1.1.1.

## v1.1.0 — proactive sentinel (detection + automated response)

Every audit round so far was reactive: fix the hole after it is found.
This release flips the direction — the relay and panel now watch their
own traffic for attack patterns and, when configured to, respond
automatically. No wire-protocol changes; the 1.0.1 client is unaffected
(the update floor moves to v1.1.0).

### Added
- **Relay-side sentinel** (`internal/server/sentinel.go`): rolling-window
  detection for auth-failure floods, active probing (non-upgrade requests
  on the tunnel path, junk TLS handshakes), rate-limit pressure,
  per-device session churn and per-IP session bursts. Findings land in
  the panel alert feed (kind `sentinel`), throttled per subject — no
  alert storms, ever.
- **Response ladder** — `sentinel_mode` is `off` | `alert` | `respond`
  (default `respond`; GET/POST `/admin/api/sentinel`):
  - auth-failure flood from one IP → 30-minute guard ban (the peer keeps
    receiving the decoy page; the ban stays invisible);
  - stolen-token evidence (v5 signature mismatch, or a v4 downgrade from
    a peer that has proven v5 key possession) → 60-minute automated
    device kick + critical alert;
  - impossible travel (same device from two countries within 30 minutes)
    → 30-minute automated kick + critical alert.
  Every action self-expires; allowlisted operator devices are never
  auto-kicked.
- **Panel-side detectors** (`internal/panel/sentinel.go`, one-minute
  tick): impossible travel (new `peer_ips` connection history, GeoIP),
  source-IP spread per device (shared or leaked token), and registration
  bursts per /24. Throttles persist in the DB — restarts never re-fire.
- **TLS-layer scanner intel**: handshake errors are classified (obsolete
  TLS, plain HTTP sent to the TLS port, junk bytes, cipher mismatch) per
  source and fed to the sentinel as probe events.
- Registration now records the registrant's source IP (`last_ip`) so the
  burst detector works before the first tunnel session.

### Changed
- Stolen-token and downgrade alerts flow through the sentinel: throttled,
  and able to drive the automated response in `respond` mode.
- Update floor raised to v1.1.0 (build-stamped as of 1.0.1).

## v1.0.1 — security hardening (audit round four)

Ten hardening items across the relay, panel, client and update chain. No
wire-protocol changes; existing clients keep working, and every fix is
covered by new regression tests.

### Fixed
- **SSH key injection (N-11 chain)**: `ssh_pubkey` is validated and
  canonicalized (single-line ed25519 only) — newline-smuggled keys are
  refused. The canonical `authorized_keys` line now carries a forced
  command: `restrict` alone never prevented non-PTY command execution or
  SFTP (proven empirically against OpenSSH 10.0), while forwarding — the
  only channel the tunnel uses — is unaffected.
- **Revocation is real (N-12)**: banning or deleting a device removes its
  key from `authorized_keys` immediately.
- **SSRF filter fails closed**: zone identifiers (`::1%lo`), NAT64
  literals, reserved ranges and unparseable hosts are refused; previously
  anything `net.ParseIP` could not parse walked straight through to the
  loopback plane.
- **Control channel identity binding**: verdicts and health records are
  bound to the token that authenticated the session; the wire token field
  can no longer read another device's state or write rows under arbitrary
  token strings.
- **Mid-session enforcement**: bans, kicks and quotas are re-checked per
  stream (1s cache) instead of trusting the session-start snapshot; UDP
  streams re-check periodically too.
- **Trusted-channel gating for durable state (N-2)**: only the in-band or
  pinned channels may set the ever-approved marker, clear bans, or persist
  a hard ban; plain bootstrap responses are display-only.
- **Relay header stamps are unpickable**: client-named `Connection`
  headers are stripped before stamping, closing the rate-limit / login
  lockout bucket collapse.
- **Update floor is build-stamped**: each release raises `MinUpdateTag` to
  its own tag, so a middleman can no longer replay-freeze the fleet on
  older — but genuinely signed — releases.
- **DoS bounds**: per-stream setup deadlines (TCP + UDP), lazy UDP
  sockets, a 4 KB login body cap, server read/write timeouts, and
  age-ordered replay-cache eviction.
- **Panel hygiene**: `no-store` on admin APIs; malformed in-band pins are
  rejected before persistence; `/admin/api/abuse` reports live counters
  instead of a hardcoded note.

### Changed
- DoH ECH fetches read the full response body (robustness on segmented
  TCP).
- Log hygiene: quoted visited domains; safer token prefixes.

## v1.0.0 — the undetectability overhaul

One big release: containment, ECH, and a traffic-shape pass across every
tier. Existing v0.9.x clients keep working unchanged — the server-side
enforcement is backward compatible, and every client-side feature is
fail-open.

### Added
- **Encrypted Client Hello (ECH)**: the client fetches the entry host's
  ECHConfigList over DoH (HTTPS DNS records) and rides it on every
  Chrome-hello dial — the real SNI travels HPKE-encrypted behind the
  config's cover name. The outer hello is pin-checked through uTLS's
  rejection callback, and a rejected attempt fails open: the socket is
  closed and retried once without ECH. The control plane (status polls,
  health reports) uses the same hooks, so every flow tells one SNI story.
  Dormant until the entry host publishes an ECH config.
- **SSH-tier containment** (panel → System): a sustained per-device
  bandwidth cap plus a daily byte budget for the ssh transport's ingress.
  Once the budget is spent, new streams degrade to a trickle rate
  (default ~200 kbps) — pages keep loading, media cannot, and devices
  that fan into one relay IP stop reading as a media relay on the wire.
- **Traffic-shape mimicry**: capped ssh-tier bulk drains in segment-sized
  bursts with jittered gaps — a streaming player's fetch cadence, not a
  flat line-rate feed. Sub-threshold (interactive) traffic stays smooth.
- **In-band ssh_host learning**: the relay announces its public ssh-tier
  dial target through the authenticated control channel; clients persist
  it so the ssh tier keeps a dialable target after the tunnel domain
  moves behind a CDN (CDNs do not proxy port 22).
- **h3 session byte cap**: h3 sessions rotate at 64 MiB, below CDN
  request-body limits, so fronted bulk is never cut mid-stream.

### Changed
- **Keepalive jitter on both ends**: the relay's sessions no longer ping
  on a fixed 20 s cadence — randomized per session (20–35 s) with a
  matching receive-silence window, because fleet-wide lockstep pings are
  a flow-level correlation signature.
- Decoy asset fallbacks serve the site's own 404 page instead of Go's
  native "404 page not found" text.

### Notes
- v0.4.0–v0.9.30 releases predate this file's upkeep; see the GitHub
  releases and git tags for their notes.

## v0.3.0 — multiplexing, UDP relay, share links

### Added
- **Connection multiplexing** (protocol v3, smux): one authenticated tunnel
  session carries every browser connection — no TLS+WebSocket handshake per
  site, fewer connections on the wire (better mimicry). Enabled by default
  (`mux = true`); automatic session pool with keepalive and reconnect.
- **UDP relay**: SOCKS5 UDP ASSOCIATE over the tunnel via dedicated framed
  streams — DNS-over-UDP, QUIC/HTTP3, voice/games now work through opentunnel
  (`udp = true`, requires mux).
- **Share links + QR** (`otu://…`): `otu-client -c config -share-link`
  prints a self-contained connection link (embeds token) plus an ASCII QR;
  `-qr file.png` writes a scannable PNG.
- `-print-fingerprint` server flag; protocol mode-byte architecture keeps
  legacy single-target sessions fully compatible.

## v0.2.0 — hardening & adaptive stealth

### Added
- **Protocol v2**: per-session salt exchange + inner AES-256-GCM framing
  (HKDF-SHA256 from token+salt), direction-separated nonce counters.
- **Adaptive profiles** (`auto` default): fast → balanced → stealth ladder;
  sticky escalation on failure, pre-escalation on slow responses (>3 s TTFB),
  automatic re-probe back down after a 10-minute cool-off. Transition logging.
- **uTLS Chrome ClientHello** (`balanced`/`stealth`) via
  refraction-networking/utls, ALPN surgically pinned to http/1.1.
- **Traffic shaping**: size-bucket padding (64B…16KB buckets + jitter) and
  per-frame write jitter in `stealth`.
- **Server guard**: per-IP concurrent-tunnel caps, global ceiling, 3-strike
  escalating bans on failed handshakes — over-limit/banned peers receive the
  normal decoy page (no signal to censors).
- **Windows console-close/logoff/shutdown restore**: SetConsoleCtrlHandler
  guarantees settings restoration even when os/signal never fires.
- `--version` on both binaries; `-print-fingerprint` on the server;
  adaptive transition logs.

### Changed
- Each AEAD frame now travels as one transport record (was two) — fewer TLS
  records, steadier traffic shape.
- Frame buffers recycled via sync.Pool.
- Self-signed server certificates persist under `%LOCALAPPDATA%\opentunnel`
  so client fingerprints survive restarts.

### Fixed
- Client read only one byte of the two-byte target response, treating every
  successful connect as a failure (M1 integration bug).
- uTLS path skipped pin-only trust mode and consulted system roots.

## v0.1.0 — M1

- First working end-to-end relay: SOCKS5 + HTTP CONNECT inbound,
  TLS+WebSocket transport with certificate pinning, decoy website for
  unauthenticated traffic, Windows per-user auto-proxy with journal +
  crash-safe restore, TOML configs, deploy files (Docker/systemd/install.sh).
