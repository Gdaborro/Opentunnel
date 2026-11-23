# Hardening operations and migration (work in progress)

These interfaces/templates are **not permission to upgrade a live fleet**.
The seven gates in `PRE-1.2-HARDENING.md` still apply. No hardening tag has been
selected, no operator keys rotated, and no service installed by this work.

## Connection authentication migration

1. Preserve verified source/artifacts, configuration, TLS credentials, node
   inventory and a consistent database backup. Keep recovery evidence private.
2. Provision independent inner TLS identities/pins without requiring them on
   old configurations. Leave `require_channel_auth = false` during canaries.
   The panel advertises v2 channel support only to new clients that request it;
   the legacy v1 capability response stays unchanged.
3. Explicitly export a v2 canary profile with `otu-pool --require-channel-auth`.
   Every node must have independent TLS pins. Import/selection still requires
   exact operator-fingerprint consent. Default-server clients can explicitly
   set `inner_tls_pins` and `require_channel_auth = true` after verification.
4. A verified v6 session permanently latches that identity against v5/v4. Do
   not test this migration by modifying the everyday device's real settings.
5. At the local authority, run `otu-migrate --database <existing-panel.db>`.
   Migration refuses any approved identity without a verified channel canary.
   Enable only with a new `--backup`, `--enable-channel-auth`, and exact
   `--confirm-pool` / `--confirm-authority` values. Coordinate new panel/relay
   config requirements before restart; a policy mismatch refuses startup.

### Rollback boundary

An older released executable does not understand the new downgrade latch.
**Do not run it against upgraded identity state and call that security-safe.**
Before enforcement, canary rollback requires a preserved pre-canary snapshot
and explicit review of all subsequent bans, revocations and usage; an old
backup must not erase newer operator policy or quota charges. After enforcement,
prefer rolling back to a previous channel-capable candidate. Full old/new
stored-state rollback still needs release acceptance; no automated weakening or
database restore command is supplied here.

## Central authority and independent relays

- Only `otu-panel` at the authority owns `panel.db` and administrator/enrollment
  account hashes. Its dedicated `authority_listen` uses a separate TLS 1.3
  identity and an explicit JSON node ID/SPKI inventory (`authority_nodes`).
- Every relay has distinct `authority_client_cert` / `authority_client_key`,
  `authority_node_id`, `authority_url`, `authority_id`, `authority_pins` and
  `pool_id`. Remote mode requires inner mutual TLS and v6. It never opens a
  local DB or falls back to shared/static credentials. Remote `otu-panel`
  startup is refused.
- `/internal/otu-authority/v1/` exposes policy, authentication-latch commits,
  filtering, bounded accounting, identity-bound control/telemetry and node
  diagnostics. No administrator sessions, approvals, rekeys, SQL export or
  authorized-key file operations are exposed to nodes.
- Node public enrollment/status forwarding preserves device proofs and the
  authenticated resolved source address. Enrollment passwords are never
  retained by the relay/client and do not approve a device.
- Reservations are charged before transmission. Lost acknowledgements/crashes
  may overcount one grant, never silently allow unlimited traffic. Settlements
  are grant/node/generation/day-bound and idempotent. They do not refill rate
  budgets. Unsettled grants are never automatically refunded.
- Authority loss denies new grants and new sessions. A previously authorized
  in-flight chunk may finish; a one-second policy watcher closes idle transfers.
  Authority latency and per-node journal capacity bound throughput; benchmark
  intended deployments before promotion. This is not a database-replication or
  high-availability consensus system. Do not start cloned independent writers.
- Credential removal takes effect when the authority is restarted with the
  reviewed inventory (including active HTTP keepalives). Accept at most two
  explicit pins per node for a bounded rotation window; never share credentials
  across nodes/operators. Review the inventory/rollback backup together.

`deploy/hardening/*.service` are least-privilege reference units. Creating OS
accounts, ownership/firewall rules, bounded certificates, service migration and
SSH forwarding-user separation requires operator review and real-host tests.
The relay identity has no access to authority DB/config; the authority process
is not root and does not manage system-wide network settings.
Provisioned API/inner-TLS files are bounded read-only inputs, not chmod-on-read
user state. Install them under root-owned, non-user-writable parent directories,
readable only by the relevant service group (for example 0640 on Linux); verify
Windows protected ACLs separately. Certificate/key readers cannot substitute
for that ownership ceremony.

## SSH desired state

Managed ownership survives row deletion, rekey and missed hooks. Reconciliation
hardens/deduplicates desired keys, removes explicitly managed revoked keys and
preserves unrelated operator entries/comments. A missing explicitly enabled
file is recreated, not silently skipped. SQL/read failures do not become an
empty desired set. A committed admission action with a failed file apply returns
HTTP 202 and `ssh_reconcile_pending=true`; minute reconciliation retries it.

Do not mistake file revocation for terminating an already established SSH
connection. Relay generation/admission checks still gate every forwarded data
stream. Multi-host remote SSH inventory is not replicated by this API.

## Signed update channels and provenance

- Existing installs stay on `update_channel = "stable"`. `canary` and
  `candidate` require explicit local config. GitHub names/labels only discover
  releases; the offline signed bundle authorizes exact channel, sequence,
  cohort, artifacts, hashes/sizes, source commit, toolchain and recipe.
- All versions after the released v1.1.10 ceiling require a signed bundle. The
  future milestone's release stamp must also set `ReleaseBundleFloor`; it is
  not a feature/version announcement. Existing v1.1.10 signatures remain valid.
- `tools/releasebundle` creates unsigned inventory for a frozen clean source.
  It never signs or publishes. Clean source/buildinfo/`BUILD-PROVENANCE.json`
  are consistency declarations, not authenticated reproducible-build evidence.
  Extend/review the scoped in-process signing
  broker for `otu-release-bundle-v1\0` before real release signing; never export
  raw release keys or use a generic unrestricted command workaround.
- `tools/buildcandidate` performs the fixed core/companion build recipe into a
  **new external** directory with an explicit exact native Go executable. It
  disables local GOENV/workspace/CGO/flag injection, sets readonly modules and
  validates pristine source before/after builds. Git status is not sufficient:
  raw checkout bytes must match Git objects, with no ignored build inputs.
  Windows line-ending conversions are refused; create an unfiltered checkout
  rather than rewriting an everyday development tree.
- `tools/releasebundle --prepare-metadata` writes a bounded deterministic
  USTAR/gzip source archive from exact regular Git blobs, per-product module
  inventories and `BUILD-PROVENANCE.json`. Generation and full verification
  check platform/package/edition/toolchain/VCS identity, dependency versions and
  sums against archived source, and exact SBOM bytes. Source archive paths,
  expansion, tables/buildinfo strings and text reads are bounded and new-only.
  The full verifier rejects a valid synthetic signature over arbitrary fake
  binaries/source; the compatibility verifier refuses post-v1.1.10 use.
- Go omits linker flags under `-trimpath` and omits off-PGO metadata. Buildinfo
  therefore cannot prove version/floor/linker recipe stamps. Those checks and
  same-host hash repetition are **not signing authorization**; independent
  authenticated reproduction plus a scoped signing ceremony remain required.
  CI output is explicitly unsigned consistency evidence, never an auto-release.
- Root rotation needs both old and new threshold signatures and an explicit
  local ceremony. Chains/checkpoints are persisted, bounded and fail closed on
  corruption. Actual root rotation/recovery is not complete until the operator
  performs the ceremony and old/new release acceptance passes.
- Guarded Windows replacement retains a unique digest-verified backup and
  waits for local startup readiness. Local listeners being ready does not
  establish fleet uptake or a successful remote data transfer. Linux auto-swap
  is not implemented; Linux artifacts still require signed operator rollout.

## Windows client editions and local preview boundary

- The `cdn.aborro.dev` edition preserves the released default identity directory
  and historical update asset `otu-client-windows-amd64.exe`. It includes public
  endpoint/TLS/SSH trust only, never a device/shared private credential. Existing
  config files are not rewritten to introduce the new defaults.
- Compile-time `genericclient` builds have an incomplete owner-provisioned
  `client.toml`; the endpoint and independently verified public TLS pin must be
  configured before startup. Generic credentials/status/update trust use
  `opentunnel-generic` and updates require `otu-client-generic-windows-amd64.exe`.
  They cannot select the legacy hosted asset or silently reuse its credentials.
- Both editions mutate the same Windows user proxy, so they share the network-only
  journal/lease. Separate identity directories do not permit simultaneous proxy
  ownership or recovering a live client's settings. For multiple independent
  operators, explicitly imported signed pool profiles remain the isolation path.
- `--build-info` and `--print-default-config` are state-free declarations before
  identity/update/network side effects. They are not authenticated provenance.
- `scripts/build-client-packages.ps1` builds **unsigned local previews only** into
  a new external directory. Previews stamp `LocalPreview`, disable automatic
  update/freshness authorization and expose the unreleased status in preflight/
  runtime diagnostics. This is not a release version, a signing bypass or fleet
  migration. Real publication continues to require all seven gates.
- Targeted identity reset scripts may accompany the private hosted package but
  never execute automatically or appear in the generic package. Archive exactly
  the copied default identity, preserve bans/recovery/update trust and obtain
  separate administrator approval for each new PC. See
  the separately delivered private reset instructions; it is not secure disk
  erasure or an unban. PC-specific scripts/names are not public source; preview
  packaging needs an explicit scripts-only private input.

## Scope, privacy and diagnostics

`otu-client --status` reads a bounded private status summary before identity,
updates or network recovery. It includes protected proxy scope, operator/node,
admission/failure category, direct-bypass inventory/count, channel/freshness and
pending browser-policy cleanup—never tokens, keys or enrollment passwords.
Stale status is not proof the client is running.

`telemetry = "minimal"` is an explicit client opt-in. `/admin/privacy` controls
server storage/retention; default `preserve` keeps existing monitoring. Minimal
stops new domain visits/IP history and stores only version/platform rather than
hardware posture. Existing records are not silently erased. Immediate age
purging requires explicit confirmation. Approval, bans, abuse containment,
aggregate accounting and filtering remain enforced. A relay operator can still
observe traffic; minimal telemetry is not anonymity or no-logs certification.
