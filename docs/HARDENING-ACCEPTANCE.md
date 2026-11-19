# Hardening acceptance checklist

Implementation and synthetic tests do not authorize stable promotion. Freeze an
exact source commit and every artifact before collecting release-gate evidence.
Keep institution/network observations, device identity and recovery logs private.

## Repeatable local checks

- `go test -race -tags=netenvfixture -count=1 -timeout 300s ./...`
- Production/fixture `go vet`, `go mod verify`, source and artifact vulnerability
  scans for every command/companion; frontend build/audit consistency.
- Build native server/panel fixtures and run
  `TestCentralAuthorityNativeExecutablesNeverUseRelayLocalDB` with
  `OTU_TEST_SERVER_BINARY` / `OTU_TEST_PANEL_BINARY` set. Test multiple processes,
  not multiple handlers all sharing one process's connection/state cache.
- Only a compile-time `netenvfixture` client may run the executable networking
  suite. Include legacy/v6 pool selection/approval/traffic, read-only status,
  SOCKS-only automatic-mode refusal, proxy recovery and updater handoff.
- `tools/releasebundle` checks all artifact hashes/sizes, signed source/toolchain,
  staged channels and explicit cohort. This is declared inventory/signature
  consistency, not authenticated source/build provenance. Offline trusted build
  authorization, reproducibility, signing history and publication are separate.
- Generic client checks: `go test -race -tags=genericclient,netenvfixture
  ./internal/config ./cmd/otu-client ./internal/client ./internal/protocol`.
  The executable generic fixture must also be built with **both** tags and
  supplied separately as `OTU_TEST_GENERIC_CLIENT_BINARY`. Test blank/invalid
  server configuration refusal, edition update-target separation, credential
  isolation and shared network-only recovery lease ownership.
- Release-contract regressions: `go test -race ./internal/releasebuild
  ./tools/buildcandidate ./tools/releasebundle ./tools/verifyrelease`. Include
  actual separately built Windows/Linux amd64/arm64 fixture metadata, malformed
  binary tables/pointers, archive traversal/links/expansion, mismatched source
  module versions/sums/SBOMs and ignored/line-ending-transformed checkout input.
  Artifact buildinfo is not proof of linker stamps or authenticated reproduction.

GitHub withdrew the picomatch advisory GHSA-fc5q-39xc-vjpf at
2026-11-18T15:38:56Z after maintainer review. On 2026-11-19, Node 26.13.0
`npm audit --audit-level=low` and an explicit lockfile/development-dependency
audit both reported zero vulnerabilities across 279 dependencies. No package,
lockfile, Vite version, override or audit suppression was changed. Keep the
audit enabled for future findings; a withdrawn advisory or zero current findings
is not a security certification.

## Soak harness

`tools/hardeningsoak` generates synthetic isolated identities, a TLS-authenticated
authority and two loopback relays. Mixed cycles include TCP uploads/downloads,
UDP and status. Deliberate authority partitions must deny data. Supply a **new**
absolute private `--state-dir`, exact `--source-digest` and `--duration` (default
72 hours). The evidence remains in that private directory; it is never deployed.
The Windows harness requires the compile-time `netenvfixture` tag before any
identity/network work; environment hints cannot enable the safe adapter. Record
binary hash and bounded allowlisted build settings, expected/observed payload
hashes, exact bounded SQL journal counts and runtime/DB resource samples. Summary
and rotating synced JSONL journals retain explicit sequences and discarded
counts. Failed writes/reads, cardinality limits, scheduling/clock gaps and
deadline-interrupted operations must not be rewritten as completed evidence.

Interrupting early is recorded as incomplete. A seconds-long run is only a
harness check, not a soak pass. This harness alone does not cover independent
hosts, HTTP fronts, SSH/REALITY, intended-network performance or real OS recovery.
The default one-second mixed-cycle gap stays within the deliberately bounded
grant-journal rate. Reducing `--interval` is an explicit saturation/load test,
not evidence of unlimited central-authority throughput.

Before stable promotion, a candidate must complete at least **72 uninterrupted
hours** of the authorized mixed-carrier/device pilot on the exact signed assets,
including intended relay/authority latency, quota loads, expiry/revocation, large
in-progress transfers and network changes. Collect bounded-resource measurements,
payload digests and failure/rollback evidence. Resource/cardinality limits that
deny work under load must be measured—not concealed as unlimited performance.

## Real disposable Windows runner

`.github/workflows/windows-acceptance.yml` is manual-only and requires the exact
`disposable-real-registry` confirmation. It builds the fixed non-fixture candidate
on a fresh GitHub Windows VM, then runs `TestRealWindows*` against that VM's real
HKCU WinINET/browser-policy keys. The test refuses to execute without both the
explicit flag and the GitHub runner environment, and also refuses a
`netenvfixture` binary. Current cases cover graceful Ctrl+Break, forced process
termination and guardian recovery, an external competing proxy change that must
not be overwritten, read-only registry ACLs, exact-value restoration and
authenticated payload/accounting. The candidate executable is copied to private
lab state before launch; release artifacts are not mutated.

This is genuine disposable-VM registry evidence, not coverage of logoff,
shutdown, sleep, power loss, mandatory administrator policy, every competing
proxy product or update handoff. Those scenarios still require an authorized
device/lab and must never be run on the everyday operator PC.

## Mandatory non-fixture gates

1. Disposable authorized Windows device: browser/system proxy read-only ACLs,
   logged-off users, close/shutdown/logoff/sleep, forced termination, mandatory
   policy conflict, interrupted journal writes and exact-settings restoration.
   Never run destructive recovery acceptance on the everyday operator PC.
2. Linux native executable and process-identity/ownership/firewall validation;
   no relay access to the authority's DB or admin credentials. Credentials must
   be separately provisioned/readable only to their service identity.
3. Two independent relay hosts against one authority: aggregate usage/rate,
   ban/rekey/revocation, network partitions, lost grant responses and bounded
   refund/retention under sustained mixed load; node revocation/rotation.
4. Real old/new stored-state rollback. Older executables must not silently
   ignore new authentication enforcement. Preserve subsequent bans/accounting
   when reconciling backups; do not downgrade by restoring stale policy blindly.
5. Scoped in-process signing/root-rotation ceremony, exact all-artifact provenance,
   reproducible builds, staged canary/uptake and reviewed service rollout.
6. Independent external security review of the frozen candidate, with findings
   resolved/retested. Self-review/tests/scans are not independent certification.

Stable release, deployment and 1.2 feature work remain blocked until the agreed
seven-gate ledger has honest evidence and explicit operator promotion approval.
