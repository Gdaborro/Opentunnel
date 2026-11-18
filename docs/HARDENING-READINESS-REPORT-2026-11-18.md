# Pre-1.2 hardening readiness report - 2026-11-18

## Decision: NOT READY for public download or stable deployment

This is the final report of the automated engineering/validation work recorded
below, **not completion of the seven release gates or an independent security
certification**. The operator requested website downloads only when ready.
Consequently, no new EXE/download link is being published on the website, no
stable release is created, and no production authentication migration is enabled.

The original installed v1.1.10 client, device identities, networking backups and
fleet policy remain preserved. PC-specific reset instructions and credentials
remain private. Self-review, unsigned test binaries and local hash repetition
do not authorize release signing or deployment.

## Source and evidence scope

- Released baseline: `2638f828eab09cbe279c38c5eafbef17e1f8fb5d` (v1.1.10).
- Review implementation: `6c5fbcc523851e46ce66ad9bec7e679f3e1b2e06` on
  `fix/pre-1.2-hardening`, followed by the release-contract work in this report's
  commit. Publication of that review branch is not promotion of `main`.
- [CI for the first review implementation](https://github.com/Gdaborro/Opentunnel/actions/runs/44286693158):
  core and companion checks passed on Windows and Ubuntu; the frontend audit
  failed, and the dependent build job was skipped. **Overall CI failed.**
- The exact review commit also passed a full Windows race/vet/module run from a
  separate clean checkout. Later release-contract code has dedicated race/fault
  checks and real separately built Windows/Linux amd64/arm64 fixture inputs.
- Synthetic version `v1.1.99` is test data only. No hardening release version,
  fleet enforcement date, root rotation or production signing ceremony was chosen.
- Raw diagnostics, local test databases, fixture credentials, broker source and
  per-device evidence are kept outside the public repository. This report
  summarizes outcomes without publishing those private inputs.

## Implemented and tested

| Area | Evidence completed | Acceptance still missing |
|---|---|---|
| Security/correctness | Bounded admission/password/abuse state, fail-closed policy/filter reads, audited transactional mutations, durable managed SSH reconciliation; synthetic fault/race tests | Intended sustained anonymous/authenticated load and independent review |
| Session authentication | Opt-in pinned TLS 1.3 mutual authentication and exporter-bound v6 proofs; generation-bound persistent latches; captured proof rejection across sessions/restart | Real canary migration and released-old/new stored-state rollback |
| Networking/recovery | Setup/caller cancellation, DNS/network generation checks, strict carrier cooldown recovery, active-transfer teardown ownership, half-close download fix; fresh registry-free executable acceptance | Real disposable Windows ACL/policy/logoff/shutdown/sleep and intended-device liveness |
| Operations/distribution | Narrow central authority API and separate node credentials, consistent database snapshots, public signed-inventory/root parsing, separate client editions, fixed source/build consistency tooling | Trusted independent reproduction, durable scoped signing history, all-artifact signatures and least-privilege host acceptance |
| Multi-VPS authority | Two independent local relay OS processes against one authority; aggregate grant/quota/refund/partition/generation tests; no relay-local SQLite fallback | Two independent relay hosts, sustained latency/load and credential rotation/revocation acceptance |
| Scope/privacy/status | Application-proxy scope diagnostics, opt-in minimal telemetry/retention, preserved bans/accounting/approval; isolated SPA normal/fault flows | Intended-device leak/accessibility matrix and actual managed-browser acceptance |
| Release proof | Repeatable failure/race suites, bounded resource/payload journals, short synthetic mixed-traffic smoke and internal reviews | At least 72 hours on exact signed assets, actual rollback, external independent review and measured canary/fleet uptake |

### Client startup and reported process exit

Local reproductions fixed stalled setup ownership and interrupted-update startup,
orphan proxy restoration and download-drain problems. Explicit `--restore` works
with an unrelated corrupt updater journal and does not create configuration or
replace device credentials. Recovery refuses live network owners and ambiguous/
live executable replacements; failure evidence is retained rather than erased.
The minimum upstream smux buffered half-close fix is pinned to v1.5.58.

The supplied device logs did not contain a recorded process crash. They showed
failed TLS/SSH connections and denied managed-browser policy writes. Local fixes
and passing fixtures therefore **do not establish that the affected PCs are
repaired**. Their identity resets, separate enrollment approvals and actual
permitted-network transfers have not been verified. No shared credential or
weakened TLS/SSH check is used to force connectivity.

### Two client editions

- The hosted edition preserves the existing identity directory and historical
  Windows update asset name. It embeds public routing/trust only; device private
  credentials are generated locally and still require separate approval.
- The generic edition has no implicit hosted endpoint or public pin. It refuses
  startup until the owner configures an endpoint and independently verified TLS
  pin. Its credentials/status/update trust and update asset are separate.
- Both editions share only the user's network-recovery journal/lease, because
  the Windows proxy itself is shared. Separate credentials do not allow competing
  proxy ownership or restoration of a running client's settings.
- Delivered previews are explicitly unsigned and disable automatic update/
  release-freshness authorization. They are not website-release artifacts.

### Source/build verification hardening

The new `internal/releasebuild` contract and `tools/buildcandidate` /
`tools/releasebundle` now:

1. Check a pristine exact Git HEAD with bounded regular source files, no ignored
   build inputs, no linked/submodule entries, and raw checkout bytes matching Git
   blobs. A normalized `git status` verdict alone is not accepted.
2. Build fixed core/companion targets with exact toolchain/platform/client-edition
   settings, readonly modules, external output and no local Go flag/workspace/
   environment configuration injection.
3. Generate a deterministic bounded USTAR/gzip source archive from those blobs,
   module inventory text and a build consistency document, all new-only.
4. Parse bounded PE/ELF inline Go buildinfo without allocating from unchecked
   virtual section/string lengths; verify package/platform/edition/toolchain/VCS
   identity and dependency versions/checksums against archived module files.
5. Compare exact SBOM bytes to the selected executable's module/settings inventory
   and companion notice to its archived source notice. A valid synthetic
   signature/hash declaration over fake binaries or source is refused.

Real Go 1.27.4 buildinfo differs from simplified synthetic expectations: it omits
linker flags under `-trimpath`, omits off-PGO metadata, and may report a VCS-derived
main module version. The consistency parser now checks the actual bounded format.
**Missing metadata does not prove the linker/version/floor stamps.** Trusted
independent reproduction remains mandatory before the signing broker can use a
real key. The compatibility-only verifier cannot authorize post-v1.1.10 releases.

A same-host repeat initially matched 21/21 binary hashes. A later raw-source
check found Windows line-ending transformations hidden by Git's clean verdict.
Only 15/21 hashes matched between filtered and unfiltered checkouts: embedded
panel/server output changed. The filtered builds are **not valid release input**.
They are retained as reproduction evidence, not silently relabeled as accepted
builds. A new unfiltered checkout matched all 506 tracked Git blobs, and its
strict build/source/module/SBOM inventory smoke passed. These are test builds,
not independently approved reproducible or signed candidate artifacts.

### Short soak and frontend evidence

The revised race-enabled loopback soak smoke ran **20 seconds**, completed 15
mixed TCP download/upload/UDP/status cycles, observed three fail-closed authority
partition probes, verified 3,195,150 payload bytes and wrote 11 durable resource
samples. No incomplete operations or observation gaps were recorded in that
short window. This is one-process/host harness validation, **not the 72-hour
multi-device/carrier pilot or a sustained resource-growth result**.

Ten isolated Edge SPA normal/fault flows passed, including explicit retention
consent, preserved bans/accounting, pending SSH notices, unavailable reads and
failed mutation visibility, with no uncaught SPA exceptions. That is not proof
of real corporate browser policies or logoff/sleep/shutdown behavior.

## Blocking dependency advisory

The fresh frontend audit reports four high-severity dependency findings for
[GHSA-fc5q-39xc-vjpf / CVE-2026-112366](https://github.com/advisories/GHSA-fc5q-39xc-vjpf),
picomatch ReDoS through Vite/fdir/tinyglobby. The advisory was reviewed on
2026-11-17; the latest published npm version inspected is 4.0.7, with no patched
version listed. The referenced open upstream PR explicitly does not fix the
single-branch repeated-extglob problem generally.

This Node build/dev dependency is not executed by the static SPA or Go EXEs, but
it is still a release-tooling gate. No forced Vite downgrade, unreviewed upstream
PR override, audit suppression or vulnerable-version exception is applied. The
audit remains enabled and failing. Earlier Go artifact scans reporting no known
vulnerabilities are not a frontend audit pass or security certification.

## What autonomous work cannot truthfully replace

Before public downloads, final signing and rollout, the following need actual
authorized resources/evidence, not another synthetic test:

1. A reviewed dependency remedy and green exact-source Windows/Linux/frontend/
   companion CI, with a final frozen complete artifact inventory.
2. Trusted independent binary reproduction and durable scoped signing history,
   real threshold signatures/root ceremony and all-artifact verification.
3. Disposable Windows managed-policy/ACL/logoff/shutdown/sleep tests and verified
   affected-device reset/enrollment/liveness without changing corporate controls.
4. Native Linux least-privilege process/file/credential ownership acceptance and
   sustained two-independent-host authority load/partition/rotation tests.
5. Released-old/new stored-state rollback that preserves subsequent bans,
   revocations and accounting; the released v1.1.10 server does not understand
   new authentication latches and is not a safe enforced-state rollback target.
6. At least **72 uninterrupted hours** of the intended mixed-carrier/device pilot
   on the exact signed candidate, followed by independent external review and
   recorded canary/fleet uptake before stable promotion.

No external review was purchased or fabricated, no real credentials/root were
rotated, and no test on an everyday PC is substituted for those device/host gates.

## Publication outcome

**NO-GO.** Source changes and this report may be published on the review branch.
That is not a final software release. Website download links, stable releases,
the original installed client and production services remain unchanged. The
operator's “only if ready” condition takes precedence over completing an upload.
The final release and website publication must remain on hold until every
remaining acceptance item above has honest evidence.
