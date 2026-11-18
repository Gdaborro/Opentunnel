# Pre-1.2 hardening milestone

One coordinated hardening release, based on v1.1.10, precedes new 1.2 features.
This is a work/acceptance ledger, **not a completed-release claim**. Existing
published releases, device identities, operational policy and system settings
are not automatically changed by implementation work.

The [2026-11-18 readiness report](HARDENING-READINESS-REPORT-2026-11-18.md)
records the automated-work outcome and the current **NO-GO** publication decision.

## Agreed product scope

- Windows/Linux application proxy first. System-wide VPN/TUN integration,
  privileged drivers, other OS support and anonymity-network claims are out
  of this milestone; they require separate engineering and acceptance.
- Preserve existing fleet monitoring, approval, bans and abuse protection.
  Explicit opt-in privacy/retention controls must not silently remove policy.
- No unapproved pool/operator switching, shared remote SQLite files or copied
  credentials. Existing identities/configs and recovery evidence are preserved.
- A single update can contain all seven areas. It cannot replace the real
  soak, independent review, managed-device and migration acceptance gates.

## Seven release gates

| Area | Required implementation | Acceptance before stable rollout | State |
|---|---|---|---|
| 1. Security/correctness | Bounded auth/abuse state, fail-closed filtering, checked identity upgrade persistence, complete SSH revocation/reconcile and strict management mutations | Fault-injection regressions, bounded sustained anonymous/authenticated load, no policy change on malformed input | In progress |
| 2. Session authentication | Fresh connection-bound authentication using mature TLS; pinned independent mutual TLS migration and no downgrade loophole; no protocol verdict for malformed anonymous probes | Captured proofs cannot authorize new sessions after expiry/restart; old/new rollout and stored-state rollback acceptance | Implemented locally; migration/rollback acceptance incomplete |
| 3. Client networking/recovery | SOCKS/HTTP automatic-mode correctness, exact legacy recovery, authority/dial separation, active-transfer drain ownership, network-change recovery | Disposable real Windows policy/ACL/logoff/sleep/shutdown tests and deterministic interrupted-transfer/UDP/DNS cases | In progress |
| 4. Operations/distribution | Separate process identities, narrow authority API, durable managed-SSH reconciliation, signed multi-artifact provenance/key rotation, staged channels, fleet/rollback status | Least-privilege tests, verified backup restoration, exact source/artifacts, explicit release channel and uptake evidence | Local implementation + reference units; signing ceremony/host acceptance incomplete |
| 5. Multi-VPS authority | Authenticated central approval/revocation/accounting, conservative aggregate reservations, per-node credentials and signed node rotation | Two independent relay processes/hosts use one authority; failed/partitioned authority denies new traffic; quota/ban consistency and credential isolation | Two local OS processes tested; multi-host load/credential acceptance pending |
| 6. Scope/privacy/status | Visible pool/node/admission/freshness/failure/bypass status; opt-in minimal telemetry and bounded retention; accessible diagnostics | No secret diagnostics, protected-scope leak matrix, privacy/policy compatibility and explicit direct bypass tests | Implemented locally; real-device/accessible UI acceptance pending |
| 7. Release proof | Repeatable soak/rollback/failure suites and independent review | Minimum 72-hour mixed traffic soak, real old/new rollback, managed-device tests, external review and signed canary uptake before promotion | Harness + local checks implemented; external/time gates not run |

## Implementation sequence

1. Convert reproducible security/correctness findings into sanitized regression
   tests; fix failure semantics and resource bounds without changing live policy.
2. Implement/review the authority and transport trust contracts together:
   local compatibility is not permission for a remote authority fallback.
3. Wire channels, status/privacy and migration/rollback tooling to those
   contracts. Do not ship client protocol changes independently of server
   acceptance or enable stronger requirements on existing devices silently.
4. Freeze an exact release candidate and run all seven gates. Publish a final
   version only after required evidence is recorded; do not call a fixture,
   source scan or one short transfer a 72-hour soak or independent review.

## Validation boundaries

Automated development tests use synthetic accounts/keys, temporary databases,
loopback listeners and compile-time registry-free executable fixtures. Real
Windows registry acceptance belongs on a disposable authorized device, not the
operator's everyday PC. Existing private recovery backups are not rewritten.
Infrastructure/credential ceremonies, Authenticode certificates, independent
review and intended-network pilots may require operator action. Passing a
vulnerability scan is not proof that behavioral audit failures are fixed.

No milestone-wide release, deployment, root-key rotation, Windows driver install
or fleet migration is performed merely by editing this ledger.

## Local evidence (2026-11-15 historical; not a frozen release candidate)

- The final local validation batch built fresh client/server/panel executables,
  set the registry-free/native acceptance paths and passed the full Windows
  `go test -race -tags=netenvfixture -count=1 ./...` suite, production/fixture vet
  and `go mod verify`. Source `govulncheck` reported no vulnerabilities.
- Regressions caught during implementation included hostile-network alerts, a
  nil-config health fixture and legacy pool test setup. They were corrected and
  re-exercised in the passing full suite. A final status-reader-only change from
  permission-protecting read to bounded nonmutating read is checked separately.
- Captured **actually accepted** v6 device proof rejected on distinct real TLS
  exporters and a restarted handler with an empty replay cache. Persistent
  requirements/current-generation proof survive rekey/restart without opening v5.
- Actual Windows fixture executable tested legacy/v6 signed-profile traffic,
  approval, read-only secret-free status, automatic-proxy recovery and SOCKS-only
  automatic-mode refusal without real registry adapters.
- Native authority executable plus two independent relay OS processes completed
  signed pending enrollment, separate approval and authenticated payloads using
  distinct node credentials; relay state directories never acquired `panel.db`.
- Six command binaries cross-compiled for Windows amd64 and Linux amd64/arm64.
  Native Linux execution and process-permission acceptance remain pending.
  Scans/builds are not security certification and do not replace the remaining
  behavioral/external gates.
- Isolated HTTP/3 edge to real HTTP/2 origin contract, quota/idempotent refunds,
  filtering faults, management-audit rollback, SSH retries and privacy defaults
  have local regression coverage. They are not intended-network certification.
- Synthetic soak harness smoke completed **12 seconds**, 12 mixed cycles and
  2,556,120 payload bytes with deliberate authority partition checks. This is
  harness validation only; **the 72-hour soak has not run**. Repeatable commands
  and the real/non-fixture gate checklist are in `HARDENING-ACCEPTANCE.md`.

## Latest local validation (2026-11-18; unsigned previews, not promotion)

- Corrected full Windows `go test -race -tags=netenvfixture -count=1 ./...`,
  production/fixture vet, module verification and separate generic-edition
  config/client/protocol race tests and vet all passed. Source inventory was
  unchanged during that run. Earlier failed race/test-fixture runs are preserved;
  they are not relabeled as passes. The client-drain test locking and the generic
  fixture's shared network-journal location were corrected and re-exercised.
- New executable regressions verified corrupt updater/identity startup refusal,
  orphan proxy recovery, explicit restore without configuration creation, normal
  legacy/v6 pool traffic and default/generic credential separation. Approved
  status is not announced as proof of a working tunnel. Caller cancellation owns
  enrollment/status work; DNS/network generations and retired transfer teardown
  have targeted lifecycle race coverage. The smux buffered half-close fix is in
  checksum-verified v1.5.58.
- Independent inner TLS/exporter authentication remains opt-in pending migration;
  legacy v5 captured-transcript limitations are not claimed fixed for the fleet.
  Interrupted executable replacement records durable PID/creation identity and
  refuses ambiguous/live replacement rollback. Network restore never restores
  device credentials or clears ban/update evidence.
- Update-trust reproductions passed for root-chain loss/rollback, malformed
  checkpoints, checked version compatibility and empty staged discovery. Public
  bundle builder/verifier use fixed payload names and threshold envelopes, but
  declared build metadata and clean source HEAD are not authenticated provenance.
- Isolated Edge SPA acceptance passed ten normal/fault flows: opt-in privacy and
  retention consent, preserved bans/accounting, HTTP 202 SSH notices, unavailable
  reads/mutations and no uncaught page errors. This is not real device policy,
  ACL/logoff/sleep/shutdown or accessibility certification.
- The revised soak harness has dedicated race/fault tests for hashes, bounded
  consistent SQL counts, rotating resource journals, cancellations, gaps,
  incomplete attempts and failed evidence writes. A race-enabled **20-second**
  smoke completed 15 mixed cycles, 3 fail-closed partition probes and 3,195,150
  verified payload bytes with 11 durable samples. This is harness validation
  only; the required 72-hour mixed-carrier/device pilot has **not** run.
- Fresh source scans for both client editions and binary scans of both unsigned
  preview EXEs reported no known vulnerabilities. The isolated companion module
  passed race/vet/module/source scans. Scans are not behavioral security proof.
- Pre-push frontend audit on 2026-11-18 failed with four high-severity dependency
  findings for `picomatch` through Vite/fdir/tinyglobby
  ([GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf),
  CVE-2026-112366). The advisory was reviewed on 2026-11-17; the latest published
  `picomatch` is 4.0.7 and no patched version is listed. This Node build/dev
  dependency is not a Go EXE vulnerability, but its remediation is a release
  gate. No forced Vite downgrade, unreviewed source override or audit suppression
  was applied. CI deliberately retains the failing audit gate pending a reviewed
  fix; the earlier frontend build/browser checks are not a current audit pass.
- The isolated private broker stage passed race/vet after saved path/edition
  reproductions were corrected. Its signing commands remain disabled pending
  trusted frozen-build authorization, durable history and full release contracts;
  no real release key was decrypted and no signing ceremony took place.
- The source commit `6c5fbcc523851e46ce66ad9bec7e679f3e1b2e06` completed Windows
  and Ubuntu Go/companion CI successfully. Overall CI failed the frontend audit;
  its build job was correctly skipped. Native process fixtures in Ubuntu CI are
  not proof of independent-host permissions or a real device/carrier pilot.
- Continued local release-contract work added bounded PE/ELF inline buildinfo,
  exact Git source archive generation/comparison, source dependency/checksum
  binding and exact module/SBOM/companion notice consistency. Targeted race/vet
  and real fixture-directory checks passed. Synthetic `v1.1.99` recipe builds are
  test data, not the selected release. No scoped real all-artifact signing ran.
- A same-host repeat produced 21 matching binary hashes, but a subsequent strict
  input check found Windows line-ending transformations hidden by Git's clean
  verdict. Only 15/21 filtered vs unfiltered artifact hashes matched. Those
  transformed-checkout builds are invalid release input; the builder now checks
  raw file bytes and excludes ignored inputs. The unfiltered source/build/archive
  consistency smoke passed separately. Neither is independent reproducibility
  authorization or a substitute for the final frozen signed artifact ceremony.
- Requested local packages contain a preconfigured `cdn.aborro.dev` Windows
  client plus a separate confirmed identity-reset tool, and a generic Windows
  client requiring its own endpoint/public TLS pin. Generic credentials/update
  trust stay separate; both editions share network-only journal ownership.
  Released clients retain the historical hosted update asset name; generic
  updates use a distinct name. Preview auto-updates are disabled at build time.
  The reset never runs automatically, never clears bans and needs separate
  approval afterward. Twelve synthetic reset checks passed; actual affected-PC
  resets/enrollment are not verified. Nothing was published or deployed.

Remaining stable-release blockers: exact source/asset freeze, trusted reproducible
build authorization, durable scoped signing history and full artifact verification,
frontend dependency advisory remediation, multi-host sustained load,
72-hour mixed traffic soak, actual old/new stored-state rollback, real disposable
Windows browser/ACL/logoff/shutdown/sleep tests, Linux executable acceptance,
independent external review and explicit canary/fleet uptake before promotion.
See `HARDENING-OPERATIONS.md` for narrow contracts and migration boundaries.

The implementation is on the review branch `fix/pre-1.2-hardening`, based on the
released v1.1.10 source. Pushing that branch for CI/review does not authorize a
stable release or deployment. PC-specific reset scripts/instructions and private
broker/evidence remain outside the public commit; only current embedded SPA
assets are included, with unrelated old local files preserved and unstaged.
No installed runtime/client settings backup, fleet policy, device identity,
live server or published release is changed by this source push.
