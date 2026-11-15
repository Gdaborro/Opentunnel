# Trusted server pools (feature branch)

This feature is implemented in source but is **not part of the published
v1.1.9 release**. No server deployment, fleet migration or public directory is
performed by importing a profile.

## What automatic selection means

- Existing installs still use their existing `client.toml`, default operator
  and device identity until a user explicitly selects an imported pool.
- A pool contains 1–16 explicitly provisioned entries belonging to **one
  approval and accounting authority**. The client selects the lowest measured
  pinned-HTTPS capability latency; it does not collect user location or scan
  for unknown servers. Latency is not a throughput guarantee.
- Probes contain no device token, private key, username or password. Four
  concurrent probes, three seconds per probe and a twelve-second total bound
  limit work. Results are reused for ten minutes; meaningful latency
  improvements avoid flapping. Failed refreshes do not reuse stale results.
- Transport setup fails over only among verified entries in the selected
  profile. There is a fifteen-second aggregate bound (including an on-demand
  probe) and four seconds per candidate. Established streams retain their own
  lifetime; finishing the setup deadline does not close them.
- Selecting another operator is explicit and takes effect on the next start.
  Unavailable, expired or corrupt selected trust does **not** silently fall
  back to the default operator.

## Authority limitations: not remote federation

The present panel/relay authority is a local SQLite database. Multiple
listeners, names, reverse-proxy entries or relay processes on the **same host**
may use that same local database. Keep panel and relay configuration identical.

Each database receives a random immutable authority ID, in addition to the
operator's key-derived pool ID. Clients check both before enrollment. Merely
assigning separate servers the same `pool_id` does not synchronize approvals,
revocations, quotas or nonce journals. **Do not copy databases or put SQLite
WAL files on a network filesystem to pretend they are a shared remote pool.**

An authority ID detects accidental independent databases. It is not an
attestation of honest infrastructure: a trusted operator can deliberately
copy an ID or misconfigure its own servers. Multi-host replication or a
remotely authenticated central accounting service requires separate design
and acceptance; it is not implemented here. Independent self-hosted operators
use different dedicated signing keys and separate imported profiles.

## Self-hosting workflow

Build the feature executables from source:

```bash
go build -o otu-pool ./cmd/otu-pool
go build -o otu-server ./cmd/otu-server
go build -o otu-panel ./cmd/otu-panel
```

1. Create a **dedicated operator profile-signing key**, not a release-signing
   key or an administrator password:

   ```bash
   ./otu-pool --gen-key --key pool-signing.pem
   ./otu-pool --print-id --key pool-signing.pem
   ```

   The command never replaces an existing key. Keep this file private; back
   it up privately. The printed 64-character SHA256 operator fingerprint is
   the `pool_id`.

2. Provision the relay, panel and TLS certificates as usual. Configure:

   ```toml
   pool_id = "<full operator fingerprint>"
   enrollment_login = false # true for separate enrollment user accounts
   auto_approve = false
   allow_legacy_master = false
   static_token_only = false
   ```

   All pool handshakes require registered Ed25519 device-key authentication
   immediately, without a v4 migration exception. Automatic approval windows
   do not approve pool enrollment. The password policy and operator ID are
   bound when the database first becomes a pool. Removing `pool_id`, changing
   the operator or changing `enrollment_login` is not an automatic migration;
   mismatched starts fail closed. Choose the desired login policy before
   first binding. An existing default fleet is not transparently migrated:
   its rows require signed pool enrollment and separate reapproval.

3. Create a credential-free `nodes.json` array, using pins verified on your
   infrastructure, for example:

   ```json
   [
     {
       "id": "primary",
       "name": "Primary entry",
       "address": "relay.example.net:443",
       "pins": ["<lowercase 64-character SHA256 TLS leaf pin>"],
       "ws_path": "/api/v1/stream"
     }
   ]
   ```

   `address` is the trusted HTTP authority and TLS server name. Optional
   `dial_address` is a literal `IP:port` TCP override (IPv6 uses brackets);
   it never changes the HTTP authority or TLS name. Optional
   `inner_tls_pins` are the relay's independent TLS public-key pins. Each
   node has its own bounded pin set; never assume all nodes use one certificate.

4. Export a signed profile using the same local database directory as the
   relay and panel (their `TMPDIR`, otherwise `/var/lib/opentunnel`):

   ```bash
   TMPDIR=/var/lib/opentunnel ./otu-pool --export operator-pool.json \
     --key pool-signing.pem --c server.toml --nodes nodes.json \
     --name "My operator pool" --valid-for 720h
   ```

   Export never overwrites files. Use a new export path when renewing a
   profile. Profiles expire after at most 90 days; default validity is 30
   days. Updates under the same accepted key must have a newer `issued_at`
   and cannot shorten the accepted expiry. Changing the authority ID is
   rejected rather than inheriting old operator state. Keep clocks accurate.

5. Share **only the signed profile**, never `pool-signing.pem`, device keys
   or passwords. Publish the operator fingerprint through an independently
   trusted channel. A self-signature authenticates changes under a key; it
   does not establish that the operator is trustworthy.

## Client import and selection

```powershell
.\otu-client.exe --pool-import .\operator-pool.json
# Inspect the operator, fingerprint, endpoints, login policy and expiry.
# Type the exact full independently verified operator fingerprint to consent.

.\otu-client.exe --pool-list
.\otu-client.exe --pool-select <full-operator-fingerprint>
.\otu-client.exe -c .\client.toml

# Explicitly return to the existing default operator on the next start:
.\otu-client.exe --pool-select default
```

For an automated import, `--accept-pool <exact-full-fingerprint>` is explicit
consent; it is not an insecure TLS switch. Import does not select the pool,
mint a device key, start a proxy, rewrite `client.toml` or change Windows
network settings. Standalone pool commands refuse network/startup flags.
`--pool-use <id|default>` overrides the selection for one run only.

Local proxy addresses, shaping preference, bypass configuration and the
existing signed-update policy remain local application settings. Imported
profiles cannot inject update feeds or credentials. Imported pools currently
use pinned WSTLS plus optional independent inner TLS. Default SSH, QUIC,
REALITY/carrier credentials, learned hosts and learned pins are **not reused**
for another operator. Adding those transports needs a signed per-node
contract; editing default fallback fields does not enable them for a pool.

Trust state lives under `%LOCALAPPDATA%\opentunnel\server-profiles` and the
selection in `selected-server-pool.json`. Each operator has a separate token,
random enrollment fingerprint, private device key and approval/ban state in
`server-identities\<pool-id>`. The existing default identity, Windows recovery
journal and signed-update transaction state stay at the existing root.
Scoped bans do not read or change the default Windows ban marker.
Ordinary startup still attempts orphan proxy-journal recovery before rejecting
corrupt/expired selected pool state; standalone import/list/select never run
network recovery. `--restore` is independent of pool profile availability.

Profiles and selection use bounded exact JSON schemas: unknown fields,
credentials, duplicate keys, nulls, trailing data and mismatched filenames are
refused. At most 64 profiles are supported. Native private-file locking
prevents conflicting import/selection updates between CLI processes. Another
ordinary user's access is restricted; malicious code running as the same user
is outside the local-file protection boundary.

## Login plus approval

Configure `enrollment_login = true` before the authority's first binding.
Log in as an administrator and open `/admin/enrollment-accounts` to create
**enrollment user accounts**, separate from administrator accounts.

- Passwords are bcrypt hashes; account inventory never returns hashes.
- Usernames are 3–64 ASCII letters/digits/`._-`; passwords are 8–72 UTF-8
  bytes when set. Device limits default to 5, with a maximum of 32.
- Bcrypt work has a four-slot admission bound; public source rate state,
  pending enrollment and account counts are bounded.
- The client first verifies the accepted node's TLS pins, operator ID,
  authority ID and login/manual-approval policy. If a new enrollment needs
  login, it asks in an interactive terminal with a hidden password prompt.
  Passwords are not accepted from command arguments, environment variables,
  profiles or credential files, and are not stored for future sessions.
- A credential attempt is pinned to one selected node, with no automatic
  cross-node retry or HTTP redirects. Do not paste passwords into issue
  reports or client logs. Go cannot promise erasure of every transient heap
  copy; this is no credential persistence, not forensic-memory immunity.
- The enrollment request proves possession of the device key. A durable,
  bounded nonce journal prevents accepted HTTP proofs being reused through
  another panel process or a restart during their validity window.
- Login authorizes **enrollment only**. The device remains pending until a
  separate administrator action approves it. Later traffic uses its device
  key, not its user password. Administrator accounts do not grant enrollment
  access, and enrollment accounts cannot create administrator sessions.
- Disabling an account prevents **new** enrollment. It does not disconnect
  previously approved devices: ban/revoke those devices separately. Unban and
  rekey still require approval, and rekey requires enrollment bound to the
  replacement key. Purged devices need enrollment/login and approval again.
- Public pool status polling is signed and body-only; it does not downgrade
  to a token-bearing legacy query or an untrusted bootstrap/carrier channel.

## Validation and remaining work

Focused regressions cover signatures/schema/expiry/rollback, concurrent trust
updates, verified latency ranking and hysteresis, cancellation and failover,
password redirection and account/admin separation, pending/approval/ban/rekey,
isolated identities and signed status. A two-entry integration uses one real
local database to verify shared approval, traffic accounting and revocation.
Windows executable acceptance uses the compile-time `netenvfixture` build,
which excludes real proxy/ban registry adapters.

Local Windows validation passed the full race-enabled suite, focused
registry-free executable pool/default-startup/recovery checks, `go vet`,
module verification and source/artifact `govulncheck` scans. Linux AMD64
relay/panel/pool and Linux ARM64 pool binaries cross-compiled; Linux-native
behavioral/race tests and remote CI were not part of these local validation
results. The feature branch runs the existing CI checks when pushed.
The existing guardian lifecycle test initially failed in a tagged run because
its child lacked the fixture-only settings file; the test now supplies a
synthetic file, and the subsequent full tagged race suite passed. No real
registry adapter was used for executable pool acceptance.

These tests do not establish multi-host federation, real managed-device
logoff/shutdown cleanup, intended-network throughput or production readiness.
This feature does not resolve all findings in the separate v1.1.9 audit.
In particular, the existing v5 tunnel transcript/replay retention limitation,
other server resource limits and broader carrier/SSH/recovery findings need
their own remediation and acceptance. No release or deployment is authorized
by this document.
