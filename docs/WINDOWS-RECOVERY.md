# Windows user-proxy recovery

`--auto-proxy` journals only WinINET user settings and the five supported HKCU
Chromium policy bundles. It does not edit machine policies, DNS, firewall rules,
browser profiles or device identity. It cannot promise that an independently
enforced browser policy uses the tunnel, or that restarting a browser overrides
that policy.

## Startup and ownership

- WinINET snapshot/apply/readback failures are mandatory errors. Automatic
  startup stops and attempts rollback; failed rollback keeps its active journal.
- Optional policy originals must be known, including value type and existence.
  A failed key/value read skips the **entire bundle**. Unknown is never recorded
  as absent. Only captured bundles can be written.
- Application compares the whole bundle to the snapshot before and between
  writes. An optional conflict or denied/uncertain write stops that bundle and
  attempts rollback using known originals. Other optional bundles and WinINET
  startup can continue.
- The active `snapshot.json` uses typed format **3**, a random session ID and
  durable per-bundle attempted-application markers. Ownership is armed before
  the first write; untouched skipped bundles cannot later be force-cleaned by
  ordinary recovery. Value restoration is verified before evidence is removed;
  created empty keys are removed conservatively, preserving unrelated contents.
- A settings lease serializes opentunnel processes, not group policy or other
  proxy applications. Complete-bundle checks reduce races but cannot make
  separate Windows registry syscalls atomic.

## Pending optional cleanup

After mandatory restoration succeeds, optional evidence is flushed into
`%LOCALAPPDATA%\opentunnel\pending-policies\<session>.json` **before** the active
journal is removed. Each bounded record contains original/applied policy values
and original key-existence data, with protected user-private ACLs. It is not a
new active session or a reason to discard the original settings.

Recovery retries these records under the same lease. Read/conflict/write/
readback/key-deletion failures are nonfatal warnings and retain evidence.
Successfully completed bundles are removed independently. Subsequent Begin
skips unresolved bundles rather than snapshotting a dead old proxy as a new
original. A corrupt/unreadable record or duplicate bundle ownership remains
for review; ambiguous optional application is skipped, while mandatory WinINET
startup remains available. If the durable pending copy cannot be written, the
active journal stays and the persistence failure is returned.

Private-state replacement/removal makes short bounded retries for transient
Windows access/sharing failures (for example, an indexer holding the file).
Sustained denial still retains evidence and returns a failure or pending warning;
retries never weaken ACLs or discard an existing recovery record.

The same-executable guardian retries a bounded number of times after parent
termination. It never restores a new active lease owner. `--restore` and the
next start are further retry opportunities; there is no monitoring daemon.

An empty `network-settings.lease` file is harmless bookkeeping. Removing it
after releasing its handle would race a new owner, so it can remain. Original
legacy/v2 import bytes are retained privately under `journal-imports/`; they
are evidence, not another automatic replay queue.

## Legacy migration and explicit restoration

Validated legacy format 0 (including v1.1.5) and complete typed format 2 journals
remain supported. Invalid/incomplete/unknown formats are retained without
registry writes. Format 2's applied values remain exact conflict boundaries.

Legacy format 0 omitted the applied bypass list. Its WinINET `ProxyOverride`
and Chromium `ProxyBypassList` may be accepted only when the exact recorded
applied proxy server **and active mode** still match. The observed REG_SZ bypass
is pinned durably before any restoration, so partial recovery/restarts do not
broaden that exception or lose it after the server is restored. Once ownership
ends, a changed bypass is a conflict, not permission to overwrite it.

For validated legacy journals only, v1.1.5's contaminated-original rule is
preserved: if the recorded original WinINET proxy server is an **exact match**
for the journal's nonempty applied address, restore no-proxy rather than enable
the stopped tunnel. This is not a loopback/port/prefix heuristic and does not
clean arbitrary modern local proxy settings. A replacement proxy still receives
normal bundle conflict protection. Old pre-address journals cannot establish
applied ownership and may need operator-directed restoration.

`--restore-from <backup>` is an explicit operator request. It refuses another
live owner, corrupt active evidence and a different active session. The chosen
original backup is not modified. Observed current values are journaled as the
retry boundary before writes; subsequent automatic retries still protect a
different administrator change. Denied optional cleanup stays pending, not a
permanent force-override authorization.

Older binaries that only understand format 2 cannot consume format 3 or the
new pending records. Complete recovery with a compatible client before a manual
downgrade. Synthetic handoff acceptance does not prove that every historical
rollback binary/guardian understands new recovery state.

## Results, warnings and acceptance

`Begin`, `Recover`, `Restore` and `RestoreFrom` return mandatory/persistence
errors normally. `LastResult()` additionally reports applied/skipped/pending
policies and nonfatal warnings, without including original registry value data.
A nil error is **not** a claim that every browser policy was changed or cleaned.
The client shows/logs those warnings; it no longer claims that all browsers are
automatically routed or that incomplete cleanup restored the normal connection.

Tests use only synthetic stores/private temporary journals. Windows executable
acceptance builds a distinct `-tags=netenvfixture` client: the production proxy
and ban-marker registry adapters are excluded at compile time, and an explicit
synthetic settings file is required. Manual-proxy executable handoff uses that
same build (manual mode otherwise clears real ban markers). The normal client
is built/scanned and only its state-free `--version` preflight is executed here.
The normal client does not recognize that fixture switch. CI never
publishes the fixture build as an artifact/release.

Acceptance covers read-only startup, mandatory rejection, full legacy policy
dictionaries/custom bypasses, forced parent termination, permission changes,
pending cleanup/new startup, partial restoration, corrupt evidence and competing
changes. Payload tests traverse an authenticated local relay using the HTTP
proxy address configured in the synthetic WinINET bundle. Device/config files
are synthetic and checked for preservation.

Managed-device ACL changes, browser behavior, logoff/shutdown, disk/power failure
and the intended network remain separate real-device acceptance requirements.
The OS may deny all restoration and helper execution; no zero-residue or
unconditional connectivity/recovery guarantee is justified.
