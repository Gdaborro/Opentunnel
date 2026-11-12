# Signed updates and supervised replacement

This is the v1.1.6 update contract. A source push is not a release or a
fleet rollout. Publication must include the complete signed asset set.

## Integrity and freshness

`manifest.sig` retains the existing Ed25519 binding of tag and executable hash
for compatibility. New targets at/after v1.1.6 also require `release.json` and
`release.json.sig`, signed over a domain-separated exact JSON byte string.
The target binds platform, asset name, size, SHA-256, tag, issue time and expiry.
The validity window is at most 90 days. A private high-water checkpoint rejects
older tag/issue-time targets, and malformed checkpoints cannot silently reset
that state. Correct local clock and a trusted initial public signing key remain
required; a censor can block updates, but cannot make expiry disappear.
Freshness is checked even when the feed reports the installed version. After a
signed high-water checkpoint, replaying a legacy target is also refused.

The private release broker generates this metadata from its fixed approved
executable and signs in-process. No generic arbitrary-message signing/export
or release-key copying is needed. The private publisher stages a draft and
checks all seven assets before publication. Signing/publication is deliberately
not part of ordinary source pushes. Existing fleets and offline devices need a
coordinated freshness migration; do not publish a newer target without its
new signatures merely because old clients accepted the previous asset set.

## Replacement transaction

1. Bound download, verify signatures/freshness/floor/hash/size, flush private
   staging and run a version-only executable preflight.
2. Persist a private transaction with current/staged hashes, original arguments,
   backup/readiness paths, parent identity and random readiness token.
3. Arm a same-executable helper and verify parent/paths/staged digest. The parent
   retains the original executable and completes graceful listener/settings/
   companion shutdown before replacement.
4. Helper preserves a unique original backup, swaps the staged file and starts
   the replacement. The replacement initializes its proxies, settings journal
   and optional companion before writing its private readiness token.
5. Require readiness plus a short stability window. Failed child creation,
   premature exit, readiness timeout or failed commit rolls back the original
   verified executable and restarts it. A successful transaction keeps the
   previous backup and removes only the completed transaction marker.
   If child termination cannot be confirmed, do not rename underneath that
   process: retain the transaction and backup for checked recovery.
6. Next-start recovery of an interrupted transaction rolls back to a
   digest-verified original, refuses another active helper/foreign install and
   preserves evidence when automatic restoration is impossible.

Readiness means local process initialization, not guaranteed Internet access
through the intended censorship network. Disk/ACL denial, OS shutdown,
corrupted/missing original backup and malicious same-user programs remain
limitations. Failure does not authorize deleting recovery evidence or
pretending the failed replacement became healthy.

Windows tests use copied test executables/private temporary files for real
rename/readiness/rollback; they do not replace the installed client. Recovery
tests use isolated settings adapters rather than changing the user's proxy.

The version-only preflight runs before identity/recovery initialization and
does not inspect recovery state belonging to the temporary staged path. Update
SOCKS setup carries cancellation through authentication, not just TCP connect.
