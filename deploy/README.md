# Deploy notes

## VPS: sshd settings for the otu ssh tier

The client's SSH fallback tier opens many short-lived pre-auth SSH
connections in bursts (a single modern web page loads dozens of domains at
once). sshd's default `MaxStartups 10:30:100` drops those handshakes
("An existing connection was forcibly closed by the remote host" on the
client, `drop connection ... past MaxStartups` in `journalctl -u ssh`),
which makes bursty sites (TikTok etc.) load slowly.

Fix (once per VPS):

```
cat <<EOF | sudo tee /etc/ssh/sshd_config.d/90-otu-tier.conf
MaxStartups 200:30:400

Match User tun
    MaxSessions 100
EOF
sudo sshd -t && sudo systemctl reload ssh
```

- `MaxStartups` is global-only (not allowed inside a Match block).
- Verified: 30 simultaneous tunnel connections, 0 drops after this change
  (vs. drops starting at ~10 before).
- Safe with the otu threat model: the relay bounds abuse itself (per-IP
  connection caps, per-session stream cap 256, per-device bandwidth/quota).
- No fail2ban on the default image; if you add one later, whitelist the
  school/office NAT IPs that share one public address for many clients.
## VPS: sshd serving panel-approved device keys

The panel service runs as user 'otu' (ProtectHome=tmpfs) and cannot write
/home/tun/.ssh/authorized_keys. Instead it appends approved device keys to
/var/lib/opentunnel/authorized_keys (otu-owned, 0600) and sshd serves them:

/usr/local/sbin/otu-keys.sh  (root:root 755):
  #!/bin/bash
  cat /home/tun/.ssh/authorized_keys /var/lib/opentunnel/authorized_keys 2>/dev/null

/etc/ssh/sshd_config.d/91-otu-keys.conf:
  Match User tun
      AuthorizedKeysCommand /usr/local/sbin/otu-keys.sh
      AuthorizedKeysCommandUser root

(AuthorizedKeysCommand runs as root, so no file-ownership/StrictModes issues
apply to the panel-managed file. Verified: fresh device key -> register ->
auto-accept -> sshd 'Server accepts key' + 'Authenticated using publickey'.)

The stock files live beside this note: `sshd-91-otu-keys.conf` and
`otu-keys.sh` (install to the paths above, root-owned).

Also add to the `Match User tun` block in `99-otu-tun.conf`:

```
    AuthorizedKeysFile none
```

Without it sshd still tries `/home/tun/.ssh/authorized_keys` first and logs
`Could not open user 'tun' authorized keys ... Permission denied` on every
attempt (the file is root-owned; the pre-auth reader is not). Harmless but
misleading — the command above already serves the home file.

## Authorized-keys self-heal (v1.1.3)

`otu-panel` reconciles `/var/lib/opentunnel/authorized_keys` against the DB
on every startup: every approved device's stored key is (re-)added if
missing. Only adds, never removes. This is the fix for the 2026-11-05
incident, where approved devices were missing from the file the running
sshd serves and the ssh tier failed with "unable to authenticate" forever.
Events: `panel: authorized_keys reconcile: restored N missing device key(s)`.

Device keys are per-device and rotated through the panel: re-registration
with a different key revokes the old line, stores the new key and sends the
device back to pending (admin approves the rotation). The legacy shared
`tun.key` line may stay in the home file during the fleet transition; it is
not re-added by the reconcile if removed from the panel-managed file.
