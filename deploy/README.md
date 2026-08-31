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
