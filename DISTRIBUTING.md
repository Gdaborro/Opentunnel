# Handing out the client

What to give someone:

```
otu-client.exe      (from the latest GitHub Release)
tun.key             (optional: enables the SSH last-resort tier)
```

That's it. No config file needed — one is created automatically next to the
exe on first run. Keep both files in the same folder.

## What the recipient does

1. Put the two files in any folder (Desktop, Downloads, USB stick — anywhere).
2. Double-click `otu-client.exe`. A console window opens:
   - the browser is routed through the tunnel automatically,
   - the very first run says `[*] Waiting for one-time approval...`,
   - you (the admin) approve the device in the panel (Security page),
   - within ~15 seconds their pages start loading. No restart needed.
3. To stop: close the window (or Ctrl+C). Normal connection is restored.

## What they never need to know

- The server address, tokens, or fingerprints (baked into the default config).
- Any proxy settings — double-click mode sets and restores them per-user.
- The admin panel — that's yours (https://<your-server>/admin/).

## Security notes for you (the operator)

- Each device gets its own token + SSH key; approval is one-time per device.
- Ban a device and its fingerprint AND key are blocked from re-registering.
- Devices idle for `purge_after_days` (default 14) are deleted and must be
  re-approved — expected behavior, not a bug.
- The client self-updates from GitHub Releases (SHA-256 verified; the
  previous binary is kept as `otu-client.exe.old`).
- Clients phone home telemetry every 60s (CPU, memory, temp, uptime, tunnel
  latency/jitter/loss) — visible on the panel Devices page.

## Troubleshooting recipient issues

| Symptom | Fix |
|---|---|
| Stuck on "Waiting for approval" | Approve on the panel Security page |
| "Device no longer registered" | Normal after 14-day purge — re-approve |
| Pages don't load, no approval message | Check kill switch is OFF on the panel |
| Was kicked (quota/schedule) | Shown in the console with resume time |
| Banned | Console says why; requires your explicit unban |
