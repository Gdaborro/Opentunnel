# Rollback playbook

Every deploy/change in this repo is reversible. Each layer below lists the
exact reverse commands. Rule of thumb: binaries are file swaps behind
`systemctl restart`; the panel DB never needs rollback for code deploys
(schema changes are additive-only so far).

## Server (relay) binary

```sh
ssh ubuntu@158.178.137.23
sudo install -m 755 /usr/local/bin/otu-server.bak-0.9.17 /usr/local/bin/otu-server
sudo systemctl restart opentunnel.service
systemctl is-active opentunnel.service
```

Backups on box: `otu-server.bak-0.9.15`, `otu-server.bak-0.9.17` (plus older
`.bak-0.6.0`). Current known-good is 0.9.20; to snapshot before a NEW deploy:

```sh
sudo cp /usr/local/bin/otu-server /usr/local/bin/otu-server.bak-0.9.20
```

## Panel binary + database

```sh
sudo install -m 755 /usr/local/bin/otu-panel.bak-0.9.17 /usr/local/bin/otu-panel
sudo systemctl restart otu-panel.service
```

Panel DB backups live at `/var/lib/opentunnel/panel.db.bak-<timestamp>`
(consistent sqlite backups; verify with `PRAGMA quick_check` before use).
Restore (stops panel, swaps DB, restarts):

```sh
sudo systemctl stop otu-panel.service
sudo cp /var/lib/opentunnel/panel.db.bak-<ts> /var/lib/opentunnel/panel.db
sudo systemctl start otu-panel.service
```

## Server config

Backups: `/etc/opentunnel/server.toml.bak-wspath` (pre boring-path),
`server.toml.bak-20260924-084341` (latest). Restore:

```sh
sudo cp /etc/opentunnel/server.toml.bak-20260924-084341 /etc/opentunnel/server.toml
sudo systemctl restart opentunnel.service
```

Note: rolling the config back to `.bak-wspath` restores `ws_path = "/ws"`
as the ONLY mounted path on old binaries; new binaries mount both paths
regardless, so config rollback alone never breaks new clients.

## Client binary (field devices)

- Auto-update is self-rolling-back: SHA-256 mismatch or install failure
  restores the previous exe in place (rename-swap with rollback in
  `internal/client/update.go`).
- Manual rollback: run `stop-otu.bat`, then put the previous exe back next
  to the config (keep `otu-client-pre-stealth.exe` or a versioned copy).
  The updater only replaces the binary it runs from, so an old exe stays on
  whatever version it was built with until a newer release appears.
- Emergency: `restore-settings.bat` (kills otu, clears the user proxy,
  restores original device identity from `settings-backup/`).

## GitHub release / auto-update fleet

"Latest" is what field clients auto-update to. To stop the rollout of a bad
release, delete the release (web UI or API) — `releases/latest` then points
back at the previous good release, so clients that have not yet updated
stay put. Clients that already updated do not downgrade automatically;
issue a fixed release or roll them back manually per device (above).
Tags can be deleted locally and remotely; never force-push main — use
revert commits.

## Local machine state

- Device identity + config snapshots:
  `%LOCALAPPDATA%\opentunnel\settings-snapshots\<date>\`
- User restore kit (device identity, keys, config):
  `Downloads\opentunnel\settings-backup\` + `restore-settings.bat`
- System proxy is restored on every client exit path (signal, crash,
  panic shield, `--restore`, terminal-handler).
