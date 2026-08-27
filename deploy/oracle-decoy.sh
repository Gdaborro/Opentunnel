#!/bin/bash
# Oracle decoy - makes VPS look like a normal web server, not a weirdo
# Runs daily via systemd timer: apt + logrotate + decoy traffic
set -e
apt-get update -qq && apt-get upgrade -y -qq
apt-get autoremove -y -qq
journalctl --vacuum-time=7d >/dev/null 2>&1 || true
# Decoy: fetch a few normal sites to generate egress that looks like a dev box
curl -s https://cdn.aborro.dev/ >/dev/null 2>&1 || true
curl -s https://example.com/ >/dev/null 2>&1 || true
# Ensure decoy homepage is still served (systemd already handles)
echo "[decoy] $(date) — normal activity" | systemd-cat -t oracle-decoy || true
