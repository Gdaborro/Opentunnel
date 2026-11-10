#!/bin/bash
# opentunnel ssh tier: authorized-keys source for user tun.
# Runs as root (AuthorizedKeysCommandUser root), so it can read the
# otu-owned panel-managed file regardless of StrictModes/ownership.
# Install as /usr/local/sbin/otu-keys.sh (root:root 0755).
cat /home/tun/.ssh/authorized_keys /var/lib/opentunnel/authorized_keys 2>/dev/null
