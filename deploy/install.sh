#!/bin/sh
# opentunnel server installer for Debian/Ubuntu/Alpine-ish systems.
# Usage: sudo sh install.sh [listen-port]
set -eu

PORT="${1:-443}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) BIN="otu-server-linux-amd64" ;;
  aarch64|arm64) BIN="otu-server-linux-arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac
HERE="$(cd "$(dirname "$0")/.." && pwd)"

install -m 0755 "$HERE/bin/$BIN" /usr/local/bin/otu-server
getent passwd otu >/dev/null || useradd -r -s /usr/sbin/nologin otu
mkdir -p /var/lib/opentunnel /etc/opentunnel
chown otu:otu /var/lib/opentunnel

if [ ! -f /etc/opentunnel/server.toml ]; then
  TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  cat > /etc/opentunnel/server.toml <<EOF
listen = ":$PORT"
token = "$TOKEN"
host = "$(hostname -f 2>/dev/null || echo localhost)"
ws_path = "/ws"
EOF
  chmod 600 /etc/opentunnel/server.toml
  echo "generated config with random token at /etc/opentunnel/server.toml"
fi

if command -v systemctl >/dev/null; then
  sed "s#/var/lib/opentunnel#/var/lib/opentunnel#" "$HERE/deploy/opentunnel.service" \
    > /etc/systemd/system/opentunnel.service
  systemctl daemon-reload
  systemctl enable --now opentunnel
  sleep 2
  FPR="$(journalctl -u opentunnel --no-pager | grep -oE '[0-9a-f]{64}' | tail -1)"
  echo
  echo "======================================================="
  echo " opentunnel is running. Pin this fingerprint in clients:"
  echo "   $FPR"
  echo "======================================================="
else
  echo "no systemd detected — run manually: su otu -c 'otu-server -c /etc/opentunnel/server.toml'"
fi
