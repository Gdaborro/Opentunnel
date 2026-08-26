#!/bin/sh
# opentunnel one-shot server deployer for fresh Ubuntu/Debian boxes.
# Usage (run as root, from anywhere):
#   DOMAIN=vpn.aborro.dev sh deploy-anyvps.sh
# Assumes opentunnel repo files are present in cwd (bin/ + deploy templates).
set -eu
DOMAIN="${DOMAIN:?set DOMAIN=your.domain}"
PORT="${PORT:-443}"

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) BIN="otu-server-linux-amd64" ;;
  aarch64) BIN="otu-server-linux-arm64" ;;
  *) echo "unsupported arch $ARCH"; exit 1 ;;
esac

apt-get update -qq && apt-get install -y -qq ca-certificates >/dev/null

id otu >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin otu
mkdir -p /var/lib/opentunnel /etc/opentunnel
install -m 755 "bin/$BIN" /usr/local/bin/otu-server

TOKEN="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat > /etc/opentunnel/server.toml <<EOF
listen = ":$PORT"
listen_internal = "127.0.0.1:8081"
token = "$TOKEN"
host = "$DOMAIN"
acme_domain = "$DOMAIN"
ws_path = "/ws"
EOF
chown otu:otu /etc/opentunnel/server.toml && chmod 600 /etc/opentunnel/server.toml

cat > /etc/systemd/system/opentunnel.service <<'UNIT'
[Unit]
Description=opentunnel relay server
After=network-online.target
Wants=network-online.target

[Service]
User=otu
ExecStart=/usr/local/bin/otu-server -c /etc/opentunnel/server.toml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=tmpfs
Environment=TMPDIR=/var/lib/opentunnel
ReadWritePaths=/var/lib/opentunnel
StateDirectory=opentunnel
WorkingDirectory=/var/lib/opentunnel
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

# Kernel tuning: BBR + fq + big socket buffers
cat > /etc/sysctl.d/99-opentunnel.conf <<'SYS'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.ipv4.tcp_mtu_probing = 1
net.core.netdev_max_backlog = 250000
SYS
sysctl --system > /dev/null

iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true

systemctl daemon-reload
systemctl enable --now opentunnel
sleep "${ACME_WAIT:-20}"

echo
echo "======================================================="
echo " opentunnel deployed on $DOMAIN:$PORT"
echo " fingerprint (pin in clients):"
openssl s_client -connect 127.0.0.1:"$PORT" -servername "$DOMAIN" </dev/null 2>/dev/null \
  | openssl x509 -fingerprint -sha256 -noout \
  || echo "   (cert still issuing — rerun this command in ~30s)"
echo " token: $TOKEN"
echo " REMINDER: cloud firewall must allow TCP $PORT and 80."
echo "======================================================="
