package config

// GenericClientTOML is deliberately incomplete. Its owner must provision their
// own endpoint and independently verified public TLS pin before client startup.
// A generated per-device credential still needs the server operator's approval.
const GenericClientTOML = `# OpenTunnel - configure YOUR server before starting
# Obtain the endpoint and public certificate SHA256 from your server operator.
# Do not copy another device's token, private key, state folder or settings backup.
server_addr = ""
fingerprint = ""
insecure = false
allow_untrusted_bootstrap = false
ws_path = "/api/v1/stream"
profile = "auto"
mux = true
udp = true
h3_tier = true
ech = true
fallback_ssh = false
# Optional SSH forwarding needs your operator's endpoint, account and public host pins.
# The client prefers its own device key; the operator must provision forwarding rights.
# ssh_dial_host = "ssh.your-server.example"
# ssh_user = "your-forwarding-user"
# ssh_host_keys = "SHA256:<independently verified server host key>"
# ssh_internal = "127.0.0.1:8081"
socks_addr = "127.0.0.1:1080"
http_addr = "127.0.0.1:18080"
bypass_list = []
allow_non_loopback_proxy = false
telemetry = "full"
update_channel = "stable"
# Imported signed pools isolate identities by operator and require explicit trust consent.
# System-wide VPN/TUN is not included. Company network/browser restrictions still apply.
`
