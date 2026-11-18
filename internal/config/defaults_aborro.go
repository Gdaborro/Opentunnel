//go:build !genericclient

package config

// Hosted first-run defaults contain public routing/trust information only.
// Existing configurations are never overwritten; no device credentials ship.
const DefaultClientTOML = `# OpenTunnel - cdn.aborro.dev edition; public first-run defaults
server_addr = "cdn.aborro.dev:443"
# Optional independently provisioned origin IP; SNI and TLS pins stay on the hostname.
# server_ip = ""
# server_fallbacks = []
fingerprint = "e86816f5e328d6d705b5594e64e7229276a639a264ca51db7916dc3c826aeac1"
# fingerprints = [] # explicit public pins for a reviewed certificate rotation
insecure = false
allow_untrusted_bootstrap = false
ws_path = "/api/v1/stream"
profile = "auto"
mux = true
udp = true
h3_tier = true
ech = true
# Use this device's generated SSH key after separate administrator approval.
# The historical tun.key name selects per-device keys; never distribute a fleet key.
fallback_ssh = true
hostile_ssh = true
ssh_port = "22"
ssh_user = "tun"
ssh_key = "tun.key"
ssh_internal = "127.0.0.1:8081"
ssh_host_keys = "SHA256:msXZMQ8kGmiZF6bt75T3aWtL2ebPnWtZ6+X1vs69Jas,SHA256:og9K+1+YtASuye2jO06RN3V6TA/eK+/zIMF8GHcsLyQ,SHA256:tWpmC5YfGj9UJD9iDb/FlkeCO/m/2pB59vGRSKvTl5o"
# A CDN HTTPS entry is not an SSH forwarding service. Preserve the known public origin.
ssh_dial_host = "git.aborro.dev"
socks_addr = "127.0.0.1:1080"
http_addr = "127.0.0.1:18080"
bypass_list = []
allow_non_loopback_proxy = false
telemetry = "full" # preserves monitoring; minimal mode requires explicit opt-in
update_channel = "stable"
# Optional signed trusted-pool profiles need explicit operator-fingerprint consent.
# Optional independent inner TLS pins require provisioning/canary acceptance first.
# inner_tls_pins = ["<independently verified relay SPKI SHA256>"]
# require_channel_auth = true
`
