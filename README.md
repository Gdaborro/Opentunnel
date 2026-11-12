# otu (opentunnel)

A minimal, self-hostable censorship-circumvention proxy. One Go binary runs
on a VPS (`otu-server`); one runs locally without administrator rights
(`otu-client`) and exposes SOCKS5/HTTP proxies that any browser can use.

- **Double-click client** — applies journaled per-user proxy settings. Normal
  shutdown restores them; a recovery helper and next-start recovery cover
  crashes where the OS permits recovery code to run.
- **Per-device identity** — each install generates its own device token and
  SSH key; the admin approves new devices once from the web panel (NAC).
  No shared secret ships in the binary. Banned devices (fingerprint + key)
  stay banned. Inactive devices are purged and re-approved on return.
- **User-level by design** — no TUN driver, no services, no UAC prompts.
  Runs from `%USERPROFILE%` or a USB stick.
- **Looks like HTTPS** — traffic rides a genuine TLS session to your server's
  WebSocket endpoint; anything else gets an ordinary decoy webpage.
- **Inner AEAD layer** — every payload is additionally sealed with
  AES-256-GCM keys derived via HKDF(token, per-session salt); direction-split
  nonce counters and a bounded server-side replay cache reject repeats inside
  its retention window. Without the opt-in independent inner TLS channel,
  the carrier terminator remains trusted; this is not
  independent end-to-end secrecy or permanent replay immunity.
- **SSH last-resort tier** — on networks that intercept TLS outright, the
  client tunnels inside real SSH (host-key pinned) automatically.
- **Multiplexed sessions** — one tunnel carries all your connections: faster
  page loads and fewer connections on the wire (enabled by default).
- **UDP relay** — DNS-over-UDP, QUIC/HTTP3, calls and games work through the
  tunnel via SOCKS5 UDP ASSOCIATE.
- **Auto-update** — verifies an Ed25519 tag/hash-bound manifest, stages a
  bounded download, and supervises replacement readiness and checked rollback.
  New v1.1.6+ targets also require signed time-bounded freshness metadata.
- **Managed REALITY (opt-in)** — verifies a separately provisioned patched
  Xray companion, supervises its lifecycle, and confines both carrier ends
  to one TCP loopback ingress. No automatic download or listener takeover.
- **Independent inner TLS (opt-in)** — pinned TLS 1.3 mutual authentication
  with enrolled device keys, ephemeral session secrets and no tickets/0-RTT.
- **Adaptive stealth ladder** — `profile = "auto"` starts at *fast*, escalates
  to *balanced* (Chrome-fingerprint ClientHello + size-bucket padding) or
  *stealth* (+ per-frame timing jitter) only when blocked or throttled, then
  automatically re-probes downward so you stay at maximum speed.
- **ISP NOC panel** — device inventory with live health (CPU, memory,
  temperature, uptime), tunnel latency/jitter/loss, alerts, top talkers,
  access schedules, bandwidth caps, data quotas, category filtering, custom
  blocklists, GeoIP locations and a global kill switch — all enforced at the
  relay.
- **Retryable recovery** — failed restores retain their journal. Settings
  changed by another application are not blindly overwritten. Backup files
  are intentionally retained; shutdown, denied writes and disk failure remain
  explicit limitations, not a "zero residue on every crash" guarantee.

> Release availability: [GitHub Releases](https://github.com/Gdaborro/Opentunnel/releases).
> Hardening introduced in v1.1.6 is described in
> [docs/HARDENING.md](docs/HARDENING.md). This is an application proxy, not a
> system-wide TUN VPN; unconfigured applications may use the direct network.
>
> Managed-carrier setup: [docs/REALITY-MANAGED.md](docs/REALITY-MANAGED.md).
> Update contract: [docs/UPDATE-TRANSACTION.md](docs/UPDATE-TRANSACTION.md).

## Quick start

### 1. Server (any Linux VPS)

```bash
./otu-server -gen-config -c server.toml   # edit token if you want a legacy fallback!
./otu-server -c server.toml
./otu-panel -c server.toml -listen 127.0.0.1:8090 # separate management process
```

Devices authenticate per-device by default; the `token` in server.toml is
only a legacy fallback (`allow_legacy_master`) and can stay disabled.
The default relay requires its policy database to open successfully. A
server-only legacy installation must explicitly set `static_token_only=true`;
database failure never enables that mode automatically. First panel setup
requires the operator's private `OTU_SETUP_TOKEN`.

### 2. Client (Windows, no admin)

**Easiest**: put `otu-client.exe` (and `tun.key` if you were given one) in a
folder and **double-click it**. A console opens, the browser is routed
automatically, and the first run waits for the admin to approve the device.

```powershell
.\otu-client.exe                        # double-click equivalent (auto-proxy on)
.\otu-client.exe -c client.toml         # manual: use a specific config, no auto-proxy
.\otu-client.exe -c client.toml --auto-proxy   # manual config + system proxy
.\otu-client.exe --restore              # emergency: restore network settings
```

Without `--auto-proxy`, point Firefox at `127.0.0.1:1080` (SOCKS5) or any
browser at the HTTP proxy on `127.0.0.1:18080`. Original settings are
restored when you press Ctrl+C or close the window.

After a crash, `otu-client.exe --restore` retries the retained recovery journal.
Denied writes or changes by another application may require operator review.

## Building

Requires Go 1.27.4 or newer.

```bash
go test ./...          # unit + end-to-end integration tests
go build ./cmd/otu-client ./cmd/otu-server
```

Cross-compile the server for a VPS:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o otu-server-linux ./cmd/otu-server
```

## Repository layout

```
cmd/otu-client/   local proxy binary (SOCKS5 + HTTP CONNECT)
cmd/otu-server/   relay binary (TLS + WebSocket endpoint, decoy site)
cmd/otu-reality/  explicit private provisioning and companion supervision
companions/xray/  separate pinned patched restricted Xray module
internal/
  protocol/       wire format: handshake, target addressing, statuses
  transport/      pluggable transports (ws-tls), cert generation/pinning
  proxy/          SOCKS5 & HTTP inbound listeners
  client/         outbound tunnel dialer
  server/         relay handler + decoy responder
  netenv/         Typed Windows proxy journal, rollback and retryable recovery
  reality/        typed fixed-target configs and verified child lifecycle
test/             end-to-end integration tests
deploy/           Dockerfile, systemd unit, install script
```

## Safety & legal notes

- Use only where circumvention is legal and legitimate (journalism, research,
  restoring access to information). Respect the laws of your jurisdiction and
  the policies of networks you don't own (e.g., school/work acceptable-use).
- The operator of the VPS can see connection metadata (destination hosts).
  Treat the server as trusted; run it on infrastructure you control.
- This is young software. For maximum-strength needs, also evaluate mature
  projects such as Hysteria2, Xray (Reality), sing-box, or Tor.

## Profiles

| Profile | TLS hello | Padding | Timing jitter | Use when |
|---|---|---|---|---|
| `fast` | standard Go TLS | no | no | default; fastest, beats basic/SNI filters |
| `balanced` | Chrome (uTLS) | size buckets | no | active DPI fingerprinting |
| `stealth` | Chrome (uTLS) | size buckets | 0–20 ms/frame | behavioral/throttling censors |

`profile = "auto"` (recommended) escalates fast → balanced → stealth only as
needed and drops back automatically after a 10-minute cool-off probe. Fixed
profiles never escalate.

## Roadmap

- **M4**: CDN fronting option, packaging polish, DPI-lab CI harness
- Later: routing rules / split tunneling (geoip), system-tray mini-GUI,
  multi-user tokens with usage stats

MIT licensed — see [LICENSE](LICENSE).
