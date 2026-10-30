# Changelog

## v1.0.0 — the undetectability overhaul

One big release: containment, ECH, and a traffic-shape pass across every
tier. Existing v0.9.x clients keep working unchanged — the server-side
enforcement is backward compatible, and every client-side feature is
fail-open.

### Added
- **Encrypted Client Hello (ECH)**: the client fetches the entry host's
  ECHConfigList over DoH (HTTPS DNS records) and rides it on every
  Chrome-hello dial — the real SNI travels HPKE-encrypted behind the
  config's cover name. The outer hello is pin-checked through uTLS's
  rejection callback, and a rejected attempt fails open: the socket is
  closed and retried once without ECH. The control plane (status polls,
  health reports) uses the same hooks, so every flow tells one SNI story.
  Dormant until the entry host publishes an ECH config.
- **SSH-tier containment** (panel → System): a sustained per-device
  bandwidth cap plus a daily byte budget for the ssh transport's ingress.
  Once the budget is spent, new streams degrade to a trickle rate
  (default ~200 kbps) — pages keep loading, media cannot, and devices
  that fan into one relay IP stop reading as a media relay on the wire.
- **Traffic-shape mimicry**: capped ssh-tier bulk drains in segment-sized
  bursts with jittered gaps — a streaming player's fetch cadence, not a
  flat line-rate feed. Sub-threshold (interactive) traffic stays smooth.
- **In-band ssh_host learning**: the relay announces its public ssh-tier
  dial target through the authenticated control channel; clients persist
  it so the ssh tier keeps a dialable target after the tunnel domain
  moves behind a CDN (CDNs do not proxy port 22).
- **h3 session byte cap**: h3 sessions rotate at 64 MiB, below CDN
  request-body limits, so fronted bulk is never cut mid-stream.

### Changed
- **Keepalive jitter on both ends**: the relay's sessions no longer ping
  on a fixed 20 s cadence — randomized per session (20–35 s) with a
  matching receive-silence window, because fleet-wide lockstep pings are
  a flow-level correlation signature.
- Decoy asset fallbacks serve the site's own 404 page instead of Go's
  native "404 page not found" text.

### Notes
- v0.4.0–v0.9.30 releases predate this file's upkeep; see the GitHub
  releases and git tags for their notes.

## v0.3.0 — multiplexing, UDP relay, share links

### Added
- **Connection multiplexing** (protocol v3, smux): one authenticated tunnel
  session carries every browser connection — no TLS+WebSocket handshake per
  site, fewer connections on the wire (better mimicry). Enabled by default
  (`mux = true`); automatic session pool with keepalive and reconnect.
- **UDP relay**: SOCKS5 UDP ASSOCIATE over the tunnel via dedicated framed
  streams — DNS-over-UDP, QUIC/HTTP3, voice/games now work through opentunnel
  (`udp = true`, requires mux).
- **Share links + QR** (`otu://…`): `otu-client -c config -share-link`
  prints a self-contained connection link (embeds token) plus an ASCII QR;
  `-qr file.png` writes a scannable PNG.
- `-print-fingerprint` server flag; protocol mode-byte architecture keeps
  legacy single-target sessions fully compatible.

## v0.2.0 — hardening & adaptive stealth

### Added
- **Protocol v2**: per-session salt exchange + inner AES-256-GCM framing
  (HKDF-SHA256 from token+salt), direction-separated nonce counters.
- **Adaptive profiles** (`auto` default): fast → balanced → stealth ladder;
  sticky escalation on failure, pre-escalation on slow responses (>3 s TTFB),
  automatic re-probe back down after a 10-minute cool-off. Transition logging.
- **uTLS Chrome ClientHello** (`balanced`/`stealth`) via
  refraction-networking/utls, ALPN surgically pinned to http/1.1.
- **Traffic shaping**: size-bucket padding (64B…16KB buckets + jitter) and
  per-frame write jitter in `stealth`.
- **Server guard**: per-IP concurrent-tunnel caps, global ceiling, 3-strike
  escalating bans on failed handshakes — over-limit/banned peers receive the
  normal decoy page (no signal to censors).
- **Windows console-close/logoff/shutdown restore**: SetConsoleCtrlHandler
  guarantees settings restoration even when os/signal never fires.
- `--version` on both binaries; `-print-fingerprint` on the server;
  adaptive transition logs.

### Changed
- Each AEAD frame now travels as one transport record (was two) — fewer TLS
  records, steadier traffic shape.
- Frame buffers recycled via sync.Pool.
- Self-signed server certificates persist under `%LOCALAPPDATA%\opentunnel`
  so client fingerprints survive restarts.

### Fixed
- Client read only one byte of the two-byte target response, treating every
  successful connect as a failure (M1 integration bug).
- uTLS path skipped pin-only trust mode and consulted system roots.

## v0.1.0 — M1

- First working end-to-end relay: SOCKS5 + HTTP CONNECT inbound,
  TLS+WebSocket transport with certificate pinning, decoy website for
  unauthenticated traffic, Windows per-user auto-proxy with journal +
  crash-safe restore, TOML configs, deploy files (Docker/systemd/install.sh).
