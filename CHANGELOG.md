# Changelog

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
