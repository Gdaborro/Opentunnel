# Firewall Probe — St Edwards College (2026-08-27)

**Target VPS:** `158.178.137.23` (Oracle Cloud, `vpn.aborro.dev` via Let's Encrypt)

## What was tested from the firewalled network

| Test | Result | Meaning |
|---|---|---|
| **TCP 22** (SSH) | **OPEN** — clean SSH banner `OpenSSH_9.6p1`, SSH handshake succeeds | Whitelisted, not MITM'd |
| **TCP 443, 8443** (TLS) | OPEN but **MITM'd** — `issuer=St Edwards College` for *every* TLS fingerprint (Go, uTLS Chrome/Firefox/iOS/Edge/QQ) | Transparent TLS interception; pin check correctly rejects |
| **TCP 53,80,853,993,995,587,465,2083,2053,8080,25565,51820,1194** | **TIMEOUT** (filtered) | Default-deny, only 22/443/8443 allowed to unknown IPs |
| **UDP to VPS** (3478,51820,8080,2083,2053,1194,51821) | **TIMEOUT** (all) | UDP to this IP blocked |
| **UDP to 8.8.8.8:53** | **PASS** (61B) | UDP not globally blocked — just to this VPS IP /24 |
| **TLS SNI spoof to VPS** (`www.google.com` SNI to `158.178.137.23:443`) | **FAIL** `remote error: tls: internal error` | SNI/IP mismatch blocked, not proxied |
| **Plain TCP to :443** (`HELLO`) | 0 bytes | Expects TLS, not plain |
| **Plain HTTP to :22** | SSH banner | Port 22 is truly SSH |

**Conclusion:** From this network to this VPS IP, **only SSH on TCP 22 gets through unmolested**. Every TLS handshake is re-signed, every other TCP port is filtered, every UDP packet to this IP is dropped.

## Why the current SSH transport works

- Outer layer: real SSH to `vpn.aborro.dev:22` (port 22 is whitelisted, not MITM'd)
- Inner layers: WebSocket + smux + AES-GCM (still end-to-end authenticated via inner token)
- The school sees `SSH-2.0-*` and lets it pass.

## Why a non-SSH transport to *this* VPS won't work here

- No other TCP port is open to this IP (tested 12)
- No UDP to this IP is open
- TLS on the open ports (443/8443) is always MITM'd — even with perfect Chrome mimicry
- SNI spoofing a whitelisted domain to this IP is blocked, not forwarded

Options to get a non-SSH transport:
1. **Move the relay to a whitelisted IP** (e.g., host it behind Vercel/Cloudflare where `aborro.dev` already resolves to `216.198.79.1` — that IP is likely whitelisted as "Education/Hosting")
2. **Run the tunnel on port 22 but speak a non-SSH protocol that *starts* with `SSH-2.0-`** — essentially a fake SSH banner, then switch to our own framing. Firewall that only checks port would still pass it, but it would no longer need a private key.

Both are doable. For now the cleanest path that keeps the panel's promise ("no private key to hand out") is to keep SSH as the outer transport but **make each client generate its own keypair**.

## Panel design (not implemented yet, per your request)

**Goal:** you click Accept/Reject, client needs no pre-shared private key to extract via decompilation.

**Flow:**

1. Client first run: `generate ed25519 keypair locally` → `private stays in %LOCALAPPDATA%\opentunnel\device.key` (never leaves device)
2. Client → Panel (hosted on Vercel, `tunnel.aborro.dev` or `panel.aborro.dev` — whitelisted, reachable without tunnel): `POST /api/request { pubkey, device_name }` → pending
3. You see pending in panel, click Accept → panel stores `pubkey` as approved
4. VPS polls panel every 10s: `GET https://panel.aborro.dev/api/approved` (outbound from VPS to Vercel — allowed) → rewrites `/home/tun/.ssh/authorized_keys` as:
   ```
   restrict,port-forwarding,permitopen="127.0.0.1:8081" <each approved pubkey>
   ```
5. Client retries SSH dial — now succeeds (its pubkey is authorized). Inner token (from `client.toml`) is still required for the opentunnel handshake, so panel can revoke by removing the pubkey *or* the token.

**What decompiling reveals:** only the panel's HTTPS URL, not a shared private key. Each device's private key never leaves it.

**What you hand out:** just `otu-client.exe` + `client.toml` (with `transport = "ssh"` but **no** `ssh_key` line). The client generates its own key on first run.

**Alternative if you prefer zero SSH at all:** host the relay behind Cloudflare Tunnel / Vercel Edge Function that forwards WebSockets — then the firewall sees `SNI=panel.aborro.dev` on 443 to a Cloudflare IP (whitelisted) and passes it. That's a bigger infra change; SSH-per-device is the minimal delta from what already works.

---
*Probe tool: `tools/tlsprobe`, `tools/sshtest` + UDP echo via Python. Raw logs in `/tmp/udp*.log` on VPS (cleaned after).*
