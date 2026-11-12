# Xray / REALITY assessment

Reviewed against upstream documentation on 2026-11-11.

**Implementation update (2026-11-12):** the opt-in managed source and loopback
authentication/confinement/lifecycle tests are now implemented; see
[REALITY-MANAGED.md](REALITY-MANAGED.md). The intended-network pilot and fleet
rollout remain unperformed. The assessed network tradeoffs below are unchanged.

## Would it help?

**Potentially, yes: as an additional TCP carrier on a network whose TLS
inspection exemptions permit its chosen server name without interception.**
It is not a substitute for fixing transport timeouts, authentication,
multiplexing, or lifecycle bugs shared by every carrier.

| Environment | Expected value |
| --- | --- |
| Selective TLS inspection with a suitable uninspected SNI | Worth a pilot; it may avoid the SSH fallback and its operational limitations |
| TLS is actually intercepted for the chosen SNI | Authentication must fail closed; REALITY does not make a modified handshake valid |
| UDP is blocked but TCP remains usable | A TCP REALITY carrier does not require QUIC |
| Origin IP is blocked or reputation-filtered | REALITY does not hide the destination IP; other entry infrastructure is needed |
| Endpoint monitoring/process inspection | Another companion process is visible; network camouflage does not hide endpoint execution |

SNI/IP consistency, flow timing, volume, target availability, policy changes,
and implementation fingerprints remain relevant. An exempt name is a
network-dependent assumption, not a permanent guarantee.

## REALITY versus Vision in this architecture

- VLESS supplies proxy framing; REALITY authenticates and protects the outer
  transport using a TLS-shaped handshake and a target-site fallback.
- Vision can recognize and optimize suitable inner TLS streams. The current
  opentunnel payload begins with its own handshake, WebSocket/framing,
  AEAD and mux, not a direct origin-TLS stream. Wrapping that opaque stream
  in Vision does **not** automatically enable the direct TLS-splice path or
  remove opentunnel's own encryption/framing overhead.
- Current upstream REALITY transport combinations are RAW, XHTTP and gRPC,
  not Xray's WebSocket transport. An *inner* WS stream through a local SOCKS
  carrier is a different layering choice and can still be viable.
- Without the optional independent pinned mutual-TLS channel, the Xray endpoint
  is inside the trust boundary. Do not assume the inner
  token-derived AEAD hides data or credentials from its carrier terminator.

## Recommended additive pilot

```
opentunnel client -> supervised, loopback-only Xray companion
                 -> VLESS + REALITY over TCP
                 -> dedicated Xray listener on relay host
                 -> fixed loopback opentunnel ingress
                 -> existing v5 auth, policy, kill switch, sentinel and mux
```

1. Pin an exact Xray version and artifact digests; include license/source
   notices. Do not silently download or run a companion selected by unsigned
   release metadata. Xray-core currently carries MPL-2.0; review distribution
   obligations for the chosen packaging rather than assuming sidecars change
   the host project's license automatically.
2. Validate the companion digest before launch, use private configuration,
   loopback binding, bounded readiness/backoff, and reliable child reaping.
   Keep bootstrap parameters available through a trusted installation path;
   in-band distribution alone cannot bootstrap a fresh disconnected client.
3. Restrict authenticated VLESS traffic to exactly the relay's fixed loopback
   target and deny all other destinations, protocols and UDP. A routing label
   alone is not proof of confinement; test both arbitrary requested addresses
   and the server-side target rewrite. A stolen carrier credential must not
   create a general-purpose proxy or bypass device proof of possession.
4. Give the new loopback listener its own trusted ingress marker. Do not apply
   SSH-specific budgets automatically, and do not mark public connections as
   trusted loopback ingress based on client-provided headers.
5. Reuse the adaptive ladder's sticky selection, failure classification,
   shared cooldowns and graceful pool lifetimes. Keep the feature disabled
   until an explicitly enabled pilot succeeds; SSH remains a backstop.
6. Test authenticated throughput/latency, unknown-client fallback, wrong
   carrier/device credentials, original source attribution, kill-switch
   enforcement, companion failure and rollback on the actual intended network.
7. Publish fleet defaults only after the pilot and companion update contract
   are verified. A port-443 takeover is a separate, disruptive decision.

## Important upstream details

- Current documentation uses `target` (old alias `dest`) and client
  `password` (old alias `publicKey`). Despite being an X25519 public value,
  the REALITY client parameter is explicitly **not** meant to be published
  as a fleet access parameter. Pin configuration syntax to the chosen version.
- Failed REALITY authentication is forwarded to the target site. That is
  useful against some probes but can also consume relay bandwidth or create
  an abusable fixed-target forwarder. Rate limits reduce abuse but can also
  introduce a distinguishable behavior. Treat this as an explicit tradeoff.
- A normal TLS probe seeing the target site's genuine certificate tests the
  unauthenticated fallback, not that the authenticated tunnel works.

This review does not install Xray, generate carrier credentials, open a new
listener, change DNS, or enable fleet defaults. Those require a measured pilot.

References:
- [REALITY configuration](https://xtls.github.io/en/config/transports/reality.html)
- [Transport compatibility](https://xtls.github.io/en/config/transport.html)
- [Xray-core source and license](https://github.com/XTLS/Xray-core)
