# Cheems Core protocol implementation order

Prioritize protocols present in the user's Flybit subscription, then broaden coverage. A node counts as supported only after parsing, authentication, traffic forwarding, failure handling and Android integration pass. A protocol name alone does not promise support for every transport option or extension.

## Stage 0 — Shared tunnel foundation (prerequisite)
- Android VPNService permission and lifecycle; a real TUN interface.
- Protect every upstream socket and resolve server names on the physical network.
- Route DNS and IPv4/IPv6 without loops or direct-connection fallback.
- Bound concurrent flows; handle stop, revoke, network switching, reconnect and cleanup.
- Keep the loopback proxy for diagnostics, with VPN forwarding as the end-user path.
- Verify with a local reference peer before testing private provider nodes.

## Stage 1 — Hysteria 2 (HY2) — first protocol
Why first: the current branch already has a Go QUIC adapter and the user's known failure is at TLS/QUIC. Finish that concrete path, and establish real UDP behavior.
Acceptance: import common hysteria2:// and hy2:// links; SNI, ALPN, CA, fingerprint, password, obfuscation and port hopping are handled or explicitly rejected; authenticate; proxy bidirectional TCP; implement and test UDP forwarding; reject wrong passwords, unknown roots and mismatched hostnames; test timeout, peer close and Wi-Fi/mobile transition on Android.

## Stage 2 — AnyTLS — largest user-node group
Why second: the user's imported subscription contained 56 AnyTLS nodes, the largest protocol group. Validate against an independent AnyTLS server, then the user's provider when available.
Acceptance: URI and subscription options; TLS verification; authentication; multiplexed bidirectional TCP; correct padding/session lifecycle; DNS and ordinary TCP through VPN. Mark UDP unavailable unless a documented tunnel mechanism is implemented and tested. URI parsing or a framing unit test alone does not establish support.

## Stage 3 — Shadowsocks
Implement common AEAD first, then SS2022. Test each cipher separately. Add plugin transports only when implemented and tested. Add UDP relay and DNS behavior before advertising UDP capability.

## Stage 4 — Trojan, then VLESS
Trojan TCP/TLS with strict certificate and hostname verification; then its UDP relay. VLESS TCP/TLS first, then Reality/Vision and UDP extensions as separate matrix entries. Never make allowInsecure the default.

## Stage 5 — VMess
Implement standard TCP/TLS first; then WebSocket, gRPC and other transports as individually tested variants. Cover UUID, alter ID compatibility, security method, header behavior and clock-related failures.

## Stage 6 — TUIC
Implement QUIC TLS, authentication and congestion settings, then TCP and UDP relay modes. Test MTU, network changes and loss before broad device rollout.

## Stage 7 — HTTP(S) proxy and SOCKS5 completeness
Retain TCP support; complete authentication edge cases, HTTPS proxy TLS, SOCKS5 UDP ASSOCIATE and DNS behavior through the VPN.

## Stage 8 — Additional ecosystem formats
Evaluate WireGuard, SSH tunneling, NaiveProxy and newer or provider-specific variants as separate modules. They do not all share the node protocols above. Add a format only with a maintained implementation, license review, and test peer; unsupported options must be visible.

## Release gate for each stage
Record the exact scheme/cipher/transport/feature combination tested. Require independent interoperability tests, TLS-negative tests, traffic and DNS checks, resource/lifecycle checks, and Android device validation. After the full declared matrix passes, build and verify the APK. No intermediate APK delivery.

## Known inventory and present checkpoint
The user's Flybit import had 65 entries: 56 AnyTLS, 9 Hysteria 2. The development branch has a HY2 Go adapter plus a locally tested QUIC reference peer, but no Android TUN/VPN integration yet. AnyTLS import/framing helpers do not establish interoperability. This list is the implementation order, not a claim that these stages are complete.