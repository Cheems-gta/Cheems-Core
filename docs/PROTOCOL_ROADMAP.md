# Cheems Core protocol compatibility roadmap

Status: implementation is in progress; registry entries are not compatibility claims.

## Compatibility definition
A protocol is marked supported only after parsing, authentication/handshake, bidirectional traffic, timeout/reconnect, DNS/IPv4/IPv6 and Android integration tests pass where applicable. Importing a URL does not mean it connects.

## Target families
- HTTP CONNECT / HTTPS proxy: HTTP/1.1, authenticated proxies; HTTP/2 where applicable
- SOCKS5: TCP CONNECT, authentication, UDP ASSOCIATE
- Shadowsocks: modern AEAD variants, supported plugin transports
- VMess / VLESS: documented transport and TLS combinations
- Trojan: TLS with certificate validation
- Hysteria2 / TUIC: QUIC and UDP paths
- AnyTLS: TLS-based multiplexing
- WireGuard: tunnel interface
- SSH tunneling: key authentication and forwarding
- NaiveProxy: supported HTTP/2/HTTP/3 transport

## Delivery phases
0. Stabilize the Android build and existing loopback HTTP CONNECT prototype.
1. Define protocol capability registry, import parser and explicit unsupported results.
2. Add HTTP(S), SOCKS5 with integration tests.
3. Add encrypted TCP families, each with independent test servers.
4. Add QUIC/UDP families and IPv6 support.
5. Android VPNService/TUN is implemented for HY2 and experimental AnyTLS and
   VLESS TCP. DNS uses HY2 UDP/TCP or AnyTLS/VLESS TCP. Their UDP limitations,
   real-device leak, network-switch and sustained-load verification remain open.
6. Release only tested combinations; maintain versioned compatibility matrix.

Security defaults: loopback-only local listener until authentication/access controls exist, no plaintext credential logging, TLS verification enabled, no silent fallback on handshake failures.

No universal 100% compatibility claim: variants and protocol versions evolve.


## Current Android tunnel checkpoint (2026-11-14)

- Android `VpnService` requests consent, establishes IPv4/IPv6 routes, protects and binds native upstream sockets to the physical network, and gives a duplicated TUN fd to the Go userspace IP stack. VPN revocation triggers service shutdown.
- HY2 TCP and DNS use the authenticated session, with DNS using UDP when negotiated and DNS-over-TCP otherwise. AnyTLS TCP and DNS-over-TCP use its authenticated multiplexed TLS streams. VLESS TCP+TLS and VMess TCP/TLS carry TCP flows and DNS-over-TCP. VMess UDP packet flows use the selected node with per-flow destinations; WebSocket and gRPC remain unimplemented.
- SOCKS5 TCP and UDP flows use the selected authenticated SOCKS5 node via CONNECT and UDP ASSOCIATE; DNS falls back to TCP over that same node if the relay fails. This requires provider UDP relay support. AnyTLS/VLESS UDP is not implemented. VLESS Reality, WebSocket, gRPC and XTLS Vision are unsupported. Other UDP flows require HY2 server datagram support. Automatic reconnect/failover and proof of no leaks on real Android devices remain open.
- AnyTLS `github.com/anytls/sing-anytls` and VMess `github.com/sagernet/sing-vmess` are GPL-3.0-or-later dependencies; license/source distribution obligations must be addressed before distributing an APK.
- Go race tests and vet pass. Android SDK build, APK inspection, Flybit interoperability, and physical-device traffic tests are still required before distribution. Do not describe this checkpoint as a stable general-purpose VPN.


## Shadowsocks 2022 TCP checkpoint

SS2022 TCP is wired through the independent `github.com/sagernet/sing-shadowsocks` v0.2.9 protocol library and protected native upstream sockets. Import accepts standard base64 PSKs of the exact method key size for `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`. Multi-key identities, plugins and SS2022 UDP remain unsupported. The local reference-service TCP echo test and Go race/vet checks pass; Android binding, provider interoperability and physical-device validation remain release gates. The dependency is GPL-3.0-or-later, with source/license distribution obligations required before APK release. No APK is delivered at this checkpoint.


## SS2022 UDP checkpoint

The SS2022 native TUN adapter now routes UDP through protected connected sockets to the selected node. Local reference-service UDP echo tests pass for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, with context cancellation and rejected-protection checks. DNS can use this UDP backend and retains the existing same-node TCP fallback. This supersedes the earlier TCP-only checkpoint; UDP remains experimental pending provider and Android device verification. No APK is delivered.
