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
- HY2 TCP and DNS use the authenticated session, with DNS using UDP when negotiated and DNS-over-TCP otherwise. AnyTLS TCP and DNS-over-TCP use its authenticated multiplexed TLS streams. VLESS TCP+TLS carries TCP flows and DNS-over-TCP.
- SOCKS5 TCP and UDP flows use the selected authenticated SOCKS5 node via CONNECT and UDP ASSOCIATE; DNS falls back to TCP over that same node if the relay fails. This requires provider UDP relay support. AnyTLS/VLESS UDP is not implemented. VLESS Reality, WebSocket, gRPC and XTLS Vision are unsupported. Other UDP flows require HY2 server datagram support. Automatic reconnect/failover and proof of no leaks on real Android devices remain open.
- AnyTLS uses `github.com/anytls/sing-anytls` under GPL-3.0-or-later; license/source distribution obligations must be addressed before distributing an APK.
- Go race tests and vet pass. Android SDK build, APK inspection, Flybit interoperability, and physical-device traffic tests are still required before distribution. Do not describe this checkpoint as a stable general-purpose VPN.
