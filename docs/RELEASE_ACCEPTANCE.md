# Compatibility release acceptance

Work continues on `compatibility`, based on main commit
`19217c0d485e5b84e0ec14de6217131a1c00c122`. No intermediate APK delivery.

## Scope

Target modern SS AEAD/2022, Trojan, AnyTLS, Hysteria 2, VMess,
VLESS with TLS/Reality, TUIC, SOCKS5 and HTTP(S). Each supported transport
combination must be listed individually. WireGuard, SSH and NaiveProxy remain
separate future integrations until their implementations and tests exist.
This scope is not a claim of universal protocol compatibility.

## Current baseline

- Java TCP adapters exist for SS AEAD, Trojan, SOCKS5 and HTTP(S).
- Hysteria 2 has a Go QUIC implementation and Android loopback bridge.
- AnyTLS has an experimental native TCP adapter and DNS-over-TCP path. Independent local protocol tests pass; Flybit interoperability, Android CI binding validation and device VPN tests remain pending. AnyTLS UDP is unsupported.
- VLESS TCP+TLS and VMess TCP/TLS are experimental. VLESS Reality, WebSocket, gRPC, XTLS Vision and UDP, plus VMess WebSocket and gRPC remain unsupported. VMess TCP/TLS and UDP are still experimental and covered by local reference-service tests only. TUIC and SS2022 adapters are pending.
- Android VPNService/TUN forwarding supports experimental HY2, AnyTLS TCP, VLESS TCP+TLS, and SOCKS5. SOCKS5 uses TCP CONNECT and UDP ASSOCIATE through the selected node; DNS has same-node TCP fallback. Other AnyTLS/VLESS UDP is unsupported; provider interoperability and real-device validation remain pending.
- Existing provider observations: certificate authority rejection and QUIC timeout.

## Trust-store correction

Export the Java platform's trusted CA certificates to the Go TLS configuration.
Keep the provider-supplied CA limit at 64 KiB; bound the combined bundle at 2 MiB.
Preserve chain verification, hostname verification and optional leaf pins.
An empty or oversized platform trust store fails explicitly.
This addresses the missing Android trust-store bridge; it does not establish
that a particular provider certificate or network is valid.

## Release gates

1. Configuration import preserves credentials and transport options, with explicit
   errors for unsupported combinations.
2. Each advertised combination passes authentication and bidirectional traffic
   tests against an independent server, including rejection of invalid credentials.
3. VPNService owns a TUN interface; upstream sockets bypass the VPN through socket
   protection. DNS, IPv4, IPv6 and supported UDP traffic pass through the selected
   node without direct fallback. Verify SOCKS5 UDP ASSOCIATE and same-node DNS fallback.
4. Start, stop, permission revocation, network changes, peer failure and reconnect
   leave no stale running state, sockets, workers or file descriptors.
5. TLS tests reject unknown roots, incorrect hostnames and incorrect pins.
6. Android device tests cover foreground/background operation, Wi-Fi/mobile
   switching and sustained traffic with bounded resource use.
7. Final APK passes build, lint, signature and packaged native-library checks.
   Document the exact compatibility matrix and remaining limitations.

The native APK workflow runs automatically only on main. Development branch
pushes may run transport checks, but do not automatically package an APK.

## Protected network checkpoint

The Go HY2 configuration now accepts a physical-network resolver and socket
protection callback. A rejected protection request or DNS failure stops the
connection without falling back to another resolver. The mobile bridge exposes
`StartWithNetwork`; existing local-proxy callers keep their previous API.
The Android VPN service implements and calls this interface for HY2, AnyTLS TCP, VLESS TCP+TLS, and VMess TCP/TLS. AnyTLS `sing-anytls` and VMess `sing-vmess` use GPL-3.0-or-later; distribution obligations remain a release gate. The TUN path is still alpha; no device stability or leak-free claim is made.

A local HTTP/3 test peer verifies TLS trust, HY2 authentication, bidirectional
TCP stream payload, wrong-password rejection and UDP socket cleanup. Additional
tests verify protection rejection, resolver failure and immediate cancellation
of startup by Stop. Go race tests and vet pass. These tests do not establish
Flybit interoperability, QUIC obfuscation, congestion-control compatibility or
Android device stability.


## Shadowsocks 2022 TCP checkpoint

SS2022 TCP is wired through the independent `github.com/sagernet/sing-shadowsocks` v0.2.9 protocol library and protected native upstream sockets. Import accepts standard base64 PSKs of the exact method key size for `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, and `2022-blake3-chacha20-poly1305`. Multi-key identities, plugins and SS2022 UDP remain unsupported. The local reference-service TCP echo test and Go race/vet checks pass; Android binding, provider interoperability and physical-device validation remain release gates. The dependency is GPL-3.0-or-later, with source/license distribution obligations required before APK release. No APK is delivered at this checkpoint.
