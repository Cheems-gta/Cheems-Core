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


## SS2022 UDP checkpoint

The SS2022 native TUN adapter now routes UDP through protected connected sockets to the selected node. Local reference-service UDP echo tests pass for AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305, with context cancellation and rejected-protection checks. DNS can use this UDP backend and retains the existing same-node TCP fallback. This supersedes the earlier TCP-only checkpoint; UDP remains experimental pending provider and Android device verification. No APK is delivered.


## TUIC v5 native checkpoint

An experimental native TUIC v5 adapter uses `sing-quic` v0.7.1 with protected physical-network sockets, strict TLS, TCP, UDP datagrams and UDP stream relay. Local reference-service round trips pass for TCP and both UDP modes; wrong passwords and unknown TLS roots are rejected. Existing transport race tests and vet pass after updating upstream quic-go to v0.59.0 to resolve QPACK API conflicts. This adds a second QUIC implementation; APK size and device resource use remain unmeasured. Android import/start/TUN registration for TUIC is not implemented yet, so TUIC remains unavailable in the app. Provider/device interoperability, license/source distribution and packaged native binding checks remain required. The GPL-3.0-or-later sing-quic dependency must be included in release source/license compliance. No APK is delivered.


## TUIC Android integration checkpoint

TUIC v5 share-link/YAML import, strict option validation, gomobile startup and native TCP/UDP TUN backend registration are implemented experimentally. Both native UDP datagrams and QUIC stream relay modes are selectable through the imported configuration. DNS uses the same selected backend with the existing same-node TCP fallback. Credentials remain local; TLS chain/hostname checks stay enabled. 0-RTT, disabled SNI, certificate pins and client TLS fingerprint emulation are unsupported. A local bridge lifecycle regression checks registration and cleanup; Go race/vet checks pass. Android binding/Java checks run in source-only CI. Provider interoperability, physical-device traffic, background stability and network switching remain unverified; no APK is delivered.


## WebSocket native transport checkpoint

Optional ordinary RFC6455 WebSocket transport is implemented for VMess and VLESS native clients using gorilla/websocket v1.5.3 (BSD-2-Clause). It upgrades an already protected TCP/TLS socket and preserves the configured HTTP host/path. Verified-TLS VMess and VLESS WebSocket round trips pass against local reference peers. WebSocket early data, arbitrary custom headers, gRPC and Reality remain unimplemented. Android import/start binding for WebSocket is still pending, so the app continues rejecting WebSocket nodes. This is source progress, not provider interoperability; no APK is delivered.


## WebSocket Android integration checkpoint

VMess and VLESS ordinary WebSocket transport options now cross the Android importer and gomobile startup boundary. HTTP Host and path are preserved from share links and YAML; non-Host custom headers and early-data configuration are rejected. Native verified-TLS WebSocket reference-service tests and Go race/vet checks pass. Android source-only CI checks the generated WebSocket startup API signatures and JVM import tests. gRPC and Reality remain pending; no APK should be delivered until all three requested transport integrations pass their source checks. Provider and physical-device validation are still required.


## Standard gRPC Tun checkpoint

VMess and VLESS standard bidirectional Hunk/Tun over verified TLS/HTTP2 are implemented with protected native upstream connections. Android imports service name and authority, and gomobile forwards both to the native transport. Independent wire-vector checks and local VMess/VLESS reference-service round trips pass along with Go race/vet checks. TunMulti, compression, arbitrary service names containing slashes, h2c and Reality remain unsupported. TLS gRPC requires an explicit nonempty supported service name. Android source-only CI validates the generated API signatures, JVM imports and compilation. The requested combined APK is still blocked on Reality integration and its checks; live-provider/device verification remains pending.


## Reality preview checkpoint

VLESS TCP Reality (empty flow) is integrated through Android import and native startup. Supported fingerprints are chrome/firefox. Independent synthetic reference tests verify decrypted ClientHello fields, authenticated TLS and VLESS echo traffic, and rejection of wrong public keys/short IDs and ordinary TLS certificates. Go race/vet pass. XTLS Vision, Reality over WS/gRPC, ML-DSA authentication and other fingerprints remain unsupported. The three preview families now have implementation paths: VMess/VLESS TLS WebSocket, standard TLS gRPC Tun, and VLESS TCP Reality. This is a scoped transport preview, not universal compatibility or proof of Flybit interoperability. Android source CI must pass before building the combined device-test APK; physical device acceptance follows.


## Virtual DNS and readiness correction

Previously the flow judge accepted virtual DNS as generic UDP, bypassing NewDNSPacket; replies also used the upstream resolver address rather than the virtual address queried by Android. Both paths are corrected. DNS requests are copied and handled asynchronously with bounded concurrency and tunnel-lifetime cancellation; UDP falls back to TCP through the selected backend. Virtual TCP DNS is redirected to the same node resolver. Packet-dispatch regressions cover IPv4/IPv6 replies and UDP-to-TCP fallback without root or live provider access.

Startup now automatically checks the local authenticated proxy through the selected node to example.com:80, and distinguishes interface establishment from successful target TCP forwarding. It does not claim TUN/device validation from that check. UI metrics include native TUN traffic/DNS counts and sanitized error stages, with per-session isolation. Physical Flybit validation is still required; certificate trust errors are not automatically bypassed.
