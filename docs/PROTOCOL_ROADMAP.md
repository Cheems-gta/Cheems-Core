# Cheems Core protocol compatibility roadmap

Status: **targets only**, not claims of support.

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
5. Add Android VPNService, DNS routing, leak tests and reconnect tests.
6. Release only tested combinations; maintain versioned compatibility matrix.

Security defaults: loopback-only local listener until authentication/access controls exist, no plaintext credential logging, TLS verification enabled, no silent fallback on handshake failures.

No universal 100% compatibility claim: variants and protocol versions evolve.
