# Hysteria 2 implementation gate

Status: NOT IMPLEMENTED. Importing a node is not connectivity.

## Current blockers (verified in repository)
- Node.java rejects hysteria2 and hy2 as unsupported.
- Dialer.java has no Hysteria 2 transport.
- Android build has no QUIC stream/datagram implementation.
- CoreService exposes a loopback HTTP CONNECT listener, not Android VpnService.

## Required implementation
1. Use a real, Android-compatible QUIC transport with stream and datagram APIs; Java SSLSocket and HTTP/3-only clients are insufficient.
2. Verify TLS certificates and SNI, negotiate the required Hysteria 2 ALPN, and perform the Hysteria 2 authentication handshake.
3. Implement the Hysteria 2 TCP request/response framing and bidirectional forwarding with cancellation, backpressure, and timeouts.
4. Implement UDP session handling, datagram framing, fragmentation and cleanup if advertising UDP support.
5. Parse Clash YAML and hy2:// links consistently, including auth, SNI, obfuscation and optional TLS settings. Never silently ignore unsupported options.
6. Integrate the transport with Dialer and ProxyCore; only change Node.supported() after real transport exists.
7. Test against an independent Hysteria 2 server for TLS verification, auth rejection, TCP forwarding, UDP if claimed, reconnect and teardown.
8. Add Android VpnService separately if claiming system-wide VPN support; loopback HTTP CONNECT is not system-wide VPN.

## Release gate
- Do not publish an APK as Hysteria 2 compatible until the integration tests pass.
- Do not describe successful Gradle builds or node import as protocol compatibility.
- Do not include real subscription URLs, passwords or tokens in source, CI logs, or test fixtures.
