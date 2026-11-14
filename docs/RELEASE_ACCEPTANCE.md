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
- AnyTLS import and framing helpers exist; complete interoperability is pending.
- VMess, VLESS/Reality, TUIC and SS2022 adapters are pending.
- System-wide VPNService/TUN forwarding and UDP forwarding are pending.
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
   node without direct fallback.
4. Start, stop, permission revocation, network changes, peer failure and reconnect
   leave no stale running state, sockets, workers or file descriptors.
5. TLS tests reject unknown roots, incorrect hostnames and incorrect pins.
6. Android device tests cover foreground/background operation, Wi-Fi/mobile
   switching and sustained traffic with bounded resource use.
7. Final APK passes build, lint, signature and packaged native-library checks.
   Document the exact compatibility matrix and remaining limitations.

The native APK workflow runs automatically only on main. Development branch
pushes may run transport checks, but do not automatically package an APK.
