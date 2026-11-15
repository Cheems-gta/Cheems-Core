# Cheems Core 0.4.4 AnyTLS compatibility build

Changes in this APK:
- Native libraries use 16 KiB ELF alignment; the build verifies both ELF load segments and uncompressed APK entry alignment. This is a binary compatibility check, not an emulator/device test.
- AnyTLS imports and uses chrome, firefox, safari, ios, android, edge, 360, qq and random ClientHello presets. Empty/none uses standard TLS. Explicit ALPN and URI fp/client-fingerprint are forwarded.
- Proxy-node certificate verification is disabled by default at the user's request, without confirmation dialogs. Imported CA/pin settings are omitted from each connection copy; saved subscription data is unchanged. Encryption remains enabled, but server identity is not verified.
- The same selected policy reaches HY2, AnyTLS, VLESS TLS, VMess TCP/WS/gRPC, TUIC and the Java TLS node dialer. Reality retains its protocol authentication.
- VPN stack always receives a logger; an optional TUN offload-query failure no longer dereferences a nil logger. The regression test reproduces this with an unprivileged datagram socket and checks descriptor ownership on shutdown.
- Runtime events persist after app restart, with bounded size and credential/address redaction. Activity recreation no longer resets an active startup as an interrupted process.

Validation:
- Real local AnyTLS service: TLS handshake, password authentication, concurrent multiplexed streams, session reuse, all listed ClientHello presets and explicit ALPN.
- Self-signed certificate with a mismatched hostname connects under the selected skip policy. Strict native API calls still reject unknown CA, wrong hostname, wrong pin and wrong password.
- Native unit/integration tests and Android import, diagnostic persistence, compile, lint and signature checks run before artifact delivery.

Limits:
- No Flybit subscription credential is present in the test environment. These checks do not prove connectivity to a particular Flybit endpoint or on a specific phone/network.
- AnyTLS carries TCP; DNS uses TCP fallback through the selected node. General AnyTLS UDP/UoT is not implemented.
- This is a compatibility build, not a claim of all-protocol support or production stability. Existing unsupported transport combinations remain explicitly labelled.
- Android's system VPN permission is still required.

Install the APK, import your subscription if this is the first installation of package win.cheems.core.startupdiag, select a real regional AnyTLS entry, then tap Connect VPN. The connection is reported usable only after the startup forwarding check and VPN interface creation succeed.
