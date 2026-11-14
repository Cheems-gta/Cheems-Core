# Cheems Core

Experimental independent Android proxy client (Android 9+, Java UI with an optional Go QUIC engine). It **does not embed Mihomo or sing-box**.

## Current implementation

- Import Clash YAML, Base64 subscriptions and common share links; preserve node names and SNI.
- Java TCP proxy transports: Shadowsocks AEAD, Trojan TCP/TLS, SOCKS5, HTTP CONNECT.
- **Hysteria 2 / HY2 (native alpha):** Go QUIC + HTTP/3 authentication (expects HTTP 233), bidirectional TCP proxy streams and a loopback SOCKS5 bridge. The Android frontend routes HTTPS/HTTP CONNECT tunnels via this bridge when the native AAR is actually packaged.
- Hysteria 2 SOCKS5 currently supports **TCP CONNECT only**. Datagram negotiation is enabled, but **UDP relay is not implemented**.
- Other protocols such as AnyTLS, VMess/VLESS, SS2022, WebSockets, Salamander obfuscation and port hopping are **not implemented**. Unsupported nodes must be marked unavailable rather than silently falling back to direct.
- TLS certificate and hostname checks are enforced. Nodes configured to bypass certificate validation are not accepted.

## Android networking limitation

The frontend exposes a local **HTTP CONNECT** server on `127.0.0.1:8899`. This listener now requires a fresh per-service HTTP Basic password (user `cheems`); obtain the temporary credentials from the Android app and configure the consuming application explicitly. The internal native SOCKS5 bridge on `127.0.0.1:10990` also uses an independent ephemeral random password and a 32-client cap. There is **no Android VPNService / system-wide TUN traffic capture yet**, so installing this build will not automatically tunnel all phone apps.

The native Hysteria 2 implementation is **unverified against a real Flybit node** and should not be presented as a fully compatible release. The source and unit tests do not prove real-world QUIC interoperability.

## Builds

- `.github/workflows/android-quic-aar.yml`: tests Go code, builds the Android native AAR, verifies the generated Java bindings, tests/builds/lints the Android app, checks the APK contains `libgojni.so`, verifies debug signing, and uploads a checksummed `Cheems-Core-v0.3.3-hy2-alpha.apk` workflow artifact **only if the CI job passes**.
- `.github/workflows/android.yml`: legacy Java-only workflow for manual use; **its APK does not contain the Hysteria 2 native engine** and must not be confused with the native build.
- Build tools: Java 17, Gradle 8.9, Android SDK 35, Android NDK 27.2.12479018, Go and `gomobile`.

The debug APK is test-signed; a production release requires a controlled release signing key and real-device testing. Node credentials are saved locally using Android Keystore and should never be committed or pasted into CI logs.

## Tests

Go tests include authentication framing, TCP request/response validation, partial writes, and local SOCKS5 data relay with synthetic destinations. Android JVM tests cover HY2 Clash YAML and share-link parsing, including explicit rejection of unsupported configurations.

**Outstanding**: independently confirm GitHub Actions succeeds; test authentication and actual TCP forwarding against a real, authorized Hysteria 2 service; implement and validate a TUN/VpnService bridge if system-wide VPN connectivity is required.


## V0.3.1 HY2 alpha changes

- Providers marking HY2 nodes `skip-cert-verify: true` no longer make the import parser reject the endpoint outright. **The client does not disable certificate validation**: it shows a warning, then makes a regular strictly verified TLS attempt if the user chooses. Servers with untrusted or mismatched certificates still fail until the provider supplies valid SNI, a trusted CA or a certificate pinning strategy.
- The Android version label comes from APK metadata, and the UI distinguishes native connection attempts, healthy local listeners and detected QUIC disconnects.
- Android service shutdown is synchronous with native stop to avoid the previous asynchronous old-session/new-session race.
- Both local proxy listeners enforce per-service credentials rather than trusting loopback as a private socket. The HTTP proxy's username/password can be copied from the app; its password changes when the service restarts.
- Subscription parsing now repeats its 2 MB limit after Base64 decoding and reports malformed share links clearly.
- Regression tests exercise HTTP Basic rejection and SOCKS5 auth success/rejection. Tests still cannot prove compatibility with a live Flybit server.

## V0.3.2 HY2 alpha changes

- The Android foreground service now monitors the native QUIC session after startup. If the Hysteria 2 tunnel drops, the stale local HTTP CONNECT listener is shut down instead of continuing to appear usable. This is disconnect handling, **not** automatic reconnection.
- Native SOCKS5 credential cleanup uses an atomic compare-and-set to prevent a failed older connection attempt from clearing a newer session's token.
- Android 13+ clipboard previews mark copied local proxy authentication credentials as sensitive. Clipboard contents are still accessible to software with permitted clipboard access; do not share the temporary password.
- APK versionCode is raised to 5, with an explicitly distinct V0.3.2 alpha artifact.

**Build and interoperability disclaimer:** Commit uploads alone do not confirm the newest GitHub Actions run passed. Hysteria 2 compatibility against actual Flybit endpoints, full Android VPN capture, UDP forwarding, AnyTLS, and automatic failover are still unverified or unimplemented.

## V0.3.3 diagnostic milestone

- HY2 HTTP/3 authentication handling now checks status `233` and closes its response body without reading to EOF. This avoids an unnecessary block when a peer keeps the response stream open.
- The Android app's **Verify complete proxy forwarding** action checks the full loopback HTTP CONNECT path rather than contacting the selected dialer directly. It requires the current node's foreground proxy to be started.
- The diagnostic reports distinct stages for: local HTTP proxy connectivity, HTTP CONNECT / proxy authentication or upstream TCP failure, and remote HTTP status. There is **no fallback to an unproxied direct connection**.
- Android users can copy the last 40 runtime event lines. The diagnostic itself does not print node or proxy passwords; review copied logs before sharing.
- Unit tests use synthetic loopback proxy interactions and a response body spy. These provide useful regression coverage but **do not establish real Flybit compatibility**.

To validate on a phone after the CI artifact is verified: install the integrated V0.3.3 alpha, import the authorized subscription, select one supported Hysteria 2 node, start the local proxy, run the full forwarding verification, and inspect the diagnostic log for the failed stage. The app is **not** a system-wide VPN and still requires applications to explicitly configure a local proxy and authenticate. Never paste a subscription URL, node password, or local proxy password into an issue or public log.
