# Making

> **Latest independent Making engine for Doreena:** [Making latest source branch](https://github.com/Cheems-gta/Cheems-Core/tree/making-latest) · [Standalone build and integration guide](https://github.com/Cheems-gta/Cheems-Core/blob/making-latest/MAKING.md). This branch contains the exact upstream engine version pinned by Doreena plus the currently applied TUN/latency integration source, and a workflow that publishes an Android `.aar` and post-patch source archive. The main branch is not identical to Doreena's packaged core.


**Making** is an experimental open-source Android networking and proxy project, formerly known as **Cheems Core**.

> **Repository rename pending:** the GitHub repository and Go module still use `Cheems-Core` paths. Do not change import paths until the repository rename and downstream migration are coordinated.

## Scope and status

This repository contains the original Android Java client and an optional Go-based QUIC / Hysteria 2 transport. It is **not** the same source tree as the separate **Cheems Clash** Android app. Features implemented in Cheems Clash (including its Android TUN integration) must not be assumed to exist in this repository.

The project is experimental. A passing CI build is not proof of compatibility with every server or Android device. Consult the implementation and tests before relying on a protocol.

## Build

See `.github/workflows/android-quic-aar.yml` for the Go and Android native build steps. The Android application and Go module retain their historical package identifiers until a coordinated migration.

## License

Project-owned source code is released under the [MIT License](LICENSE), subject to the rights of the respective contributors. Third-party components retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Security and privacy

Do not commit subscription URLs, node passwords, private keys, signing keys, or real user configuration. Report suspected leaks privately to the repository owner. Existing Git history and transitive dependencies still require a full security/license audit before a stable release.

---

## Historical Cheems Core documentation

# Cheems Core

Experimental independent Android proxy client (Android 9+, Java UI with an optional Go QUIC engine). It **does not embed Mihomo or sing-box**.

## Current implementation

- Import Clash YAML, Base64 subscriptions and common share links; preserve node names and SNI.
- Java TCP proxy transports: Shadowsocks AEAD, Trojan TCP/TLS, SOCKS5, HTTP CONNECT.
- **Hysteria 2 / HY2 (native alpha):** Go QUIC + HTTP/3 authentication (expects HTTP 233), bidirectional TCP proxy streams and a loopback SOCKS5 bridge. The Android frontend routes HTTPS/HTTP CONNECT tunnels via this bridge when the native AAR is actually packaged.
- Hysteria 2 SOCKS5 currently supports **TCP CONNECT only**. Datagram negotiation is enabled, but **UDP relay is not implemented**.
- Other protocols such as AnyTLS, VMess/VLESS, SS2022, WebSockets, Salamander obfuscation and port hopping are **not implemented**. Unsupported nodes must be marked unavailable rather than silently falling back to direct.
- Hysteria 2 uses strict TLS certificate/hostname verification by default. Users can paste a trusted PEM CA for one connection or use a SHA-256 leaf-certificate pin supplied in the node configuration. Nodes explicitly marked skip-cert-verify may use an unverified connection only after a two-step, session-only security warning. Unverified connections without a pin are vulnerable to impersonation and are not recommended.

## Android networking limitation

The frontend exposes a local **HTTP CONNECT** server on `127.0.0.1:8899`. This listener now requires a fresh per-service HTTP Basic password (user `cheems`); obtain the temporary credentials from the Android app and configure the consuming application explicitly. The internal native SOCKS5 bridge on `127.0.0.1:10990` also uses an independent ephemeral random password and a 32-client cap. There is **no Android VPNService / system-wide TUN traffic capture yet**, so installing this build will not automatically tunnel all phone apps.

The native Hysteria 2 implementation is **unverified against a real Flybit node** and should not be presented as a fully compatible release. The source and unit tests do not prove real-world QUIC interoperability.

## Builds

- `.github/workflows/android-quic-aar.yml`: tests Go code, builds the Android native AAR, verifies the generated Java bindings, tests/builds/lints the Android app, checks the APK contains `libgojni.so`, verifies debug signing, and uploads a checksummed `Cheems-Core-v0.3.4-hy2-tls-alpha.apk` workflow artifact **only if the CI job passes**.
- `.github/workflows/android.yml`: legacy Java-only workflow for manual use; **its APK does not contain the Hysteria 2 native engine** and must not be confused with the native build.
- Build tools: Java 17, Gradle 8.9, Android SDK 35, Android NDK 27.2.12479018, Go and `gomobile`.

The debug APK is test-signed; a production release requires a controlled release signing key and real-device testing. Node credentials are saved locally using Android Keystore and should never be committed or pasted into CI logs.

## Tests

Go tests include authentication framing, TCP request/response validation, partial writes, and local SOCKS5 data relay with synthetic destinations. Android JVM tests cover HY2 Clash YAML and share-link parsing, including explicit rejection of unsupported configurations.

**Outstanding**: a V0.3.4 CI build has succeeded, but authentication and actual TCP forwarding against a real, authorized Hysteria 2 service are NOT yet verified. Implement and test an Android VpnService/TUN bridge separately if full-device VPN is needed.


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

## V0.3.4 HY2 TLS diagnostics

- Optional trusted CA in inline PEM form (`ca-str` or inline `ca` in the imported HY2 node, or pasted once in Android) extends the trust store while preserving hostname checks. File paths and malformed CA material are not silently trusted.
- A node-provided `pinSHA256` / `pin-sha256` fingerprint pins the **leaf** server certificate; a mismatch blocks the connection. Do not confuse this with TLS client fingerprint selection.
- `skip-cert-verify: true` is merely a provider hint. It **never automatically disables** verification. The user must choose a one-time high-risk option and confirm again; it does not become a persistent setting. Using this without a trusted fingerprint is not recommended.
- The UI persists useful error status after rapid TLS/QUIC failures so that a failed attempt does not look like an untouched “not started” state.
- Go regression tests cover strict TLS defaults, malformed trust inputs, leaf certificate pin matching, and CA hostname validation; Android JVM tests cover importing pin and CA fields.
- This remains a local proxy, not Android system VPN, and build success does not establish connectivity to Flybit. No credentials, subscription URLs, or TLS private keys should be shared in issue reports.
