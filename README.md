# Cheems Core V0.2

Independent experimental Java node proxy for Android 9+. No Mihomo or sing-box runtime.

- Import Clash YAML, Base64 subscriptions and SS/Trojan/SOCKS/HTTP share links.
- SS TCP: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305; platform crypto, SIP004 framing.
- Trojan TCP/TLS with strict certificate and hostname validation.
- SOCKS5 and HTTP CONNECT upstreams, optional TLS as specified by the node.
- Local HTTP CONNECT listener on 127.0.0.1:8899. No direct fallback.
- 24 concurrent tunnels, bounded workers, explicit stop closes sockets.
- Android foreground service; credentials encrypted with Android Keystore; backups disabled.
- Import, select, verify HTTP forwarding to example.com, start local proxy.

This is **not a system-wide Android VPN**. Applications must explicitly use the local HTTP proxy, and only CONNECT requests are accepted. Node verification performs a plain HTTP request through the selected tunnel; it is a forwarding check, not a full security or performance assessment. UDP, QUIC, VMess, VLESS/Reality, Hysteria2, SS2022, WebSocket and plugins are not supported. Unsupported imported nodes remain visible and cannot be selected for connection. Subscription URL is not retained; reimport to update.

CI runs parser, AEAD and SOCKS interoperability tests, Android lint, compilation and signature verification. Actual Flybit compatibility depends on the node protocol and transport. Physical-device and real-provider verification remain pending.

Build: Java 17, Gradle 8.9, Android SDK 35; `gradle :app:testDebugUnitTest :app:assembleDebug :app:lintDebug`.

APK is debug-signed. V0.1 may need uninstalling first because the original build did not preserve its signing key. Releases are experimental.
