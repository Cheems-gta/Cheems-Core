# Making — independent open-source networking core

**Making** is the independent Go/Android native transport engine integrated into the **Doreena** Android VPN app. This branch publishes the native engine source corresponding to the current Doreena integration, including its tested build-time integration changes.

## Contents

- `native/quic/` — Go transports, proxy bridging, Android gomobile APIs, and TUN machinery, from the exact upstream version pinned by Doreena.
- `integration/patch_making_timeout.py` — **source**, not a closed binary: the Doreena integration changes for native shutdown ordering, Android VPN lifecycle, Hysteria2 handshake latency and AnyTLS stream latency. The CI build **applies** it before compilation.
- `integration/android/win/cheems/core/CheemsBridge.java` — Android integration bridge used by Doreena. This class is an integration example, not part of the Go AAR.
- `.github/workflows/making-native-release.yml` — reproducible Android ARM/ARM64 `gomobile` AAR build, tests, checks for probe methods, and GitHub prerelease publication.

## Build and use

For an out-of-the-box binary, get `Making-android.aar` from this branch's tagged GitHub releases. The artifact exports a gomobile Java API and Android native `libgojni.so`; it is **not an Android application APK** or a standalone executable. A hosting Android app must integrate the library, network protection callbacks and VPN lifecycle itself.

To build from source, follow the GitHub Actions workflow. It uses Go, Java 17, Android SDK 35, Android NDK 27.2.12479018 and gomobile. The script expects the original pinned sources and rejects mismatches. The project intentionally preserves old Go module import paths (`github.com/Cheems-gta/Cheems-Core/native/quic`) until the corresponding GitHub repository rename and downstream import migration are coordinated.

The release also includes **Making-patched-source.tar.gz** which contains **post-patch** native code and the Android service sources. This distinction matters: a GitHub-generated source archive of the tag contains the patch **script** and original source, while the `Making-patched-source.tar.gz` asset contains the result of running it.

## Relationship to Doreena

Doreena's current Android integration lives at:

https://github.com/Cheems-gta/Cheems-Clash/tree/fix/making-disconnect-release-tun

The application still uses its own UI, imported nodes, notifications and VPN permission flow. The library does not depend on Mihomo. It is a preliminary independent engine release, **not** a claim of fully validated cross-client ABI compatibility.

## Open source and license review

This branch descends from the Doreena-pinned historical transport preview, which carries **`COPYING` containing GNU GPL version 3**, plus third-party notices. The root of the **main** branch has a newer MIT license statement for the project-owned code to which that statement applies. The effect of historical copyright grants, contributor rights, and transitive licenses still needs a careful review before claiming that *all* of this branch can be relicensed under MIT.

Preserve third-party notices and the original `COPYING` when redistributing code or binaries; do not assume a change of repository name changes licensing.

## Status and security

- Source code and build scripts are public; no credentials, subscription endpoints, or private profiles are included intentionally.
- Go compilation and tests and Android AAR class/API verification run in CI.
- Device-level VPN disconnect/reconnect, transport stability and latency measurements require separate validation on physical Android devices.
- Some compatibility modes bypass TLS server certificate verification, which weakens server authentication. Use properly authenticated endpoints where possible.

**Public project name: Making.** Until a repository administrator performs the GitHub repository rename, this public branch remains under the old URL `Cheems-gta/Cheems-Core`; that URL does not mean the project is still branded Cheems Core.
