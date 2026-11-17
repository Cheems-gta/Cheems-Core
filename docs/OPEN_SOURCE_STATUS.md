# Making — open-source status and integration guide

Making is developed in public. The repository is currently named `Cheems-Core` for compatibility with existing Go module import paths.

## Source locations

- **Making / Cheems Core:** https://github.com/Cheems-gta/Cheems-Core — mainline Android/Go source code.
- **Doreena Android application:** https://github.com/Cheems-gta/Cheems-Clash — Android app integrating the independent Making engine.
- **Doreena's current Making integration branch:** https://github.com/Cheems-gta/Cheems-Clash/tree/fix/making-disconnect-release-tun
- **Native integration and compatibility changes:** `integration/patch_making_timeout.py` in the Doreena branch. This build-time patch applies additional TUN lifecycle, native shutdown and latency-probing changes to the pinned upstream source.

**Important:** The current default branch of this repository should not be described as identical to Doreena's packaged Making engine. The Android app pins Cheems Core commit `148b1034255a4a097695baf6c173c1f545a51ae1`, copies its Java sources, applies its integration patch and compiles a Go Android library. Look at the pinned revision *and* integration patch to reproduce the app's actual engine.

## How to inspect and reproduce

1. Clone this repository for the Making core source, or clone the Doreena repository for the version currently used in the Android app.
2. Review Doreena's `.github/workflows/android.yml`, including the fixed upstream revision and commands running `integration/patch_making_timeout.py`.
3. The Doreena workflow runs Go tests and `go vet`, builds a native AAR with `gomobile bind`, checks its generated Java bridge methods, assembles the Android APK, verifies APK signing, and publishes a preview GitHub Release.
4. The native AAR contains Android native library artifacts such as `libgojni.so`; these are compiled artifacts, *not* substitutes for distributing the corresponding source.
5. Local verification requires a supported Android SDK/NDK and the versions declared in the workflow. CI success is not proof of real-device connection, disconnect/reconnect, or protocol interoperability.

## Licensing and provenance

The current Making repository root has an `LICENSE` containing the MIT License for the project-owned code to which that grant applies. The **pinned historical revision** used by the Doreena build contains a `COPYING` file with the **GNU GPL version 3** text; the app's integration workflow copies it to the APK's bundled license notices.

Do **not** assume the root MIT file retroactively relicenses every historical commit, independently contributed component, or third-party dependency. Before redistributing a separately packaged standalone Making engine, audit the effective license of the exact revision and integrated changes, contributor ownership, and direct/transitive dependency notices. Do not remove a prior GPL notice merely to simplify distribution. See `THIRD_PARTY_NOTICES.md` for the project's incomplete inventory.

## Repository naming

The public project name is **Making**. Existing repository names, historical package names, and Go module paths retain `Cheems-Core` for now. Renaming the GitHub repository or Go module requires coordinating imports and downstream Android builds, and is **not** needed to make the existing sources publicly readable.

## Security for contributors

Never publish real subscription URLs, authentication credentials, node passwords, private keys, debug signing secrets, or private user profiles. The Doreena compatibility build may disable TLS certificate verification for some connections; this weakens server identity checks. Avoid describing this compatibility mode as secure by default.

## Current scope of "open source"

**Already public:** core repository, Android frontend repository, integration patch, CI build recipes, root license and third-party notices.

**Still needed for a polished standalone Making release:** consolidate and test Doreena's integrated core changes into a separately buildable engine tree; review licensing and third-party notices against the exact source/binary; document a stable public API and release reproducible source/binary packages. No separate standalone Making release is claimed here.
