# Aethery

<p align="center">
  <img src="app/src/main/res/drawable-nodpi/aethery_launcher.png" width="112" alt="Aethery icon">
</p>

<p align="center">
  Native Android client for private, censorship-resistant connections.
</p>

<p align="center">
  <a href="https://github.com/ZethRise/Aethery/releases"><img src="https://img.shields.io/github/v/release/ZethRise/Aethery?display_name=tag&style=for-the-badge&color=74c69d" alt="Release"></a>
  <a href="https://github.com/ZethRise/Aethery/actions/workflows/android-release.yml"><img src="https://img.shields.io/github/actions/workflow/status/ZethRise/Aethery/android-release.yml?branch=main&style=for-the-badge&label=Android%20build" alt="Android build"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge" alt="AGPL-3.0"></a>
  <a href="https://github.com/CluvexStudio/Aether"><img src="https://img.shields.io/badge/core-Aether-101411?style=for-the-badge" alt="Aether core"></a>
</p>

> **v0.1.1** — Aethery is an Android app around the [Aether core](https://github.com/CluvexStudio/Aether). It is not a replacement or fork of Aether's networking engine.

## What Aethery does

Aethery turns Aether into an Android-first VPN experience. It provides the native interface, Android VPN/TUN bridge, connection state, protocol picker, live connection logs, and release packaging. Aether remains responsible for route discovery, tunnel establishment, transport protocols, and encrypted traffic handling.

```text
Android UI + Android VPN/TUN
            │
            ▼
      Aethery client
            │ JNI
            ▼
 Aether core — discovery, MASQUE, WireGuard, routing
```

## Highlights

- Native Android UI with one-tap connect, connection state, motion, and live logs.
- Connection type picker: **VPN** routes device traffic through Android `VpnService`; **Proxy** exposes local SOCKS5 at `127.0.0.1:1819` by default for apps configured to use it.
- **MASQUE** over HTTP/3, with HTTP/2 fallback when available.
- **WireGuard** for networks where it is reachable.
- **WARP-on-WARP** (`gool`) support through the Aether core.
- Automatic endpoint scanning with IP-level diagnostics, cached-gateway reconnect, and Ironclad verification.
- Retained Aether v1.3.0 Android FFI core builds into `libaether.so`; it is excluded from GitHub language statistics.
- App-level default protocol setting and direct links to releases/source.

## Protocol notes

| Protocol | Intended use |
| --- | --- |
| MASQUE | Recommended default. Uses HTTPS-like tunnel transport and can fall back to HTTP/2. |
| WireGuard | Fast direct transport where UDP/WireGuard is reachable. |
| WARP-on-WARP | Nested WireGuard transport supplied by Aether. It still needs a reachable outer WireGuard path. |

Network filtering differs by provider and location. A protocol appearing connected means Aether completed its tunnel readiness check; it does not promise that every destination is reachable on every network.

## Download

Draft and published builds are available from [GitHub Releases](https://github.com/ZethRise/Aethery/releases).

| Device ABI | Asset |
| --- | --- |
| 64-bit ARM | `Aethery-arm64-v8.apk` |
| 32-bit ARM | `Aethery-Arm64-v7.apk` |

The second filename intentionally follows the current release naming convention, while its contents target `armeabi-v7a`.

Install an APK from Android Downloads after allowing installs from the source application when Android asks.

## Build from source

### Requirements

- Android Studio with Android SDK 36
- Android NDK `26.3.11579264`
- CMake `3.22.1`
- JDK 17
- Rust stable with required Android targets:

  ```powershell
  rustup target add aarch64-linux-android armv7-linux-androideabi
  ```

- `cargo-ndk`

### Build APKs

Gradle builds and stages matching Aether library automatically:

```powershell
.\gradlew.bat :app:assembleDebug -PtargetAbi=arm64-v8a
.\gradlew.bat :app:assembleDebug -PtargetAbi=armeabi-v7a
```

Build both ABI splits:

```powershell
.\gradlew.bat :app:assembleDebug
```

APK output:

```text
app/build/outputs/apk/debug/app-arm64-v8a-debug.apk
app/build/outputs/apk/debug/app-armeabi-v7a-debug.apk
```

## CI releases

The [Android release workflow](.github/workflows/android-release.yml) runs manually and builds debug APKs for `arm64-v8a` and `armeabi-v7a`. It uploads only direct `.apk` files to a **draft** GitHub Release. See the [release guide](docs/release.md).

To prepare v0.1.1:

```bash
Open **Actions**, select **Build Android APKs**, choose **Run workflow**, and enter `v0.1.1` as the release tag.
```

Review the draft assets and release note in GitHub, then publish the release when ready.

## Project layout

```text
app/                 Android application and JNI bridge
core/aether/         Aether Rust core used by this client
core/quiche/         QUIC/HTTP3 dependency used by Aether
.github/             issue forms and Android release workflow
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Bug and feature forms are available from [New issue](https://github.com/ZethRise/Aethery/issues/new/choose).

## Security

Do not disclose security-sensitive tunnel, credential, or traffic issues in public issues. Read [SECURITY.md](SECURITY.md) for private reporting guidance.

## License

Aethery is licensed under [GNU AGPL-3.0](LICENSE). Aether and bundled dependencies retain their own license terms; see their respective files in `core/`.

## Credits

- [Aether](https://github.com/CluvexStudio/Aether) — network core.
- [quiche](https://github.com/cloudflare/quiche) — QUIC and HTTP/3 library used by Aether.
- Built by [ZethRise](https://github.com/ZethRise).
