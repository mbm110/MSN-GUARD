# Aethery

<p align="center">
  <img src="docs/Untitled-1.png" width="140" alt="Aethery icon">
</p>

<p align="center">
  Native Android client for private, censorship-resistant connections.
</p>

<p align="center">
  <a href="https://github.com/ZethRise/Aethery/stargazers"><img src="https://img.shields.io/github/stars/ZethRise/Aethery?style=for-the-badge&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/ZethRise/Aethery/releases/latest"><img src="https://img.shields.io/github/downloads/ZethRise/Aethery/latest/total?style=for-the-badge" alt="Latest release downloads"></a>
  <a href="https://github.com/CluvexStudio/Aether"><img src="https://img.shields.io/badge/core-v1.6.0-101411?style=for-the-badge" alt="Aether core v1.6.0"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge" alt="AGPL-3.0"></a>
</p>

> **v0.8.0** — Aethery is an Android app around the [Aether core](https://github.com/CluvexStudio/Aether). It is not a replacement or fork of Aether's networking engine.

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
- Quick Settings tile uses last saved settings for connect/disconnect without opening app.
- Foreground notification shows upload/download totals, opens app on tap, and provides Disconnect action.
- Connection type picker: **VPN** routes device traffic through Android `VpnService`; **Proxy** exposes local SOCKS5 at `127.0.0.1:1819` by default for apps configured to use it.
- **MASQUE** over HTTP/3, with HTTP/2 fallback when available.
- **WireGuard** for networks where it is reachable.
- **WARP-on-WARP** (`gool`) support through the Aether core.
- Automatic endpoint scanning with IP-level diagnostics, cached-gateway reconnect, and Ironclad verification.
- Aether v1.6.0 Zero Trust enrolment through email OTP, service tokens, or an Access JWT.
- Custom DNS plus destination block/direct rules in Proxy mode and optional Zero Trust gateway filtering in VPN and Proxy modes.
- Retained Aether v1.6.0 Android FFI core builds into `libaether.so`; it is excluded from repository language statistics.
- App-level default protocol setting and direct links to releases/source.

## Protocol notes

| Protocol | Intended use |
| --- | --- |
| MASQUE | Recommended default. Uses HTTPS-like tunnel transport and can fall back to HTTP/2. |
| WireGuard | Fast direct transport where UDP/WireGuard is reachable. |
| WARP-on-WARP | Nested WireGuard transport supplied by Aether. It still needs a reachable outer WireGuard path. |

Network filtering differs by provider and location. A protocol appearing connected means Aether completed its tunnel readiness check; it does not promise that every destination is reachable on every network.

## Download

Draft and published builds are available from [Gitea Releases](https://git.diastom.xyz/ZethRise/Aethery/releases).

| Device ABI | Asset |
| --- | --- |
| 64-bit ARM | `Aethery-arm64-v8a.apk` |
| 32-bit ARM | `Aethery-armeabi-v7a.apk` |

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

The [Android release workflow](.gitea/workflows/android-release.yml) runs manually and builds signed release APKs for `arm64-v8a` and `armeabi-v7a`. It uploads direct `.apk` files to a **draft** Gitea Release. See the [release guide](docs/release.md).

To prepare v0.8.0:

```text
Open Gitea Actions, select Build Android APKs, choose Run workflow, and enter v0.8.0 as the release tag.
```

Review the draft assets and release note in Gitea, then publish the release when ready.

## Project layout

```text
app/                 Android application and JNI bridge
core/aether/         Aether Rust core used by this client
core/quiche/         QUIC/HTTP3 dependency used by Aether
.gitea/             issue forms and Android release workflow
```

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or pull request. Bug and feature forms are available from [New issue](https://git.diastom.xyz/ZethRise/Aethery/issues/new/choose).

## Security

Do not disclose security-sensitive tunnel, credential, or traffic issues in public issues. Read [SECURITY.md](SECURITY.md) for private reporting guidance.

## License

Aethery is licensed under [GNU AGPL-3.0](LICENSE). Aether and bundled dependencies retain their own license terms; see their respective files in `core/`.

## Credits

- [Aether](https://github.com/CluvexStudio/Aether) — network core.
- [quiche](https://github.com/cloudflare/quiche) — QUIC and HTTP/3 library used by Aether.
- Built by [ZethRise](https://github.com/ZethRise).
