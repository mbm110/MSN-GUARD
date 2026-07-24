# Build guide

## Requirements

- Android SDK 36
- Android NDK `26.3.11579264`
- CMake `3.22.1`
- JDK 17
- Rust stable with Android targets
- `cargo-ndk`

## Build debug APKs

Gradle invokes `core/build-android.ps1` on Windows or `core/build-android.sh` on Linux/macOS when matching `libaether.so` is missing. Run from repository root:

```powershell
.\gradlew.bat :app:assembleDebug -PtargetAbi=arm64-v8a
.\gradlew.bat :app:assembleDebug -PtargetAbi=armeabi-v7a
```

Build both ABI splits:

```powershell
.\gradlew.bat :app:assembleDebug
```

APK outputs:

```text
app/build/outputs/apk/debug/app-arm64-v8a-debug.apk
app/build/outputs/apk/debug/app-armeabi-v7a-debug.apk
```

## Linux and macOS

Use `./gradlew` instead of `gradlew.bat`. The wrapper must retain its executable Git mode:

```bash
git update-index --chmod=+x gradlew
```
