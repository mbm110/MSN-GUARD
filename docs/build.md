# Build guide

## Requirements

- Android SDK 36
- Android NDK `26.3.11579264`
- CMake `3.22.1`
- JDK 17
- Rust stable with Android targets
- `cargo-ndk`

## Build arm64 debug APK

From repository root in PowerShell:

```powershell
.\core\build-android.ps1
New-Item -ItemType Directory -Force app\src\main\jniLibs\arm64-v8a
Copy-Item core\android-libs\arm64-v8a\libaether.so app\src\main\jniLibs\arm64-v8a\libaether.so -Force
.\gradlew.bat :app:assembleDebug -PtargetAbi=arm64-v8a
```

APK output:

```text
app/build/outputs/apk/debug/app-arm64-v8a-debug.apk
```

## Build armv7 debug APK

Build Aether for `armeabi-v7a`, place its output at `app/src/main/jniLibs/armeabi-v7a/libaether.so`, then run:

```powershell
.\gradlew.bat :app:assembleDebug -PtargetAbi=armeabi-v7a
```

## Linux and macOS

Use `./gradlew` instead of `gradlew.bat`. The wrapper must retain its executable Git mode:

```bash
git update-index --chmod=+x gradlew
```
