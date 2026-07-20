# Architecture

Aethery is a native Android client around retained Aether v1.3.0 core sources. Android code owns the user interface, VPN lifecycle, and platform integration; Aether owns route discovery and tunnel transport. The retained core is marked vendored for GitHub language statistics and still builds into `libaether.so` for each Android ABI.

```text
MainActivity
    │ configuration and connection state
    ▼
AetherVpnService ── Android VpnService / TUN interface
    │
    ▼
NativeCore (Kotlin) ── JNI ── aether_jni (C++) ── libaether.so (Rust)
```

## Android layer

- `MainActivity` presents connection controls, protocol selection, diagnostics, and connection status.
- `AetherVpnService` creates the Android TUN interface, runs as a foreground service, and owns connect/disconnect lifecycle.
- The service reports `connecting`, `connected`, `failed`, and `disconnected` status broadcasts to the UI.
- Connection is shown as connected only after `NativeCore.isReady()` reports tunnel readiness.

## Native bridge

`NativeCore` loads two shared libraries:

- `libaether.so`: Aether Rust core, prebuilt for each Android ABI.
- `libaether_jni.so`: C++ JNI bridge compiled by CMake.

The bridge passes configuration and TUN file descriptor to Aether. It also registers `VpnService.protect()` as a socket protector, preventing core transport sockets from being routed back into the VPN TUN interface.

## ABI layout

Gradle builds per-ABI APKs. Before an Android build, the matching core library must exist at:

```text
app/src/main/jniLibs/<abi>/libaether.so
```

Supported ABIs are `arm64-v8a` and `armeabi-v7a`.
