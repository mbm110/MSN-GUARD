# Task: Aether v1.3.0 Android FFI upgrade

- Retain `core/` sources; mark them `linguist-vendored` for GitHub statistics.
- Keep existing JNI C exports and `cdylib` output (`libaether.so`).
- Carry selected v1.3.0 scanner coverage: expanded MASQUE CIDRs and ports, Ironclad mode, cached gateway reconnect, bounded probe cleanup, non-loopback SOCKS UDP relay binding.
- Expose Ironclad in Android scanner choices.
- Track Rust lockfile and quiche sources as Gradle Rust-build inputs.
- Build Rust tests and Android debug APK when local toolchains permit.
