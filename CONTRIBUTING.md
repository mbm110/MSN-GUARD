# Contributing to Aethery

Thanks for improving Aethery. This project is an Android client around the [Aether core](https://github.com/CluvexStudio/Aether); keep changes scoped to the client unless the core itself is the right place for the fix.

## Before opening an issue

1. Update to the latest draft or published build.
2. Check [open issues](https://github.com/ZethRise/Aethery/issues) for duplicates.
3. Use the bug or feature form. Include protocol, Android version, device ABI, and a redacted connection log for connection reports.
4. Never post keys, provisioning identities, private endpoints, full IP scans, or traffic captures in a public issue.

## Development setup

Install Android Studio, SDK 36, NDK `26.3.11579264`, CMake `3.22.1`, JDK 17, Rust stable, and `cargo-ndk`. See the [build guide](README.md#build-from-source) for an arm64 command.

The Android app loads `libaether.so` from `app/src/main/jniLibs/<abi>/`. Build or copy the matching Aether core library before running the app for that ABI.

## Change guidelines

- Keep Android UI changes native and dependency-light unless a dependency is clearly necessary.
- Preserve Android VPN safety: core transport sockets must stay protected from the TUN interface.
- Do not show **Connected** until the core reports actual tunnel readiness.
- Keep protocol-specific behavior in the Aether core when it is shared with other clients.
- Add actionable logs, but redact sensitive material by default.
- Keep release assets ABI-specific and named exactly as documented.

## Pull requests

1. Start from the latest `main` branch.
2. Keep each pull request focused on one problem.
3. Explain the user-visible change and test coverage in the description.
4. Run the relevant Gradle build before requesting review.
5. Include screenshots for UI changes and redacted logs for connection changes.

## Commit style

Use short imperative subjects, for example:

```text
fix: keep settings back button below status bar
feat: add armv7 debug release build
docs: explain Aether core boundary
```

## Code of conduct

Be respectful, specific, and constructive. Reports and reviews should focus on behavior and evidence, never on individuals.

## Security reports

Security issues follow [SECURITY.md](SECURITY.md), not public issues.
