# Walkthrough: Aether v1.3.0 Android FFI upgrade

## Retained ABI

`core/aether/Cargo.toml` remains `cdylib`; `src/ffi.rs` JNI C exports stay unchanged. `aether_version()` now reports `1.3.0`.

## Scanner

- Expanded v1.3.0 MASQUE IPv4/IPv6 ranges and candidate ports.
- `ironclad` repeats successful HTTP/3 CONNECT-IP verification before candidate selection.
- Existing cache path remains first connection attempt. Failed cached checks fall back to fresh scan; successful entries refresh asynchronously.
- Every HTTP/3 probe is bounded by `tokio::time::timeout`; dropped future releases probe socket/resources.

## SOCKS

UDP ASSOCIATE now binds relay on SOCKS listener address, not hard-coded loopback. Existing `127.0.0.1` Android configuration remains loopback-only.

## Build tracking

Gradle Rust task now invalidates for `Cargo.lock` and vendored `core/quiche` changes. `.gitattributes` keeps retained core sources out of GitHub language statistics.
