<div align="center">

<img src="docs/logo.png" width="160" alt="MSN-GUARD">

# MSN-GUARD

**Device-wide tunnelling for censored networks — Rust core, native Android client**

[![Build](https://img.shields.io/github/actions/workflow/status/mbm110/MSN-GUARD/build.yml?branch=master&style=for-the-badge&label=build)](https://github.com/mbm110/MSN-GUARD/actions)
[![Version](https://img.shields.io/badge/version-1.0.0-5CE68F?style=for-the-badge)](https://github.com/mbm110/MSN-GUARD/releases)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3A4FB0?style=for-the-badge&logo=android&logoColor=white)](https://github.com/mbm110/MSN-GUARD)
[![License](https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge)](LICENSE)

**English** · [فارسی](README.md)

</div>

---

## What this is

MSN-GUARD is a native Android VPN client that moves every packet leaving the device through one of four independent transports. That word *native* is doing real work here. Most tools in this space are proxies: they hand you a local SOCKS port, and whatever bothers to read the system proxy setting — usually just a browser — gets protected. Everything else leaks. MSN-GUARD binds Android's own `VpnService`, stands up a TUN interface, and takes ownership of the whole routing table. Every TCP stream, every UDP datagram, every QUIC flow, from every installed app, goes through the tunnel whether that app knows about proxies or not.

The codebase splits cleanly in two. A **Rust network core** implements the transports and negotiates with upstream gateways. A **Kotlin layer** owns the Android VPN lifecycle, the interface, and platform plumbing. There is no relay server in the middle and nothing of ours between you and the exit — the handset speaks directly to the upstream gateway.

The thing that separates this from a generic VPN app: it was built for Iranian mobile networks, and essentially every protocol decision in it came out of **measurement against MCI, Irancell and Samantel**, not from a spec document and not from a guess. Where the measured answer contradicted the documented one, the measurement won. Several of those findings are written up below, because they are the interesting part.

---

## Feature summary

| | |
|---|---|
| Device-wide tunnel | `VpnService` + TUN at MTU 1500; every app covered with zero per-app configuration |
| Four transports | MASQUE over HTTP/3, WireGuard, WARP-on-WARP, Psiphon |
| One-tap connect | A single button. Gateway selection, negotiation and recovery are automatic |
| Real UDP and QUIC | Datagrams bridged through `udpgw`, so video, gaming and voice calls actually work |
| Live status | Exit IP with country flag, data usage, session timer, streaming log |
| Quick Settings tile | Connect and disconnect without opening the app |
| Split tunnelling | Choose which apps stay outside the tunnel |
| Kill switch | If the tunnel drops, the network drops with it — no plaintext leak |
| DNS enforcement | Public resolvers only; carrier DNS is excluded outright |

---

## Architecture

The path an outbound packet takes, from app to internet:

1. The app writes an outbound packet.
2. It arrives on the Android TUN interface.
3. `tun2socks` with `lwIP` terminates it in userspace.
4. It is handed to the local SOCKS listener on `127.0.0.1:1819`.
5. The Rust core encrypts and encapsulates it.
6. It leaves for the upstream gateway, and from there to the internet.

Three layers of code make that path:

**Kotlin — interface and lifecycle**

| File | Responsibility |
|---|---|
| `MainActivity` | Interface, connection console, settings |
| `MsnGuardVpnService` | VPN lifecycle, TUN construction, Psiphon ladder |
| `MsnGuardTileService` | Quick Settings tile |
| `Tun2SocksManager` | Native tun2socks process supervision |

**Rust — compiled to `libaether.so`**

| File | Responsibility |
|---|---|
| `prober.rs` | Gateway discovery and ranking |
| `account.rs` | Device enrolment, MASQUE credential issuance |
| `quic.rs` | QUIC and HTTP/3 transport |
| `masque.rs` | CONNECT-IP encapsulation |
| `wireguard.rs` | Noise handshake and WireGuard transport |
| `netstack.rs` | TUN-level packet bridge |

**C — packet processing**

`badvpn tun2socks` with `lwIP` terminates TCP in userspace; `udpgw` shuttles UDP and QUIC datagrams over `127.0.0.1:7300`.

---

## Transports

### MASQUE over HTTP/3

`CONNECT-IP` over QUIC, built on [quiche](https://github.com/cloudflare/quiche). On the wire this is indistinguishable from an ordinary HTTPS session, which is the entire point: there is no custom protocol fingerprint for a DPI box to key on.

Four findings from building this, each of which cost real debugging time and each of which is documented in the source:

- The pseudo-header must be `:protocol = cf-connect-ip`. The standards-registered value `connect-ip` returns `403`. This is not written down anywhere public — it came out of bisecting header sets against a live edge.
- **HTTP/2 is not viable for this, at all.** Cloudflare does not advertise `SETTINGS_ENABLE_CONNECT_PROTOCOL` on HTTP/2, so extended CONNECT is rejected with `400` before you get to negotiate anything. HTTP/3 is the only path. An HTTP/2 fallback here isn't a degraded mode, it's dead code.
- The seed gateway order is measured, not alphabetical. Of eight known addresses only `162.159.198.2` and `162.159.198.1` return `200`; `162.159.196.1`, `195.1` and `192.1` refuse the QUIC handshake outright.
- The assigned gateway must be read from the MASQUE key-enrolment response, not from WireGuard registration. They differ, and using the wrong one gets you a working handshake into a gateway that will not carry your traffic.

### WireGuard

Direct transport with a full Noise handshake, for networks that haven't closed UDP. Where it works it's the fastest option available, and it's tried accordingly.

### WARP-on-WARP

A WireGuard tunnel nested inside another WireGuard tunnel. Useful when the outer path is reachable but the inner endpoint isn't — which is a real situation on some carriers, and cheap to support once the WireGuard transport exists.

### Psiphon, and the three-rung ladder

The rungs are ordered by **measured time-to-connect on a hostile carrier**, which is not the order Psiphon's own defaults would give you:

| Rung | Strategy | Budget | Why it sits there |
|---|---|---|---|
| A | Domain-fronted CDN cover | 60s | The only path that works on MCI, because it targets a CDN edge rather than a Psiphon server IP |
| B | All protocols, direct | 45s | Fast winner on a carrier that isn't blocking; Samantel connected via QUIC-OSSH in seconds |
| C | In-proxy / user relay | 75s | Last resort — residential addresses that aren't on the carrier's blocklist |

Here is what makes rung A first. On MCI, every direct dial fails **at the TCP layer**. No RST, no TLS alert, no handshake failure — the packets simply do not arrive, because the carrier has null-routed Psiphon's server IPs. Of the 430 server entries Psiphon ships in its embedded list, exactly 5 advertise the FRONTED-MEEK protocol. That ratio is why domain fronting is tried first instead of last: the default ordering spends its entire budget dialling addresses that will never answer. The winning rung is persisted per SIM, so after one successful connection each device starts from the rung that actually works on its own network.

---

## Engineering notes that matter

**The routing loop.** The Psiphon process has to stay outside the tunnel, or its own traffic re-enters the TUN and loops. `addDisallowedApplication` on our own package is the fix. This one presents as a mysterious total stall rather than an error, so it's worth knowing about before you go looking for it in the transport code.

**UDP and QUIC.** lwIP terminates TCP only. Datagrams cross through `udpgw` on `127.0.0.1:7300` with a 128-connection ceiling. Skip this and QUIC, online gaming and most voice calls break while TCP browsing looks fine — a failure mode that is easy to misdiagnose as a slow tunnel.

**MTU.** Pinned at 1500. Anything smaller fragmented packets and cost measurable throughput on the MASQUE path.

**SOCKS port.** Fixed at `127.0.0.1:1819`, not configurable. In VPN mode nothing external binds it, so exposing a setting would only have created a way to break the app.

**Pre-tunnel packet backlog.** Android brings the TUN up before a tunnel exists, so device traffic queues behind it for several seconds. The old behaviour flushed that entire backlog into a brand-new QUIC connection the moment the CONNECT-IP stream opened — while the congestion window was still at its initial value. The `:status 200` response then had to compete with the flood for window space, and starved. Those packets are now dropped until the tunnel is confirmed, and the count is reported in the log. This was worth about 25 seconds of connect latency.

**Identity rejection.** Only `401` and `403` count as identity rejection. `400` means the request was malformed. Conflating them threw away perfectly good enrolments and triggered pointless re-registration.

**Addressing.** TUN on `10.0.0.1/8`, router at `10.0.0.2`, DNS forced to public resolvers with carrier DNS excluded.

---

## Install

Grab the latest APK from [Releases](https://github.com/mbm110/MSN-GUARD/releases) or from the [Actions](https://github.com/mbm110/MSN-GUARD/actions) artifacts.

| Device architecture | File |
|---|---|
| ARM 64-bit — most current handsets | `app-arm64-v8a-debug.apk` |
| ARM 32-bit — older devices | `app-armeabi-v7a-debug.apk` |

Android 8.0 (API 26) or newer. Allow installation from unknown sources, and approve Android's VPN permission prompt on first connect.

---

## Build from source

Prerequisites: JDK 17, Android SDK 36, NDK `26.3.11579264`, CMake `3.22.1`, Rust stable with Android targets, and `cargo-ndk`.

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo install cargo-ndk

./gradlew assembleDebug -PtargetAbi=arm64-v8a,armeabi-v7a
```

Output lands in `app/build/outputs/apk/debug/`. `core/build-android.sh` compiles the Rust core per ABI and places `libaether.so`; Gradle invokes it, so you don't run it by hand.

Every push to `master` runs [`build.yml`](.github/workflows/build.yml), which builds and uploads APKs for both architectures as artifacts.

---

## Project layout

| Path | Contents |
|---|---|
| `app/src/main/java/…/` | Kotlin client |
| `app/src/main/cpp/aether_jni.cpp` | JNI bridge between Kotlin and the Rust core |
| `app/src/main/cpp/badvpn/` | tun2socks and lwIP, vendored |
| `core/aether/src/` | Rust network core |
| `core/quiche/` | Cloudflare's QUIC and HTTP/3 library, vendored |
| `.github/workflows/` | CI build workflow |
| `docs/` | Documentation and brand assets |

Repository language statistics are corrected via `.gitattributes`: `core/quiche` and `badvpn` are marked vendored so the language bar describes code written for this project — Rust and Kotlin — rather than the 7.6 MB of third-party library that only exists to satisfy the build.

---

## Security

Do not open public issues for security problems affecting the tunnel, credentials or user traffic. Private reporting instructions are in [SECURITY.md](SECURITY.md).

No credentials, keys or tokens are stored in this repository. The MASQUE device certificate is issued and stored on the handset at runtime.

---

## License

Released under the [GNU AGPL-3.0](LICENSE). Vendored libraries keep their own terms:

- [quiche](https://github.com/cloudflare/quiche) — QUIC and HTTP/3, BSD-2-Clause
- [badvpn](https://github.com/ambrop72/badvpn) — tun2socks, BSD-3-Clause
- [lwIP](https://savannah.nongnu.org/projects/lwip/) — TCP/IP stack, BSD-3-Clause
- [Psiphon](https://github.com/Psiphon-Labs/psiphon-tunnel-core) — tunnel core, GPL-3.0

---

<div align="center">

**Built and maintained by [mbm110](https://github.com/mbm110)**

</div>
