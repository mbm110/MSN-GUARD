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

The thing that separates this from a generic VPN app: it was built for Iranian mobile networks, and essentially every protocol decision in it came out of **measurement against real hostile carriers**, not from a spec document and not from a guess. Where the measured answer contradicted the documented one, the measurement won — repeatedly, and in ways that were not obvious in advance.

> **A note on what this document does not say.** The connection strategy — handshake parameters, gateway selection, ladder ordering, timing budgets, the specific values that make a session survive an active filter — is the result of a long and expensive measurement campaign against live carriers. Those details are deliberately not published here. This README describes *what* the client does and *why* it is shaped the way it is; it does not hand over a working recipe. Circumvention advantages have a shelf life measured by how quickly they can be copied, and the useful ones stay unwritten.

---

## Feature summary

| | |
|---|---|
| Device-wide tunnel | `VpnService` + TUN; every app covered with zero per-app configuration |
| Four transports | MASQUE over HTTP/3, WireGuard, WARP-on-WARP, Psiphon |
| One-tap connect | A single button. Gateway selection, negotiation and recovery are automatic |
| Real UDP and QUIC | Datagrams bridged in userspace, so video, gaming and voice calls actually work |
| Live status | Exit IP with country flag, data usage, session timer, streaming log |
| Quick Settings tile | Connect and disconnect without opening the app |
| Split tunnelling | Choose which apps stay outside the tunnel |
| Kill switch | If the tunnel drops, the network drops with it — no plaintext leak |
| DNS enforcement | Public resolvers only; carrier DNS is excluded outright |
| Verified connect | The dial only reports success once traffic has actually moved |

---

## Architecture

The path an outbound packet takes, from app to internet:

1. The app writes an outbound packet.
2. It arrives on the Android TUN interface.
3. `tun2socks` with `lwIP` terminates it in userspace.
4. It is handed to a local SOCKS listener bound to loopback.
5. The Rust core encrypts and encapsulates it.
6. It leaves for the upstream gateway, and from there to the internet.

Three layers of code make that path:

**Kotlin — interface and lifecycle**

| File | Responsibility |
|---|---|
| `MainActivity` | Interface, connection console, settings |
| `MsnGuardVpnService` | VPN lifecycle, TUN construction, transport supervision |
| `MsnGuardTileService` | Quick Settings tile |
| `Tun2SocksManager` | Native tun2socks process supervision |

**Rust — compiled to `libaether.so`**

| File | Responsibility |
|---|---|
| `prober.rs` | Gateway discovery and ranking |
| `account.rs` | Device enrolment and credential issuance |
| `quic.rs` | QUIC and HTTP/3 transport |
| `masque.rs` | CONNECT-IP encapsulation |
| `wireguard.rs` | Noise handshake and WireGuard transport |
| `netstack.rs` | TUN-level packet bridge |

**C — packet processing**

`badvpn tun2socks` with `lwIP` terminates TCP in userspace; a companion datagram bridge shuttles UDP and QUIC flows across loopback.

---

## Transports

### MASQUE over HTTP/3

`CONNECT-IP` over QUIC, built on [quiche](https://github.com/cloudflare/quiche). On the wire this is indistinguishable from an ordinary HTTPS session, which is the entire point: there is no custom protocol fingerprint for a DPI box to key on.

Four things are worth saying about building it, without saying how:

- The pseudo-header value the edge actually accepts is **not** the one registered in the standard. The registered value is refused outright. Finding the variant that works meant bisecting header sets against a live edge, and it is not documented anywhere public.
- **HTTP/2 is not viable for this, at all.** The h2 path never offers the capability the transport depends on, so the negotiation dies before it begins. HTTP/3 is the only route. An HTTP/2 fallback here isn't a degraded mode, it's dead code.
- The seed gateway order is measured, not alphabetical. Most published addresses refuse the handshake; only a small minority will carry traffic, and that ranking is compiled into the build rather than discovered at runtime.
- The gateway you must use comes from one particular enrolment response — and there is a second response that looks equally authoritative and is wrong. Using the wrong one gets you a clean handshake into a gateway that will never carry your packets, which is a genuinely difficult failure to read from logs.

A short, fixed startup budget governs the whole sequence. A gateway that answers once and then goes quiet is not slow, it is stuck; reconnecting beats waiting, and the client does not wait.

### WireGuard

Direct transport with a full Noise handshake, for networks that haven't closed UDP. Where it works it's the fastest option available, and it's tried accordingly.

One hard-won rule governs this path: the socket that passed validation is the socket that carries traffic. Validating a tunnel and then rebuilding it is not equivalent, because a carrier can admit one flow and drop the next one that looks identical. The client no longer does that, and this is what separates a real WireGuard connection from one that merely handshakes.

### WARP-on-WARP

A WireGuard tunnel nested inside another WireGuard tunnel. Useful when the outer path is reachable but the inner endpoint isn't — which is a real situation on some carriers, and cheap to support once the WireGuard transport exists.

### Psiphon, and the three-rung ladder

Psiphon is driven through a three-rung ladder ordered by **measured time-to-connect on a hostile carrier**. That ordering is not the one Psiphon's own defaults would give you, and the difference is not marginal.

The reason is a measurement, and it is the part worth understanding even without the specifics. On the worst carrier tested, every direct dial fails **at the TCP layer**. No RST, no TLS alert, no handshake failure — the packets simply never arrive, because the operator has null-routed the relevant server addresses. Any strategy that presents a blockable server address is therefore dead on arrival, no matter how much budget you give it. Only a small fraction of the vendor's embedded server list supports the class of strategy that survives this, so the default ordering spends its entire budget dialling addresses that will never answer.

The ladder is arranged accordingly, each rung has its own time budget, and the rung that wins is remembered per SIM so that each device starts from whatever actually works on its own network. The rung strategies, their order and their budgets are intentionally left undocumented.

---

## Engineering notes that matter

**The routing loop.** The tunnel process has to stay outside its own tunnel, or its traffic re-enters the TUN and loops. The app's own package is excluded from the interface it creates. This one presents as a mysterious total stall rather than an error, so it's worth knowing about before you go looking for it in the transport code.

**UDP and QUIC.** lwIP terminates TCP only. Datagrams cross a separate userspace bridge with a bounded connection ceiling. Skip this and QUIC, online gaming and most voice calls break while TCP browsing looks fine — a failure mode that is easy to misdiagnose as a slow tunnel.

**MTU.** Pinned. The value was chosen by measurement: smaller settings fragmented packets and cost real throughput on the MASQUE path.

**SOCKS port.** A fixed loopback port, not configurable. In VPN mode nothing external binds it, so exposing a setting would only have created a way to break the app.

**Pre-tunnel packet backlog.** Android brings the TUN up before a tunnel exists, so device traffic queues behind it for several seconds. The old behaviour flushed that entire backlog into a brand-new connection the moment the stream opened, while the congestion window was still at its initial value — and the handshake response then had to compete with the flood for window space, and starved. Those packets are now dropped until the tunnel is confirmed, and the count is reported in the log. This was the single largest connect-latency win in the project.

**Identity rejection.** Only genuine authentication failures invalidate an enrolment. A malformed-request status means exactly that and nothing more. Conflating the two threw away perfectly good enrolments and triggered pointless re-registration.

**Honest connection state.** The interface does not trust a handshake. After a transport reports success the client watches the byte counters coming from inside the packet bridge, and if nothing has actually moved within a short window the dial degrades and says so. A carrier can fake a handshake; it cannot fake payload crossing the tunnel.

**Addressing.** The TUN sits on a private range with DNS forced to public resolvers and carrier DNS excluded.

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

No credentials, keys or tokens are stored in this repository. Device credentials are issued and stored on the handset at runtime.

Requests for the specific connection parameters, gateway rankings or ladder configuration will not be answered, in issues or anywhere else. Publishing them shortens the life of the thing they unblock, for every user of it.

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
