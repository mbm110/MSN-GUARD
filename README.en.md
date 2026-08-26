<div align="center">

<img src="docs/logo.png" width="160" alt="MSN-GUARD">

# MSN-GUARD

**Device-wide tunnelling for censored networks — five transports, Rust core, native Android client**

[![Build](https://img.shields.io/github/actions/workflow/status/mbm110/MSN-GUARD/build.yml?branch=master&style=for-the-badge&label=build)](https://github.com/mbm110/MSN-GUARD/actions)
[![Version](https://img.shields.io/badge/version-1.5.0-5CE68F?style=for-the-badge)](https://github.com/mbm110/MSN-GUARD/releases)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3A4FB0?style=for-the-badge&logo=android&logoColor=white)](https://github.com/mbm110/MSN-GUARD)
[![License](https://img.shields.io/badge/license-AGPL--3.0-6c5ce7?style=for-the-badge)](LICENSE)
[![Transports](https://img.shields.io/badge/transports-MASQUE%20%C2%B7%20WireGuard%20%C2%B7%20WARP%C2%B7WARP%20%C2%B7%20Psiphon%20%C2%B7%20Tor-1f6f4a?style=for-the-badge)](#transports)

**English** · [فارسی](README.md)

</div>

---

## What this is

MSN-GUARD is a native Android VPN client that moves every packet leaving the device through one of five independent transports. That word *native* is doing real work here. Most tools in this space are proxies: they hand you a local SOCKS port, and whatever bothers to read the system proxy setting — usually just a browser — gets protected. Everything else leaks. MSN-GUARD binds Android's own `VpnService`, stands up a TUN interface, and takes ownership of the whole routing table. Every TCP stream, every UDP datagram, every QUIC flow, from every installed app, goes through the tunnel whether that app knows about proxies or not.

The codebase splits cleanly in two. A **Rust network core** implements the transports and negotiates with upstream gateways. A **Kotlin layer** owns the Android VPN lifecycle, the interface, and platform plumbing. The last two transports — Psiphon and Tor — bring their own cores and attach to the same TUN through a local SOCKS listener. There is no relay server of ours in the middle — the handset speaks directly to the upstream gateway.

The thing that separates this from a generic VPN app: it was built for Iranian mobile networks, and essentially every protocol decision in it came out of **measurement against real hostile carriers**, not from a spec document and not from a guess. Where the measured answer contradicted the documented one, the measurement won — repeatedly, and in ways that were not obvious in advance.

> **A note on what this document does not say.** The connection strategy — handshake parameters, gateway selection, ladder ordering, timing budgets, the specific values that make a session survive an active filter — is the result of a long and expensive measurement campaign against live carriers. Those details are deliberately not published here. This README describes *what* the client does and *why* it is shaped the way it is; it does not hand over a working recipe. Circumvention advantages have a shelf life measured by how quickly they can be copied, and the useful ones stay unwritten.

---

## Feature summary

| | |
|---|---|
| Device-wide tunnel | `VpnService` + TUN; every app covered with zero per-app configuration |
| Five transports | MASQUE over HTTP/3, WireGuard, WARP-on-WARP, Psiphon, Tor |
| Tor and Tor-over-WARP | The Tor network on its own, or nested inside MASQUE where Tor itself is blocked |
| Exit country picker | 27 countries for Tor, 25 for Psiphon, each shown with its real relay or server count |
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
| `TorManager` | tor startup, torrc generation, mode ladder and bridge selection |
| `TorSocksFront` | SOCKS front-end for Tor; where DNS is steered to Tor's own DNSPort |

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

An exit country picker is available here too: the 25 countries present in Psiphon's embedded server list, each shown with how many servers it holds. The whole list totals 430 servers, with the US and Canada holding 65 each.

### Tor, and Tor-over-WARP

Version 1.5.0 added the Tor network as the fifth transport. There is no Orbot dependency and no companion app: `tor 0.4.9.11` is cross-compiled for Android and shipped inside the APK alongside `lyrebird 0.8.1`, which serves obfs4, meek_lite and snowflake from one binary. Three layers of Tor encryption therefore apply to the whole device, not just to a browser.

Four connection modes are exposed, plus an automatic one that walks them:

| Mode | What it does | Where it earns its place |
|---|---|---|
| Auto | Walks the ladder from the top until something connects | The default, and in practice the fastest |
| Direct | No bridge, straight into the Tor network | Networks that have not blocked Tor |
| obfs4 | Bridge that disguises Tor's traffic shape | Tor blocked, bridges not yet scanned |
| Meek | Rides a CDN | Hardest to block, and the slowest |
| Snowflake | Volunteer WebRTC proxies | Last resort when nothing else answered |

The automatic order is Direct, Meek, obfs4, Snowflake. Direct goes first because where it works it is both the quickest to connect and the quickest to use. Meek comes second because it connects almost everywhere — on the wire it is HTTPS to a CDN — but every cell pays an HTTP round trip. Public obfs4 bridges are the first thing a serious censor enumerates, and Snowflake is the highest-variance rung of the four because it has to find a volunteer proxy through a broker before anything happens.

**Tor-over-WARP** nests Tor inside the MASQUE tunnel: WARP on the outside, Tor bootstrapping within it. This is for the case where the carrier has blocked reach to the Tor network itself — from the carrier's vantage point you have one HTTPS connection, and Tor begins where that connection ends.

Only Direct and Meek are allowed to chain, and that limit came from measurement rather than caution. Through a real SOCKS5 proxy on our own server, Direct reached 100% in 12–15 seconds and Meek in 36 seconds with all 75 CDN dials crossing the proxy. obfs4, however, stalled at 10% on one run and 85% on the next — same bridge, back to back, with no proxy involved at all. So it is not excluded because the proxy was shown to hurt it; it is excluded because it was never shown to be dependable on these bridges in the first place, which is worse. Putting a rung that unpredictable inside a tunnel that already costs a second handshake means any failure becomes unattributable between the two layers. Snowflake has its own broker and WebRTC dials, which a SOCKS5 `CONNECT` cannot carry. Both remain fully available unchained.

**The Tor exit country picker** lists 27 countries, each annotated with its real running-exit count, because that number is the honest predictor of whether the request will be honoured. The counts come from the Tor Project's own onionoo service: 3275 running exits across 52 countries, with the top three holding more than two thirds of them. The cut is at five exits — a country with one or two exits produces a control that mostly does nothing, and a control that mostly does nothing is worse than no control.

`StrictNodes 0` is set deliberately, which makes the choice a preference rather than a guarantee: when Tor cannot build a working circuit in that country it goes elsewhere, and the interface says so instead of pretending otherwise. `StrictNodes 1` turns a thin country into a dead end — `{gr}` under that setting sat at 45% for 42 minutes in testing and never connected.

Worth saying plainly: Auto is almost always faster than pinning a country, because Tor stays free to take the nearest healthy circuit.

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

**DNS takes a different route under Tor.** The other four transports force public resolvers; the Tor path lists only Tor's own `DNSPort` and no public address at all. That difference is deliberate. A public resolver in that list would send every app's lookups outside the circuit, in the clear, to Cloudflare — telling anyone watching exactly what a user who just enabled Tor is trying to reach. Tor does not need a public resolver to bootstrap either: bridges are dialled by IP, and the app's own package sits outside the TUN.

**The UDP table ceiling on the Tor path.** Under Tor only DNS crosses the datagram bridge; the rest of UDP — QUIC, NTP, STUN — is dropped there. Tor does not carry UDP at all, so those packets were never going to arrive; the problem was that handing them to the bridge burned one of its 256 table slots per flow, permanently, until the table filled and DNS replies started landing on recycled slots and name resolution failed mid-session. Apps fall back to TCP, which is what they already do.

---

## Install

Grab the latest APK from [Releases](https://github.com/mbm110/MSN-GUARD/releases) or from the [Actions](https://github.com/mbm110/MSN-GUARD/actions) artifacts. The current version is `1.5.0`, and the app checks that same Releases page for updates.

| Device architecture | File |
|---|---|
| ARM 64-bit — most current handsets | `MSN-GUARD-v1.5.0-arm64-v8a.apk` |
| ARM 32-bit — older devices | `MSN-GUARD-v1.5.0-armeabi-v7a.apk` |

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
| `app/src/main/jniLibs/` | tor and lyrebird binaries, built in CI and committed here |
| `tools/build-tor.sh` | Cross-compiles tor for Android |
| `tools/filter-geoip.py` | Shrinks the GeoIP database to the countries the app actually offers |
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
- [Tor](https://gitweb.torproject.org/tor.git) — BSD-3-Clause
- [lyrebird](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird) — obfs4, meek and snowflake transports, BSD-2-Clause

---

<div align="center">

**Built and maintained by [mbm110](https://github.com/mbm110)**

</div>
