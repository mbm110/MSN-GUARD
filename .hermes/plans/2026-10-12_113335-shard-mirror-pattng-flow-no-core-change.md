# SHARD: mirror the PattNG sub→config→peer flow (no Xray core change)

> **For Hermes:** Use subagent-driven-development to implement this plan task-by-task.

**Goal:** Make SHARD connect reliably by porting PattNG's subscription→parse→peer flow verbatim into MSN's SHARD, without touching the Xray core (binary, `ShardSocksFront`, `ShardProbe` probes).

**Architecture:** Keep the mirror+subscription+race skeleton. Fix every place where MSN diverges from PattNG's proven flow for the same input (Free-Configs `vless://…` with `fm/cs/fp/ech`).

**Tech Stack:** Kotlin, `ShardSubscription` / `ShardConfigs` / `ShardManager`, `VlessFmt`-style parsing reference from PattNG; mirror sync workflow `remote/shard-nodes.txt`.

---

## Ground truth from this repo (no guesses)

- Subs source: `.github/workflows/shard-nodes-sync.yml` fetches `https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt` every 4 h into `remote/shard-nodes.txt`. App's live URL is `https://raw.githubusercontent.com/mbm110/MSN-GUARD/master/remote/shard-nodes.txt` ( `ShardSubscription.SUBSCRIPTION_URL` ). Cache is `shard-configs.txt` + ETag (`If-None-Match`); seed fallback is `assets/shard-seed.txt`.
- Local mirror now is "80 healthy nodes × 3 variants = 240 configs" ( `remote/shard-nodes.txt:39-50` — same credential/host/addr `188.114.97.6:443` etc, variants: `unsafe+fm`, `chrome+ech`, `chrome+fm+ech`, plus `grpc/anytls`-filtered by `SUPPORTED`).
- Parsing is in `ShardConfigs.kt` (`fun parse(...)` / `parseOne`), edges are `ShardEdges.kt` (fan-out over RemotePolicy edges), race is `ShardManager.kt` ( `RACE_WIDTH=12`, `PROBE_TIMEOUT_MS=5000`, `RACE_BUDGET_MS=12000`, `MAX_RACE_SLICES=3`).
- Failure mode on 3.0.30 repro is **before any Xray dial**: `M7 ph found nothing in 20000ms — tried 12 nd — e.g. read timeout after 8000ms` × every slice → no nd answered. That's a *probe or candidate* problem, not a transport fate problem. User also reports 3.0.30 did NOT use a DoH/ECH change — `cloudflare-ech.com+udp://1.1.1.1` is known-good in IR and must not be rewritten.
- `ShardPusher` (if present) is the device that appends `#profile-*` / `configs.txt` headers and enforces `FILTER_NODES` with 5 IPs — if it now emits `echCl=…` or malformed params, that's a regression to hunt.
- PattNG has no SHARD. The reference to steal is its generic sub decode + fmt parsing ( `AngConfigManager.parseBatchSubscription/parseBatchConfig/parseConfig`, `VlessFmt`, base64 vs plain-text branching ).

---

## Analysis requests (read-only before code)

- Audit every SHARD settings button (Node List + any ancillary buttons in that screen) and map which code path each triggers — verify each is wired to the same `ShardSubscription.refreshIfDue / cachedCount / ShardHealth` flow the connect uses. If a button only updates a subtitle without actually refreshing the cache, that's a bug; if it bypasses ETag, that's intentional but document it.
- From `ShardConfigs.parseOne`, enumerate every `params["…"]` accepted, which are required vs optional, and what dropping vs carrying verbatim (`fm`, `cs`, `fp`, `ech`, `insecure`, `allowInsecure`) does downstream. Cross-check against PattNG `VlessFmt.parse` / `TrojanFmt.parse` for the same query keys.
- From the mirror file and the pusher code, confirm the exact shape of a "5-IP" candidate: is it 5 lines per credential, 5 edges per node, or 5 literal addresses injected by the pusher? The race's counting (`ShardEdges.pathsPerNode`) must match reality.

---

## Plan

### Task 0 — Confirm the failure without touching the core

- Capture the next SHARD failure log on the regressed build (already have 3.0.30: `read timeout after 8000ms` on all 12, 3 slices → `no nd answered`). Reproduce once more on master ( `40c168c` ) to confirm whether the symptom persists after the Xray revert, or whether the 3.0.30 ECH/doh change was the only cause.
- Verify `remote/shard-nodes.txt` vs `shard-seed.txt` vs live fetch body are byte-identical shape (CRLF, BOM, empty lines).

### Task 1 — Make the decoder actually match PattNG for this sub

- PattNG branches: if the body is base64 (no newlines, decodes to `://`-containing text) decode first, else treat as plain lines. MSN must do the same. Currently MSN's `parse` assumes plain lines only — if the publisher ever flips to base64 (common for `sub`-style endpoints), MSN silently yields 0 nodes and the race has nothing to probe, which looks exactly like the observed `tried 12 nd — e.g. read timeout…` if the pool was truncated earlier.
- Port the tolerant line filter verbatim: skip `#profile-*` / empty lines, trim, drop only unparseable lines. Do not reject on unknown params — carry them as `extra` / `ShardNode` fields the same way PattNG carries.

### Task 2 — Fix param handling to be lossless (no silent mis-parse)

- Audit `parseQuery` / `decode` for `fm` (JSON with `{"tcp":[…]}`), `cs` (colon-joined list), `ech=cloudflare-ech.com+udp://1.1.1.1`, `alpn`, `fp`. One wrong `URLDecoder` pass or one case-fold on `host`/`sni` breaks an otherwise good config. PattNG keeps these verbatim after a single decode — MSN must too. The observed "all 12 timed out" is consistent with a params bug that makes every candidate carry a broken `host`/`sni`/`fp` and therefore never complete a TLS hello.
- Do not rewrite `ech` — user confirms `cloudflare-ech.com+udp://1.1.1.1` is the good value. Revert any DoH/ech resolver work from 3.0.30 and keep the param verbatim.

### Task 3 — Repair the candidate pool size/count

- The "5-IP" feature must be visible in `pathsPerNode` and in the pool actually raced. If `ShardPusher` now emits `echCl=…` or new fields, update the parser to carry them instead of rejecting the line. If the pusher is emitting base64, the Task 1 fix handles it. If it's emitting duplicate lines, `seen` dedupe is correct but must be on `node.key` (not raw line), as it already is.
- Fix `cachedPathCount` / settings subtitle computation to match `ShardEdges.expand` reality so QA is not misled about pool size.

### Task 4 — Make probes answer the question the race asks

- Do not touch probe targets ( `cp.cloudflare.com/generate_204` etc — `ShardProbe.RULE_HOSTS/RULE_PORTS` already match the routing rule). Verify the probe's SOCKS handshake (`ATYP=3` via `ShardSocksFront`) still reaches the node and isn't blocked by the same bad `sni`/`host` that breaks the browser path. If probes are the failure, the wire symptom is exactly `read timeout after 8000ms` on every nd.
- Keep `RACE_WIDTH=12 / PROBE_TIMEOUT_MS=5000` as-is unless a separate timeout bug is found; the current 36-path / ~36 s worst case is the shipped contract.

### Task 5 — Node List button semantics

- Spec user wrote: "when the user taps Node List, the config list should refresh, but only actually re-probe-and-bind to the best ping when they hit Connect." So: Node List = `ShardSubscription.refreshIfDue(force=true)` + update subtitle/count; no race, no `ShardManager.start`. Connect = refreshIfDue (capped by `MIN_INTERVAL_MS`) then `ShardManager.race` over the *already-expanded* pool using `ShardHealth` ranking. Verify the current screen does exactly that; if it races on Node List, stop it.

### Task 6 — Regression guard

- Add a unit/instrumentation test that feeds the exact 3 example `vless://…` URLs from the bug report through `ShardConfigs.parse` and asserts: count, `host`/`sni`/`fp`/`fm`/`ech` verbatim, and that `ShardConfigs.outbound` (or config render) emits the same outbound JSON PattNG would for the same input. This is the contract that prevents the next silent parse regression.

---

## Files likely to change

- `app/src/main/java/com/msnguard/vpn/ShardConfigs.kt` — decoder + query param handling.
- `app/src/main/java/com/msnguard/vpn/ShardSubscription.kt` — base64 branch, mirror vs live URL, force-refresh contract.
- `app/src/main/java/com/msnguard/vpn/ShardEdges.kt` — only if the 5-IP counting is wrong.
- `app/src/main/java/com/msnguard/vpn/MainActivity.kt` (or wherever the SHARD settings screen lives) — Node List wiring.
- `.github/workflows/shard-nodes-sync.yml` / `tools/shard-pusher/*` (if that dir exists) — only if the 5-IP emission is broken.

Do NOT touch:

- Xray binary / `ShardSocksFront.kt` / `ShardProbe.kt` probe targets / any Warp/WoW/WireGuard/Tor/Psiphon path.
- `ech` rewriting or DoH resolver work — reverted by `40c168c` and must stay reverted.

---

## Validation

- On-device: SHARD connects on Hamrah-e-Aval / Irancell without triggering a release; Node List updates the count; Connect picks the lowest-ping candidate from the fresh pool.
- In logs: `M7 racing 12 nd` followed by `M7 ph winner …` not `found nothing in 20000ms`, and no `read timeout after 8000ms` on every nd.
- No regression on already-working Warp/WoW/masque paths, same version string contract.

---

## Risks

- Base64 branch must be gated: decoding a plain `vless://` body as base64 corrupts it. Gate on "no `://` after trim and decodes to text containing `://`."
- The pusher's `echCl` field (visible in `remote/shard-nodes.txt:42`) — if the parser rejects unknown keys strictly, those lines are silently dropped; make it tolerant.
- Edge fan-out + `ShardHealth.rank` interaction: a bad host silently makes all expanded variants bad; fixing the host fixes all variants at once, which is why this is prioritized before any timeout tuning.
