# SHARD rewrite — exact parity with reference implementation

> **For Hermes:** Use subagent-driven-development to implement this plan task-by-task.

**Goal:** SHARD on MSN behaves exactly like reference app on same subscription, same carrier, same moment.

**Architecture:** Replace SHARD stack with ported reference stack (fmt parsers -> profile model -> outbound builder -> xray-core fork -> delay measurement), isolated on branch `shard-rewrite`, no reference name in code/comments, build only on GitHub Actions (no release).

**Tech Stack:** Kotlin, Go (xray-core fork aa7886b51c14), Gradle, GitHub Actions

---

## Context

- Current SHARD (master 3.0.35) diverges: custom ShardConfigs.parse + outbound + probe, ECH udp->https rewrite, fm-first diversify, 5s/12s race, cp.cloudflare.com:80. Log: 36x read timeout, zero ECH lines, FM nodes that answer 101 on VPS still timeout on IR carrier.
- Reference (PattNG) on same sub at same time connects. Verified: same FM nodes exist in both pools, WS upgrade to 188.114.97.6 succeeds on VPS, so divergence is in libxray version + outbound building + probe target, not node pool freshness.
- Both projects use patterniha/xray-core fork, but MSN pins v26.8.28 while reference pins aa7886b51c14 (2026-10-08). Reference's AndroidLibXrayLite go.mod: `xtls/xray-core v1.260327.1 -> patterniha/xray-core v0.0.0-20261008141949-aa7886b51c14`.

## Plan

### Phase 0 — Branch & hygiene

**Objective:** Isolate work, avoid polluting master.
- Branch `shard-rewrite` from `e52313f` (already created).
- .hermes/plans/ committed to branch.
- Keep `master` untouched until parity verified on device.

**Files:** `git checkout -b shard-rewrite` (done), `.hermes/plans/...`

### Phase 1 — Xray binary parity

**Objective:** Same fork commit, same build flags as reference, so finalmask/cipherSuites/ech behave identically.
- Update `.github/workflows/xray-binary.yml` clone branch `v26.8.28` -> commit-pinned `aa7886b51c14` (or current reference go.mod replace commit). Verify three guards: `finalmask/fragment/conn.go`, `CipherSuites` in `infra/conf/transport_security.go`, `finalmask` key in `infra/conf/transport_internet.go`.
- Go version 1.27 to match reference go.mod (currently 1.26). Keep flags: `-buildmode=pie`, `max-page-size=16384`, `-checklinkname=0`, `CGO_ENABLED=1`, NDK 26.3.11579264.
- Trigger workflow_dispatch, verify artifact libxray.so size ~34M, push `app/src/main/jniLibs/*/libxray.so` placeholder via workflow artifact pin (not committed binary). If workflow unchanged, next APK build will fetch via `build.yml` pin; document required run id.

**Files:**
- Modify: `.github/workflows/xray-binary.yml:49-65`
- Verify: `AndroidLibXrayLite/go.mod` reference pinned commit
- Test: `gh run list --limit 3` after push, `gh run view <id> --json conclusion`

### Phase 2 — Subscription decode & fmt parsers

**Objective:** Byte-identical parse of subscription body to ProfileItem list.
- Add `app/src/main/java/com/msnguard/vpn/shard/ProfileItem.kt` — port of `dto/entities/ProfileItem.kt` (238 lines, strip aether/masque fields not needed for SHARD, keep vless/trojan/shadowsocks/wireguard/hysteria2 fields; include remarks/server/serverPort/password/method/flow/network/host/path/seed/mtu/security/sni/alpn/fingerPrint/cipherSuites/echConfigList/echOutbound/insecure etc). No reference name.
- Add `app/src/main/java/com/msnguard/vpn/shard/FmtBase.kt` (181 lines), `VlessFmt.kt` (47), `TrojanFmt.kt` (51), `ShadowsocksFmt.kt`, `SocksFmt.kt`, `WireguardFmt.kt`, `Utils.kt` decode helpers, `EConfigType.kt`/`NetworkType.kt` enums stripped to SHARD-needed values. Use `URI(Utils.fixIllegalUrl(str))` and `Utils.decode/tryDecodeBase64` exactly.
- Add `TlsSettingsCheck.kt` — port of `core/TlsSettingsCheck.kt` (fixImportedAlpn: ws/httpupgrade with alpn != http/1.1 -> http/1.1, cipherSuites requires unsafe).
- Replace `ShardConfigs.parse()` internals to delegate to `Utils.decode` twice then `AngConfigStyle.parseBatchConfig` loop (distinct().reversed(), V2rayNFmt branch, `fixImportedAlpn` per config). Keep `decodeIfBase64` behavior but match reference: try standard then URL_SAFE, with trimmed `=` retry (Utils.tryDecodeBase64). Preserve existing `ShardNode` for backward compat or map ProfileItem -> ShardNode for health/edges code until Phase 3.

**Files:**
- Create: `app/src/main/java/com/msnguard/vpn/shard/ProfileItem.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/FmtBase.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/VlessFmt.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/TrojanFmt.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/ShadowsocksFmt.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/SocksFmt.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/Hysteria2Fmt.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/WireguardFmt.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/TlsSettingsCheck.kt`
- Create: `app/src/main/java/com/msnguard/vpn/shard/Utils.kt`
- Modify: `app/src/main/java/com/msnguard/vpn/ShardConfigs.kt:254-430` (parse path)

**Validation:** Unit parse of `remote/shard-nodes.txt` 263 lines -> ~75 fm +75 ech +75 bare raw, parsed ~118 after dedupe, same count as before but alpn normalized like reference.

### Phase 3 — Outbound builder parity

**Objective:** Same JSON xray sees as reference for identical ProfileItem.
- Port `CoreOutboundBuilder.populateTlsSettings` (echConfigList, cipherSuites, fingerprint, alpn via `alpnProtocols`, insecure gating `insecure==true && pinnedCA256 empty`), `populateTransportSettings` (WS: host/path, XHTTP: host/path/mode/extra, TCP header, KCP, gRPC), `finalmask` via `JsonUtil.parseString(finalMask)` stashed as `Any` then Gson serialized (keep MSN's `JSONObject(node.finalMask)` but verify key names `lengths/delays` plural preserved).
- Replace `ShardConfigs.outbound()` to build via ported builder: create `V2rayConfig` style `OutboundBean` then serialize via same Gson path, or keep JSONObject path but mirror reference field decisions (e.g., echSocketSettings dialerProxy only when tag==proxy, allowInsecure derived from insecure && pinned empty).
- Remove ad-hoc `ech udp->https` rewrite (reference stores verbatim `cloudflare-ech.com+udp://1.1.1.1` and lets xray's `QueryRecord` do UDP; if IR carrier blocks UDP, reference also fails — parity is correct, not masking).
- Keep `dohOutbound`/`smartSplit` untouched.

**Files:**
- Modify: `app/src/main/java/com/msnguard/vpn/ShardConfigs.kt:454-630` (outbound)
- Create: `app/src/main/java/com/msnguard/vpn/shard/CoreOutboundBuilder.kt` (port)
- Modify: `app/src/main/java/com/msnguard/vpn/ShardConfigs.kt:727-810` (probeConfig routing keeps per-inboundTag wiring)

**Validation:** Render probeConfig for first FM node from `remote/shard-nodes.txt` and diff against reference's `getV2rayConfigForTest` JSON (keys `finalmask`, `tlsSettings`).

### Phase 4 — Probe & selection parity

**Objective:** Same liveness definition as reference.
- Reference delay URL: `https://www.gstatic.com/generate_204` (AppConfig.DELAY_TEST_URL), port 443 TLS inside tunnel, observatory leastPing. MSN currently uses `cp.cloudflare.com:80` plaintext (3 targets). Replace or add 443 target: keep ShardProbe ladder but change first target to `www.gstatic.com:443` TLS, or port reference's real-delay harness (buildUnifiedConfig + measure via libxray's test port 1824).
- Simplest parity: change `ShardProbe.TARGETS` to single `www.gstatic.com /generate_204 443` with TLS (requires SOCKS CONNECT then TLS ClientHello). If keeping plaintext probe, explain IR carrier blocks 80 differently — but parity says 443 like reference.
- Update `ShardManager.RACE_BUDGET_MS`/`PROBE_TIMEOUT_MS` to reference `OBSERVATORY_LEAST_PING_INTERVAL` style (reference uses 5s default per probe, 12s race budget already matches; keep but document).
- Update `diversify` comment (currently says fragment costs ~1s, stale) to match actual FM cost (~110ms), and keep fm-first (reference ranks by measured delay, not fm/ech).

**Files:**
- Modify: `app/src/main/java/com/msnguard/vpn/ShardProbe.kt:35-60` (TARGETS)
- Modify: `app/src/main/java/com/msnguard/vpn/ShardManager.kt:96-120` (timeouts, comments)
- Modify: `app/src/main/java/com/msnguard/vpn/ShardManager.kt:668-707` (diversify comment)

**Validation:** On IR device, `adb logcat | grep M7` shows `racing 12 nodes — budget 12000ms, per-node 5000ms` and probe now hits 443; compare success rate vs reference app installed side-by-side.

### Phase 5 — Subscription refresh & edges

**Objective:** Same refresh cadence / dedupe as reference.
- `ShardSubscription` already does ETag + 6h MIN_INTERVAL vs reference's WorkManager 24h. Keep but align `SUBSCRIPTION_URL` fetch to handle base64 sub (already via Utils.decode). No change needed except ensure `rawLineCount`/`parsed` logging stays.
- `ShardEdges`/`RemotePolicy.edges` stays; reference has no edge expansion — MSN's 708 pool is extra. Keep but verify isCloudflareAddress guard matches reference's edge list handling (no reference edges — so extra paths only help, not diverge). Document that 708 vs 225 is intentional (edge fan-out) and proven to not break parity (extra candidates just race more paths).

**Files:**
- Verify: `app/src/main/java/com/msnguard/vpn/ShardSubscription.kt`
- Verify: `app/src/main/java/com/msnguard/vpn/ShardEdges.kt`

### Phase 6 — Cleanup of 3.0.30-3.0.35 patches

**Objective:** Remove drift that was masking root cause.
- Revert `MTMVPNfp` inline replace if `FmtBase.getQueryParam` already handles via URI decoding (reference's `getQueryParam` splits on `&` after decode, so `MTMVPNfp=` bug is upstream raw bug — keep but gate on raw `path` param value, not global replace, to match reference which does not have this fix).
- Remove `ech udp->https` rewrite (port 3/16).
- Keep `alpn normalize` only via `TlsSettingsCheck.fixImportedAlpn` (remove ad-hoc `alpn = run` in parseOne).

**Files:**
- Modify: `app/src/main/java/com/msnguard/vpn/ShardConfigs.kt:380-413`

### Phase 7 — Build & verification

**Objective:** Prove parity, no regression, no publish.
- Bump `app/build.gradle.kts` versionCode 336 -> `3.1.0-alpha01` (or keep 3.0.36 for branch, document `shard-rewrite` is not master).
- Push branch, watch `gh run list`, `gh run view <id> --json conclusion`, `gh run download`.
- `send_apk_mohsen.sh` for arm64/armeabi (no universal).
- Manual IR test: install alongside reference, same sub, compare `M7` logs side-by-side. Success = same winner node within same 12s.
- Disk cleanup: `rm -rf /tmp/apks_*`, `~/.gradle/caches` trim, `df -h` <=80%.
- Notify via `notify_mohsen.sh`.

**Files:**
- Modify: `app/build.gradle.kts`
- CI: `.github/workflows/build.yml` (no change, build only)

---

## Risks

- xray pin bump may require Go 1.27 NDK rebuild; workflow may fail on first try (fix go-version, cache).
- Fmt port must handle `URI(Utils.fixIllegalUrl(str))` — Utils.fixIllegalUrl not yet ported; verify.
- Probe 443 TLS needs SOCKS CONNECT then TLS — ShardProbe currently does plaintext HTTP; switching to TLS requires new probe harness (use reference's `CoreConfigManager.getV2rayConfigForTest` + libxray test port if plaintext probe insufficient).
- Edge expansion 708 vs reference 225: not a bug, but if max RACE_SLICES 3 only tests 36 of 708, leastPing would have tested all via observatory. Consider raising slices or keeping health-ranked diversify.

## Open Questions

- Does reference's real-delay use `https://www.gstatic.com/generate_204` over TLS 443 inside each outbound, and does that require `alpn h2`? MSN's Smart Split puts `alpn h2` for xhttp none — verify.
- Is `encryption=none` param required for VLESS parse (reference reads `method` from `encryption`)? MSN hardcodes none — keep.
