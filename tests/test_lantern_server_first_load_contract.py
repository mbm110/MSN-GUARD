#!/usr/bin/env python3
"""Contract: the Lantern Server picker loads its list on FIRST entry.

Field report (3.2.47→3.2.48): opening Settings → Lantern → Server showed only
"Automatic" and the servers appeared only after backing out one level and
re-entering. Root cause part 1 (3.2.48): the first offline open boots the
list-only sidecar, whose control socket answers immediately while Radiance's
first config fetch can outlast the picker's 5s snapshot read. Root cause part 2
(3.2.49): /servers answers NON-NULL with an EMPTY array the moment the control
socket is up — the waiter returned on that first empty read and the sheet still
opened with "Automatic" only.

Also verified live (scratch probes, 3.2.49): Lantern geo-serves its free pool
by client country — IR is PINNED to a dedicated four-track pool (3x Frankfurt +
1x Amsterdam, "-ir-free-" tags) while every other country draws a random ~6-
location sample from the GLOBAL pool (Milan, Ashburn, Cardiff, ...). The
official app's richer list is a global draw, and MSN showed the same early on.
So the sidecar runs with RADIANCE_COUNTRY set (LanternEngine spawn → env →
x-lantern-client-country): every fetch draws from the global pool, and the
picker forces a re-roll on offline opens (LanternEngine.forceConfigRefresh →
POST /update-config → radiance UpdateConfig) so the open sheet REBUILDS in
place with the new draw — no back-out needed.
"""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
CORE = ROOT / "core/lanternbridge"
UI = (APP / "MainActivity.kt").read_text()
ENGINE = (APP / "LanternEngine.kt").read_text()
STRINGS = (APP / "Strings.kt").read_text()
RUSSIAN = (APP / "RussianStrings.kt").read_text()
BRIDGE = (CORE / "bridge.go").read_text()
SIDECAR = (CORE / "cmd/lanternsidecar/main.go").read_text()


class LanternServerPickerFirstLoadContract(unittest.TestCase):
    def test_first_open_waits_for_the_config_fetch(self):
        # loadLanternServers: after the list-only boot, an empty 5s snapshot
        # must hand off to the bounded waiter instead of opening the sheet
        # with "Automatic" only.
        self.assertIn("snapshot = LanternEngine.serversSnapshot(timeoutMs = 5_000)", UI)
        self.assertIn("if (snapshot == null) {", UI)
        self.assertIn("snapshot = awaitLanternServerConfig()", UI)

    def test_the_waiter_gates_on_a_non_empty_list_not_a_non_null_answer(self):
        # 3.2.49 root cause: /servers answers non-null with an EMPTY array the
        # moment the sidecar control socket is up; the old loop returned on
        # that first empty read. The gate must be a NON-EMPTY servers array,
        # and the bound is 60s (the raw Iranian link regularly outlasts the
        # old 25s).
        self.assertIn("private fun awaitLanternServerConfig(): JSONObject?", UI)
        self.assertIn("System.currentTimeMillis() + 60_000L", UI)
        self.assertIn("Thread.sleep(1_500L)", UI)
        self.assertIn("serversSnapshot(timeoutMs = 3_000)", UI)
        self.assertIn('(candidate.optJSONArray("servers")?.length() ?: 0) > 0', UI)
        self.assertIn("runOnUiThread { loading.get()?.dismiss() }", UI)
        # The dismiss is posted after the show from the same worker thread, so
        # ordering is guaranteed — the invariant the AtomicReference relies on.
        show_idx = UI.index("dialog.show()")
        dismiss_post_idx = UI.index("runOnUiThread { loading.get()?.dismiss() }")
        self.assertLess(show_idx, dismiss_post_idx)

    def test_offline_open_forces_a_fresh_config_draw(self):
        # Lantern hands each config fetch a random ~6-location draw from its
        # global free pool; the offline picker must force the refetch so the
        # list is a fresh draw instead of a stale cache, and the open sheet
        # must rebuild in place when the tag set changes — the whole
        # field-report complaint.
        self.assertIn("fun forceConfigRefresh(): String?", ENGINE)
        self.assertIn(
            'request("POST", "/update-config", JSONObject(), timeoutMs = 120_000)', ENGINE
        )
        self.assertIn("LanternEngine.forceConfigRefresh()", UI)
        self.assertIn("if (sidecarUp && !LanternEngine.isRunning) {", UI)
        self.assertIn("before != afterTags", UI)
        self.assertIn("runOnUiThread { reopenLanternServerSheetIfOpen() }", UI)

    def test_the_sidecar_draws_from_the_global_pool(self):
        # IR clients are pinned to Lantern's four-track "-ir-free-" pool
        # (3x Frankfurt + 1x Amsterdam) — the exact list the field report
        # complained about, while the official app shows a global draw. The
        # sidecar therefore presents a non-IR country identity
        # (RADIANCE_COUNTRY → x-lantern-client-country) so every config fetch
        # (boot, forced refresh, poll) draws from the global pool; one
        # ProcessBuilder line, trivially revertible.
        self.assertIn('builder.environment()["RADIANCE_COUNTRY"] = LANTERN_CONFIG_COUNTRY', ENGINE)
        self.assertIn('private const val LANTERN_CONFIG_COUNTRY = "TR"', ENGINE)

    def test_the_sidecar_exposes_the_update_config_route(self):
        # Go side: radiance's UpdateConfig() forced through the control socket.
        self.assertIn("func UpdateConfig() error {", BRIDGE)
        self.assertIn("b.UpdateConfig()", BRIDGE)
        self.assertIn('request.Path == "/update-config"', SIDECAR)

    def test_the_open_sheet_is_rebuilt_in_place(self):
        # The sheet dialog is tracked so a refresh can rebuild it without the
        # user backing out; a dismiss that happens only for the rebuild is not
        # treated as the user closing the picker.
        self.assertIn(
            "private fun openLanternServerSheet(servers: List<LanternServerOption>)", UI
        )
        self.assertIn("private fun reopenLanternServerSheetIfOpen()", UI)
        self.assertIn("@Volatile private var lanternServerSheet: Dialog? = null", UI)
        self.assertIn("onShown = { lanternServerSheet = it }", UI)
        self.assertIn("private var lanternSheetReopening = false", UI)
        # showChoiceSheet gained the onShown hook (no other sheet changes).
        self.assertIn("onShown: ((Dialog) -> Unit)? = null,", UI)
        self.assertIn("onShown?.invoke(dialog)", UI)

    def test_progress_caption_exists_in_every_locale_column(self):
        key = "Fetching Lantern servers…"
        self.assertIn(f'"{key}" to Triple("{key}",', STRINGS)
        self.assertIn(f'"{key}" to "', RUSSIAN)

    def test_the_empty_state_fallback_is_unchanged(self):
        # On timeout the waiter returns null and the picker still opens with
        # its empty-state text — the sheet's behavior for a dead network is
        # byte-identical to the pre-fix fallback.
        self.assertIn('"Connect with Lantern once, then pick a server here"', STRINGS)
        self.assertIn("subtitle = if (servers.isEmpty()) {", UI)


if __name__ == "__main__":
    unittest.main()
