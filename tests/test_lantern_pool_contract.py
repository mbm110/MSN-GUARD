#!/usr/bin/env python3
"""Contract: the Lantern server pool setting (3.3.7) is real, not cosmetic.

3.4.9: the pool is enforced CLIENT-SIDE. The server-track probe proved the
server draws the pool from the EXIT IP of the config fetch — the
x-lantern-client-country header and the locale are ignored — so the 3.4.8
header pin could not survive a mid-session refresh that left through the
tunnel (field log 3.4.8: the 17:18 refill swapped 5 dead global servers into
the auto group and the session died). RADIANCE_POOL=ir filters the server
list to the pinned '-ir-free-' pool inside the vendored Radiance
(vpn/hostaccess.go pinPoolIfRequested), on every load — boot and refresh
alike; global keeps the upstream rotating worldwide sample.

3.4.11 SR-REJECT (field log 3.4.10): the 3.4.9/3.4.10 filter was FAIL-OPEN.
On the 3.4.10 field network the probe returned ZERO ir-free servers on
EVERY fetch (two non-IR exits, repeated same-account fetches; the header,
the fa-IR locale and preferred_location=IR are all ignored), so the
default Iran setting filtered nothing and the device ran the worldwide
pool to its death. The pin is now fail-closed in three places: the draw is
rejected as a whole when it carries no ir-free member (updateServers keeps
the manager's held pool: the picker, the boot box options and the tunnel
stop rotating into the dead worldwide sample), buildOptions drops the
non-ir-free members at boot, and only an explicit "global" setting leaves
every draw unfiltered.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
CORE = (APP / "CoreConfig.kt").read_text()
ENGINE = (APP / "LanternEngine.kt").read_text()
UI = (APP / "MainActivity.kt").read_text()
STRINGS = (APP / "Strings.kt").read_text()
RUSSIAN = (APP / "RussianStrings.kt").read_text()
VENDORED = ROOT / "core/lanternbridge/third_party/radiance"
HOSTACCESS = (VENDORED / "vpn/hostaccess.go").read_text()
BOXOPTIONS = (VENDORED / "vpn/boxoptions.go").read_text()
BACKEND = (VENDORED / "backend/radiance.go").read_text()


class LanternPoolContract(unittest.TestCase):
    def test_the_pool_filter_is_real_in_the_vendored_radiance(self):
        # The filter must exist in the vendored Radiance — otherwise the
        # setting is cosmetic.
        self.assertIn('p != "iran" && p != "ir"', HOSTACCESS)
        self.assertIn('"-ir-free-"', HOSTACCESS)

    def test_the_filter_is_fail_closed(self):
        # 3.4.11 SR-REJECT: a draw with no ir-free members must be REJECTED
        # (an empty list), never passed through fail-open like 3.4.9/3.4.10
        # did.
        self.assertIn("if len(irOnly) == 0 {", HOSTACCESS)
        self.assertIn("return servers.ServerList{}", HOSTACCESS)
        # allowedServers must treat the rejected (nil) draw as empty rather
        # than crash or fall back to the unfiltered list.
        self.assertIn("if list = pinPoolIfRequested(list); list.Servers == nil {", HOSTACCESS)

    def test_the_manager_rejects_worldwide_draws_under_iran(self):
        # 3.4.11 SR-REJECT: the same draw must not refill the manager either
        # (updateServers) — that was the hole 3.4.9/3.4.10 left open: the
        # tunnel kept the previous list while the picker and the boot box
        # options still took the worldwide sample.
        self.assertIn("if vpn.IrPoolSelected() {", BACKEND)
        self.assertIn(
            'slog.Warn("RADIANCE_POOL=iran: draw had no ir-free servers; keeping the held pool",',
            BACKEND,
        )
        # Only Lantern servers are filtered; helpers never carry the marker.
        self.assertIn("srv.IsLantern && !lbA.IsHelperTag(srv.Tag) &&", BACKEND)

    def test_the_boot_box_options_pin_the_pool(self):
        # buildOptions must drop the non-ir-free members at boot too, or a
        # worldwide draw still starts the tunnel alongside the held pool.
        self.assertIn("if irPoolSelected() {", BOXOPTIONS)
        self.assertIn("isLanternOutboundIn(bOptions, o.Tag)", BOXOPTIONS)
        self.assertIn("isLanternOutboundIn(bOptions, e.Tag)", BOXOPTIONS)
        # The client-info injector's tag list must match what survives.
        self.assertIn("func isLanternOutboundIn(bOptions BoxOptions, tag string) bool {", BOXOPTIONS)
        self.assertIn("if vpn.IrPoolSelected() {", BACKEND)
        self.assertIn("if vpn.IrPoolSelected() {\n\t\t// MSN 3.4.11 SR-REJECT: the pin in buildOptions", BACKEND)

    def test_the_engine_sets_the_env_for_both_pools(self):
        # 3.4.9: the pool value flows straight into RADIANCE_POOL; iran
        # filters to the pinned IR pool, global leaves the sample unfiltered.
        self.assertIn('builder.environment()["RADIANCE_POOL"] = pool', ENGINE)
        self.assertIn("val pool = CoreConfig.lanternPool(context)", ENGINE)
        # The old 3.4.8 country header is gone: the probe proved the server
        # ignores it, so it must not linger as a second, conflicting knob.
        self.assertNotIn("RADIANCE_COUNTRY", ENGINE)
        # The filter key must match the stored setting value — 3.4.9 shipped
        # keyed on "ir" while the pref stores "iran" and never matched.
        self.assertIn('if (pool == "iran") "on" else "off"', ENGINE)

    def test_the_sidecar_log_pump_is_quiet_for_battery(self):
        # 3.4.10 battery report (40%/hot phone): the stdout pipe fed the app's
        # log pump every INFO line sing-box emitted, all session long. warn
        # keeps errors in-app and the pipe quiet.
        self.assertIn('builder.environment()["RADIANCE_LOG_LEVEL"] = "warn"', ENGINE)

    def test_the_engine_logs_the_live_choice_per_session(self):
        # Both selectors must be verifiable in the app log on every connect.
        self.assertIn('"Lantern: server pool=$pool', ENGINE)
        self.assertIn("DNS region=${CoreConfig.lanternDnsRegion(context)}", ENGINE)

    def test_the_pref_exists_with_iran_default(self):
        self.assertIn('const val LANTERN_POOL = "lantern_server_pool"', CORE)
        self.assertIn('getString(LANTERN_POOL, "iran")', CORE)

    def test_the_ui_offers_both_pools(self):
        self.assertIn('IRAN("Iran", "iran",', UI)
        self.assertIn('GLOBAL("Global", "global",', UI)
        self.assertIn("private fun chooseLanternPool(", UI)
        self.assertIn("CoreConfig.LANTERN_POOL, chosen.coreName", UI)
        # Falls back to IRAN for unknown stored values.
        self.assertIn("?: LanternPool.IRAN", UI)

    def test_all_rows_are_translated(self):
        for key in (
            "Server pool",
            "Which server pool Lantern draws from · applies next connection",
            "Lantern's Iran pool — 3x Frankfurt + 1x Amsterdam; the fast servers for Iranian lines",
            "Global",
            "The worldwide free pool (Milan, Ashburn, and more); more locations but slower on Iranian lines",
        ):
            self.assertIn(f'"{key}" to Triple(', STRINGS)
            self.assertIn(f'"{key}" to "', RUSSIAN)


if __name__ == "__main__":
    unittest.main()
