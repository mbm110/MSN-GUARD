#!/usr/bin/env python3
"""Contract: the Lantern server pool setting (3.3.7) is real, not cosmetic.

3.4.9: the pool is enforced CLIENT-SIDE. The server-track probe proved the
server draws the pool from the EXIT IP of the config fetch — the
x-lantern-client-country header and the locale are ignored — so the 3.4.8
header pin could not survive a mid-session refresh that left through the
tunnel (field log 3.4.8: the 17:18 refill swapped 5 dead global servers into
the auto group and the session died). RADIANCE_POOL=ir now filters the
server list to the pinned '-ir-free-' pool inside the vendored Radiance
(vpn/hostaccess.go pinPoolIfRequested), on every load — boot and refresh
alike; global keeps the upstream rotating worldwide sample.
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


class LanternPoolContract(unittest.TestCase):
    def test_the_pool_filter_is_real_in_the_vendored_radiance(self):
        # The filter must exist in the vendored Radiance — otherwise the
        # setting is cosmetic.
        self.assertIn('p != "iran" && p != "ir"', HOSTACCESS)
        self.assertIn('"-ir-free-"', HOSTACCESS)
        # A draw with no ir-free members must keep the previous list, never
        # empty the auto group.
        self.assertIn("draw had no ir-free servers; keeping the previous list", HOSTACCESS)
        # The filter runs inside allowedServers, which every server load
        # (boot and config refresh) goes through.
        self.assertIn("list = pinPoolIfRequested(list)", HOSTACCESS)

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
        self.assertIn('CoreConfig.LANTERN_POOL, chosen.coreName', UI)
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
