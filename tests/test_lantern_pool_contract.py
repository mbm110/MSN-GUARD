#!/usr/bin/env python3
"""Contract: the Lantern server pool setting (3.3.7) is real, not cosmetic.

RADIANCE_COUNTRY is consumed by Radiance's config/fetcher.go: non-empty → the
x-lantern-client-country header rides every config fetch (boot, forced
refresh, poll), so Lantern serves the worldwide free pool instead of the
geo-served IR pool (3x Frankfurt + 1x Amsterdam, '-ir-free-' tags). The
3.2.49 field test drew Milan/Ashburn this way; 3.2.50 pinned the IR pool for
throughput; 3.3.7 makes it the user's choice with Iran as the default.
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
RADIANCE = pathlib.Path(
    "/root/.hermes/cache/scratch/radiance-src/config/fetcher.go"
)
RADIANCE_ENV = pathlib.Path(
    "/root/.hermes/cache/scratch/radiance-src/common/env/env.go"
)


class LanternPoolContract(unittest.TestCase):
    def test_the_env_var_is_real_in_radiance(self):
        # The header must exist in the vendored Radiance source — otherwise
        # the setting is cosmetic.
        fetcher = RADIANCE.read_text()
        self.assertIn("x-lantern-client-country", fetcher)
        env_go = RADIANCE_ENV.read_text()
        self.assertIn('"RADIANCE_COUNTRY"', env_go)

    def test_the_engine_sets_the_env_only_on_global(self):
        # Iran (default) presents NO country identity — geo-served IR pool.
        # Global sets the identity that draws the worldwide pool.
        self.assertIn(
            'if (CoreConfig.lanternPool(context) == "global") {', ENGINE
        )
        self.assertIn(
            'builder.environment()["RADIANCE_COUNTRY"] = LANTERN_CONFIG_COUNTRY',
            ENGINE,
        )
        # The identity must be a non-IR country or the draw stays IR.
        self.assertIn('LANTERN_CONFIG_COUNTRY = "TR"', ENGINE)

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
