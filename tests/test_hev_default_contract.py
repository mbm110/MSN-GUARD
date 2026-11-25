import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TUN = (ROOT / "app/src/main/java/com/msnguard/vpn/TunEngine.kt").read_text()
SERVICE = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()


class HevDefaultContract(unittest.TestCase):
    """3.4.16: the default TUN engine is HEV (mapdns answers DNS locally),
    BadVPN stays an explicit compatibility choice. Field evidence:
    on BadVPN every app DNS query rides the full local chain and the
    tunnel RTT — Telegram's first open stalls seconds on "Connecting";
    on Hev, mapdns answers in-process and the domain rides to the SOCKS
    edge — Telegram connects instantly (user-verified 3.4.15, WireGuard,
    Iranian mobile line)."""

    def test_the_default_is_hev(self):
        self.assertIn('ctx.profiled().getString(KEY, HEV) ?: HEV', TUN)
        self.assertIn('return if (v in ALL) v else HEV', TUN)

    def test_legacy_stays_selectable_and_is_the_fallback_engine(self):
        # The old default stays in the pool and keeps its role as the
        # runtime fallback when an engine fails to start.
        self.assertIn('const val LEGACY = "legacy"', TUN)
        lowered = TUN.lower()
        self.assertIn('falling back to legacy', lowered)
        self.assertIn('if (engine !== LegacyEngine) LegacyEngine.start', TUN)

    def test_the_validator_maps_every_engine(self):
        self.assertIn('TunEnginePref.ZEPTUN -> ZeptunEngine', TUN)
        self.assertIn('TunEnginePref.HEV    -> HevEngine', TUN)
        self.assertIn('else                 -> LegacyEngine', TUN)

    def test_warp_path_branches_per_engine_unchanged(self):
        # The service keyed these on the engine identity, not on a default
        # assumption — the switch must not touch them.
        self.assertIn('legacyFrontUp', SERVICE)
        self.assertIn('smartDnsUp', SERVICE)

    def test_all_three_engines_are_stopped_on_teardown(self):
        self.assertIn('if (LegacyEngine.isRunning) LegacyEngine.stop()',
                      TUN.replace('try { ', ''))
        self.assertIn('if (HevEngine.isRunning) HevEngine.stop()',
                      TUN.replace('try { ', ''))


if __name__ == "__main__":
    unittest.main()
