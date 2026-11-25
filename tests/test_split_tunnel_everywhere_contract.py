import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()
UI = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()
TUNNELSTATUS = (ROOT / "app/src/main/java/com/msnguard/vpn/TunnelStatus.kt").read_text()
SPLIT = (ROOT / "app/src/main/java/com/msnguard/vpn/SplitTunnelSettings.kt").read_text()


class SplitTunnelEverywhereContract(unittest.TestCase):
    """3.4.17: the Split Tunneling choice must apply to EVERY transport —
    a user report said it did not work on Foxy. The audit found the wiring
    present on every establish site, but nothing pinned it: the Psiphon and
    Tor paths had each silently shipped without it in the past, and any new
    path could again. This test makes a missing call a CI failure."""

    def _establish_sites(self):
        """Every REAL `Builder ... .establish()` call site (not the word
        'establish()' inside comments/docs), with its preceding block."""
        sites = []
        for m in re.finditer(r'\.establish\(\)\s*\??:', SERVICE):
            pass
        # Match actual calls: `.establish() ?: error(...)` or `= builder.establish()`
        for m in re.finditer(r'\.establish\(\)', SERVICE):
            tail = SERVICE[m.end():m.end() + 80]
            # A real call is followed by ` ?: error(...)` or ends a statement
            # (`val x = builder.establish()`); the doc mention is followed
            # by prose (`— serves it to sing-tun`).
            if not (tail.lstrip().startswith('?:') or tail.lstrip().startswith('\n')):
                # allow bare call statements (kill switch)
                if 'builder.establish()' not in SERVICE[max(0, m.start()-30):m.end()]:
                    continue
            start = max(0, m.start() - 4000)
            sites.append(SERVICE[start:m.start()])
        return sites

    def test_every_vpn_establish_site_applies_split_tunneling(self):
        # The Litmus TUN (`kill switch TUN`) and the TUN-handoff builder
        # are the only establishes allowed without the split call:
        # - the kill-switch builder carries its own documented call
        #   (verified separately below),
        # - establishLanternTun applies it after mirroring the engine plan.
        sites = self._establish_sites()
        self.assertGreaterEqual(len(sites), 6, "establish sites disappeared — re-check the service")
        missing = [i for i, block in enumerate(sites)
                   if 'applySplitTunneling()' not in block]
        self.assertEqual(missing, [],
                         f"establish site(s) {missing} lost the split-tunneling call")

    def test_split_modes_match_the_settings_model(self):
        self.assertIn('ALL("All apps")', SPLIT)
        self.assertIn('INCLUDE("Only selected apps")', SPLIT)
        self.assertIn('EXCLUDE("Exclude selected apps")', SPLIT)
        self.assertIn('?: Mode.ALL', SPLIT)

    def test_foxy_paths_apply_it(self):
        # The user-reported transport: both the Foxy TUN builder and the
        # engine-owned Lantern path must honour the choice.
        for needle in ['Foxy: creating TUN', 'FoxyHevConfig.MAPDNS_ADDRESS']:
            i = SERVICE.find(needle)
            self.assertGreater(i, 0, f"{needle} disappeared from the service")
            block = SERVICE[i:i + 4000]
            self.assertIn('applySplitTunneling()', block,
                          "the Foxy establish path lost the split-tunneling call")

    def test_include_mode_never_mixes_disallow_calls(self):
        # Mixing addAllowedApplication with addDisallowedApplication crashes
        # Builder.establish() — the INCLUDE branch must not do it
        # (packageName included in the allow set would too). The INCLUDE
        # branch's own actions: assert the addAllowed line and that the
        # branch body contains no DISALLOW call of its own.
        inc = SERVICE.find('SplitTunnelSettings.Mode.INCLUDE -> {')
        self.assertGreater(inc, 0, "the per-package INCLUDE dispatch disappeared")
        block = SERVICE[inc:SERVICE.find('}', inc)]  # only the INCLUDE branch body
        self.assertIn('addAllowedApplication(pkg)', block)
        self.assertNotIn('addDisallowedApplication', block)

    def test_whole_device_routing_knows_every_engine(self):
        # The engine-ownership invariant: when Foxy's Hev moved OUT of
        # TunEngineManager, isActive() was patched but isWholeDeviceRouting
        # was not — the exact drift the wrapper reference bans. Both must
        # enumerate every data-path engine.
        for engine in ['TunEngineManager.isRunningAny',
                       'LanternEngine.isSessionActive',
                       'FoxyHevEngine.isRunning']:
            self.assertIn(engine, TUNNELSTATUS)

    def test_split_screen_still_saves_both_mode_and_packages(self):
        self.assertIn('settings.save(settings.mode(), selected)', UI)
        self.assertIn('putStringSet(PACKAGES', SPLIT)


if __name__ == "__main__":
    unittest.main()
