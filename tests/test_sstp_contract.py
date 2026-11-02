import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()
SERVICE = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()
REPO = (ROOT / "app/src/main/java/com/msnguard/vpn/SstpModels.kt").read_text()
SESSION = (ROOT / "app/src/main/java/com/msnguard/vpn/SstpSession.kt").read_text()


class SstpContract(unittest.TestCase):
    def test_sstp_is_after_wow_and_has_manual_automatic_ui(self):
        self.assertIn('WARP_IN_WARP("WARP-on-WARP"', MAIN)
        self.assertIn('SSTP("SSTP", "sstp"', MAIN)
        self.assertLess(MAIN.index('WARP_IN_WARP("WARP-on-WARP"'), MAIN.index('SSTP("SSTP", "sstp"'))
        self.assertIn('Automatic', MAIN)
        self.assertIn('Update SSTP servers', MAIN)

    def test_sstp_sources_are_deduplicated_and_cached(self):
        self.assertIn('F0rc3Run', REPO)
        self.assertIn('vpngate.net', REPO)
        self.assertIn('omgvpn.com', REPO)
        self.assertIn('opengw.net', REPO)
        self.assertIn('groupBy { it.key }', REPO)
        self.assertIn('sstp_servers_json', REPO)

    def test_service_dispatches_sstp_without_native_core(self):
        self.assertIn('currentProtocol.contains("SSTP")', SERVICE)
        self.assertIn('startSstpTunnel()', SERVICE)
        start = SERVICE.index('private fun startSstpTunnel()')
        end = SERVICE.index('private fun startShardTunnel()')
        self.assertNotIn('NativeCore.start', SERVICE[start:end])
        self.assertIn('Controller(SharedBridge(this))', SESSION)
        self.assertIn('protectSocket', SESSION)
