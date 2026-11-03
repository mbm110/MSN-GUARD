from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "app/src/main/java/com/msnguard/vpn"


class FoxyMtuAndCancelContract(unittest.TestCase):
    def test_manual_mtu_clears_connect_scan_and_commits(self):
        mtu = (SRC / "MtuConfig.kt").read_text()
        scan = (SRC / "MtuAutoScan.kt").read_text()
        self.assertIn("MtuAutoScan.clearSessionValue(method)", mtu)
        self.assertIn("putInt(method.prefKey, value).commit()", mtu)
        self.assertIn("fun clearSessionValue(method: MtuConfig.Method)", scan)

    def test_connecting_notification_has_cancel_and_stops_service(self):
        service = (SRC / "MsnGuardVpnService.kt").read_text()
        self.assertIn('const val ACTION_CANCEL_CONNECT', service)
        self.assertIn('action = ACTION_CANCEL_CONNECT', service)
        self.assertIn('Strings.t("Cancel")', service)
        self.assertIn('ACTION_CANCEL_CONNECT ->', service)
        self.assertIn('stopRequested.set(true)', service)
        self.assertIn('cancel(NOTIFICATION_ID)', service)


if __name__ == "__main__":
    unittest.main()
