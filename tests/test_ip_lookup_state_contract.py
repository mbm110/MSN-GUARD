from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()


class IpLookupStateContract(unittest.TestCase):
    def test_ip_and_country_lookup_are_blocked_while_connecting(self):
        self.assertIn("if (visualState == OrbitDialView.State.CONNECTING)", MAIN)
        self.assertIn("if (ip.isBlank() || visualState == OrbitDialView.State.CONNECTING) return", MAIN)
        self.assertIn("if (visualState == OrbitDialView.State.CONNECTING) return@runOnUiThread", MAIN)

    def test_disconnected_and_connected_paths_still_request_ip(self):
        self.assertIn("showConnected", MAIN)
        self.assertIn("refreshPublicIp()", MAIN)
        self.assertIn("private fun showDisconnected", MAIN)


if __name__ == "__main__":
    unittest.main()
