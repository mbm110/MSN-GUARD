from pathlib import Path
import unittest

ROOT = Path(__file__).parents[1]
MAIN = ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt"
SERVICE = ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt"
EXIT = ROOT / "app/src/main/java/com/msnguard/vpn/WarpExitManager.kt"
BUILD = ROOT / "app/build.gradle.kts"


class MasqueExitNodeContractTest(unittest.TestCase):
    def test_exit_switch_keeps_cache_first_discovery(self):
        text = MAIN.read_text()
        start = text.index("private fun requestFreshScanAfterExitSwitch")
        block = text[start : start + 500]
        self.assertIn("EndpointDiscovery.CACHE.coreName", block)
        self.assertNotIn("EndpointDiscovery.FRESH.coreName", block)
        self.assertNotIn("aether-lastconn.toml", block)

    def test_custom_exit_requires_real_tcp_preflight_before_upstream(self):
        service = SERVICE.read_text()
        probe = 'probeTcpThroughExit("www.cloudflare.com", 443, 2_000)'
        upstream = 'warpExitUpstream = "socks5://127.0.0.1:${WarpExitManager.SOCKS_PORT}"'
        self.assertIn(probe, service)
        self.assertIn("TCP preflight passed", service)
        self.assertIn("falling back to Freedom", service)
        self.assertLess(service.index(probe), service.index(upstream))

    def test_preflight_keeps_dns_inside_socks_proxy(self):
        text = EXIT.read_text()
        self.assertIn("Proxy.Type.SOCKS", text)
        self.assertIn("InetSocketAddress.createUnresolved(host, port)", text)

    def test_version_is_experimental_and_incremented(self):
        text = BUILD.read_text()
        self.assertIn("versionCode = 436", text)
        self.assertIn('versionName = "3.1.39"', text)

    def test_custom_exit_clears_freedom_ech_on_main_and_mtu_retry_env(self):
        service = SERVICE.read_text()
        self.assertGreaterEqual(service.count('remove("AETHER_API_ECH")'), 2)
        self.assertGreaterEqual(service.count('remove("AETHER_ECH")'), 2)
        self.assertIn('put("AETHER_UPSTREAM", warpExitUpstream!!)', service)
        self.assertIn('patched["AETHER_UPSTREAM"] = "socks5://127.0.0.1:${WarpExitManager.SOCKS_PORT}"', service)


if __name__ == "__main__":
    unittest.main()
