#!/usr/bin/env python3
"""Contract: the Lantern DNS hijack (3.3.8) is real, not cosmetic.

Field evidence (3.3.7 log, 17 min): apps with hardcoded resolvers
(Instagram/Chrome/X → 8.8.8.8 etc.) sent UDP:53 through the TUN; Hev could not
map those destinations, forwarded them raw, and the SOCKS server's DNS hijack
answered from its 198.18.0.0/15 fake range, which Hev cannot reverse-map —
every such connection was then rejected as "missing fakeip record" (~200 ms,
sing-box route.go: prepareMatchMetadata returns an error → connection dropped).

The fix: Hev's mapdns answers EVERY UDP query to the mapdns port, whatever
resolver it aimed at, from its own reversible 100.64.0.0/10 pool, so the domain
travels in the SOCKS request exactly like the system-resolver path. Opt-in per
tunnel: only the Lantern path sets it; every other method's DNS path stays
byte-identical.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HEV = ROOT / "app/src/main/cpp/hev/src"
KOTLIN = ROOT / "app/src/main/java/com/msnguard/vpn"


class HevDnsHijackContract(unittest.TestCase):
    def test_the_native_config_parses_the_flag(self):
        cfg = (HEV / "hev-config.c").read_text()
        self.assertIn('strcmp (key, "hijack")', cfg)
        self.assertIn("mapdns_hijack = 0;", cfg)
        self.assertIn("hev_config_get_mapdns_hijack", cfg)
        self.assertIn(
            "int hev_config_get_mapdns_hijack (void);",
            (HEV / "hev-config.h").read_text(),
        )

    def test_the_interception_honors_the_flag(self):
        tunnel = (HEV / "hev-socks5-tunnel.c").read_text()
        # The synthetic-address match must stay; the hijack only WIDENS it to
        # the mapdns port on any destination.
        self.assertIn("faddr == ip_2_ip4 (addr)->addr || hijack", tunnel)
        self.assertIn("hev_config_get_mapdns_hijack ()", tunnel)

    def test_the_flag_is_opt_in_from_the_tunnel(self):
        engine = (KOTLIN / "HevEngine.kt").read_text()
        # The TunEngine interface keeps its 4-arg shape; the new parameter is
        # an opt-in overload defaulting to the old behavior.
        self.assertIn("dnsHijackAll: Boolean", engine)
        self.assertIn("dnsHijackAll = false)", engine)
        self.assertIn('appendLine("  hijack: ${if (dnsHijackAll) "', engine)
        service = (KOTLIN / "MsnGuardVpnService.kt").read_text()
        self.assertIn(
            "HevEngine.start(establishedTun, LanternEngine.SOCKS_PORT, mtu, dnsOnly = false, dnsHijackAll = true)",
            service,
        )


if __name__ == "__main__":
    unittest.main()
