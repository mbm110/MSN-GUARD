"""Guard the WARP-path DNS cache experiment (3.2.47).

Field report: opening Telegram right after a WARP-class connect waited
seconds-to-30s while the Lantern transport felt instant — every DNS query
crosses the fresh tunnel twice, and an app resolves several names before its
first byte. Lantern answers DNS locally (sing-box fake-IP); the WARP path had
no local answer.

The experiment: [WarpDnsCache] inside [WarpUdpgwFront], the point every
WARP-class datagram already crosses. The rules below are the safety contract —
any regression means reverting this file plus the three hooks.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
CACHE = (APP / "WarpDnsCache.kt").read_text()
FRONT = (APP / "WarpUdpgwFront.kt").read_text()
SERVICE = (APP / "MsnGuardVpnService.kt").read_text()


class WarpDnsCacheContract(unittest.TestCase):
    def test_only_port_53_flows_qualify(self):
        # mDNS (5353) and QUIC (443) must never be parsed as DNS.
        self.assertIn("if (destinationPort == 53 && payload.size >= 12) {", FRONT)
        self.assertIn("val isDnsFlow = clientPort == 53", FRONT)
        self.assertIn("if (isDnsFlow && payload.size >= 12) {", FRONT)

    def test_only_clean_standard_responses_are_cached(self):
        # QR=1, opcode 0, one question, NOERROR, answers present, not
        # truncated — anything else passes through untouched.
        self.assertIn("if ((flags shr 9) and 1 != 0) return false // truncated", CACHE)
        self.assertIn("if (rcode != 0) return false", CACHE)
        self.assertIn("if (an < 1) return false", CACHE)

    def test_never_serve_stale(self):
        # An entry is served only while its shortest real TTL is positive;
        # expired entries are dropped, not served. TTLs are rewritten to the
        # remaining time so apps still see a truthful record.
        self.assertIn("if (shortestTtl(ttls) - elapsedS <= 0) {", CACHE)
        self.assertIn("entries.remove(key)\n            return null", CACHE)
        self.assertIn("val remaining = (f.seconds - elapsedS).coerceAtLeast(0)", CACHE)

    def test_opt_pseudo_rr_is_never_rewritten(self):
        # The OPT record's "TTL" field is the extended rcode and flags, not a
        # TTL — rewriting it corrupts EDNS.
        self.assertIn("if (f.type == 41) continue", CACHE)
        self.assertIn("if (f.type == 41) continue // OPT: not a real TTL", CACHE)

    def test_the_cached_reply_path(self):
        # A hit is answered inside the front, before any association opens —
        # and misses and non-DNS datagrams are byte-identical to today.
        self.assertIn("WarpDnsCache.lookup(payload)", FRONT)
        self.assertIn("writeUdpgwReply(conid, isIpv6, address, cached, output)", FRONT)
        self.assertIn("WarpDnsCache.offer(payload, clientAddress)", FRONT)

    def test_the_reply_still_flows_to_the_app(self):
        # offer() happens BEFORE writeUdpgwReply: caching arms the next query
        # and never delays or alters the datagram the app is waiting for.
        self.assertIn(
            """                        if (isDnsFlow && payload.size >= 12) {
                            WarpDnsCache.offer(payload, clientAddress)
                        }
                        writeUdpgwReply(conid, isIpv6, clientAddress, payload, output)""",
            FRONT,
        )

    def test_persistence_and_warm_up_are_purely_additive(self):
        # Answers survive reconnects via a file; the warm-up only re-asks
        # nearly-expired names through the real tunnel and feeds the cache —
        # it never serves an app.
        self.assertIn("fun configure(context: Context)", CACHE)
        self.assertIn("fun flush()", CACHE)
        self.assertIn("WarpDnsCache.flush()", FRONT)
        self.assertIn("fun warmDnsCache()", FRONT)
        self.assertIn("fun start(socksPort: Int, context: android.content.Context? = null)", FRONT)
        self.assertIn("WarpUdpgwFront.start(legacyUpstreamPort, this@MsnGuardVpnService)", SERVICE)
        # The warm-up runs after every WARP-path connect.
        self.assertGreaterEqual(SERVICE.count("WarpUdpgwFront.warmDnsCache()"), 3)
        # The stored query is a clean standard query, not the response header.
        self.assertIn("query[2] = 0x01", CACHE)

    def test_case_insensitive_keys(self):
        # Resolvers may randomize case (0x20 bit); the key lowercases ASCII
        # letters while the cached response keeps its original case.
        self.assertIn("if (c in 0x41..0x5A) c += 0x20", CACHE)

    def test_lantern_foxy_shard_psiphon_tor_paths_untouched(self):
        # WarpUdpgwFront is the WARP path only (its own doc says so); nothing
        # else references the cache.
        self.assertEqual(SERVICE.count("WarpDnsCache"), 0)
        for name in ("LanternTunEngine", "ShardSocksFront", "FoxyVpnService", "TorSocksFront"):
            path = APP / f"{name}.kt"
            if path.exists():
                self.assertNotIn("WarpDnsCache", path.read_text())


if __name__ == "__main__":
    unittest.main()
