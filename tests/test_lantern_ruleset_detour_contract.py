#!/usr/bin/env python3
"""Contract: the smart-routing rule-sets download through the tunnel (3.4.9).

Field logs 3.4.7/3.4.8: "fetch rule-set ga-ir ... lookup [domain] ... i/o
timeout" every 10s — upstream downloads remote rule-sets via "direct", whose
host needs the direct DoH resolvers, dead on the Iranian line (DPI). The
vendored Radiance now reroutes those downloads through the tunnel's
auto-select group: proxy outbounds pass the domain to the remote server, so
no local DNS is needed and the rule-set loads once the tunnel is up.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BOXOPTIONS = (
    ROOT / "core/lanternbridge/third_party/radiance/vpn/boxoptions.go"
).read_text()


class RuleSetDetourContract(unittest.TestCase):
    def test_the_detour_helper_exists(self):
        self.assertIn("func detourRuleSetsThroughTunnel(rulesets []O.RuleSet)", BOXOPTIONS)
        # Only remote rule-sets, only empty/direct detours — an explicit
        # server-chosen detour must survive.
        self.assertIn("rulesets[i].Type != C.RuleSetTypeRemote", BOXOPTIONS)
        self.assertIn('d != "" && d != "direct"', BOXOPTIONS)
        self.assertIn("rulesets[i].RemoteOptions.DownloadDetour = AutoSelectTag", BOXOPTIONS)

    def test_both_ruleset_sources_are_rerouted(self):
        # 3.4.10: ONE pass over the fully assembled opts.Route.RuleSet — the
        # rule-sets arrive from three sources (server options, smart routing,
        # ad block) and patching only two of them left the server's ga-ir
        # entry dialing direct (field log 3.4.9: errors ran the whole
        # session).
        self.assertEqual(BOXOPTIONS.count("detourRuleSetsThroughTunnel(") - 1, 1)
        self.assertIn("detourRuleSetsThroughTunnel(opts.Route.RuleSet)", BOXOPTIONS)


if __name__ == "__main__":
    unittest.main()
