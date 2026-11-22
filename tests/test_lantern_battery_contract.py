#!/usr/bin/env python3
"""Contract: Lantern's fixed per-second overheads stay bounded (3.4.10).

Field report 3.4.9: 40% battery and a hot phone while the official Lantern
app sips. The engine itself (bandit probes, gvisor) is shared with upstream;
the deltas WE added were: a control-port HTTP request + notification update
every second for the stats display, a stdout log pump fed 2-4 INFO lines per
connection for the whole session, and a real HTTP ping every 5s while the
main screen is up. This pins the reduced cadences.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICE = (
    ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt"
).read_text()
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()
ENGINE = (ROOT / "app/src/main/java/com/msnguard/vpn/LanternEngine.kt").read_text()


class LanternBatteryContract(unittest.TestCase):
    def test_stats_sampler_polls_every_five_seconds_not_one(self):
        # The Lantern stats block is the only sampler allowed at 5s; the
        # other transports keep their own cadences.
        self.assertIn("}, 1L, 5L, TimeUnit.SECONDS)", SERVICE)
        # The per-minute log line still means a minute: 12 ticks x 5s.
        self.assertIn("if (lanternStatsTick >= 12)", SERVICE)

    def test_auto_ping_is_quiet(self):
        # Foreground-only liveness ping: 15s, not 5s.
        self.assertNotIn("autoPingHandler.postDelayed(this, 5000L)", MAIN)
        self.assertIn("autoPingHandler.postDelayed(this, 15000L)", MAIN)
        self.assertIn("autoPingHandler.postDelayed(autoPingRunnable, 15000L)", MAIN)

    def test_the_sidecar_stdout_pump_is_warn_only(self):
        self.assertIn('builder.environment()["RADIANCE_LOG_LEVEL"] = "warn"', ENGINE)


if __name__ == "__main__":
    unittest.main()
