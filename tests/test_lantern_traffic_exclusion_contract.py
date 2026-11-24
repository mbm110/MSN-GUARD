#!/usr/bin/env python3
"""Contract: only ONE traffic poller may feed the pipeline per transport
(3.3.5, the Lantern zero-display regression).

Field log 3.3.4 (Lantern session): "lantern stats: tx=61516 rx=252984
(samples=60 skipped=0)" grows every minute while "warp stats: up=0 down=0"
prints every minute and the screen shows Up/Down/Speed = 0. Two pollers were
feeding updateTrafficNotification: the Lantern poller with Radiance's real
cumulative counters, and the WARP poller (armed by the generic s0 front path
a Lantern session now runs through) with NativeCore snapshots of [0, 0] — no
native core is running. Every zero interleaved with a real counter trips the
backwards-sample rebase in updateTrafficNotification, zeroing prev/accounted
baselines each second: the speed never computes and sendTraffic carries zeros.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVICE = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()


class LanternTrafficExclusionContract(unittest.TestCase):
    def test_the_warp_poller_stays_silent_during_a_lantern_session(self):
        # Same shape as the TorSocksFront/ShardSocksFront guard it sits under:
        # the front that owns the counters feeds the pipeline, the warp
        # poller's zero-snapshots must never interleave with them.
        self.assertIn("if (LanternEngine.isRunning) return@scheduleAtFixedRate", SERVICE)

    def test_a_lantern_session_cancels_the_warp_poller(self):
        # Belt and suspenders: cancelling at lantern-poll start also stops the
        # 1 Hz timer from waking at all during the session.
        self.assertIn(
            "torTrafficTask?.cancel(false)\n"
            "        // The generic s0 front path arms the WARP poller",
            SERVICE,
        )
        self.assertIn(
            "private fun startLanternTrafficPolling() {\n"
            "        torTrafficTask?.cancel(false)",
            SERVICE,
        )


if __name__ == "__main__":
    unittest.main()
