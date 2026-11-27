import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SVC = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()
ENGINE = (ROOT / "app/src/main/java/com/msnguard/vpn/LanternEngine.kt").read_text()


class LanternBatteryAuditContract(unittest.TestCase):
    """3.4.30: the two battery fixes from the audit, pinned — under the hard
    rule that Lantern's behaviour must not change: a screen-off session keeps
    working, a real death is still caught, and NO new machinery exists
    (EXIT-STOP untouched; both fixes are condition reorders inside loops
    that already ran).

    FIX 1 — the watchdog's Lantern branch. A screen-off Lantern session is the
    norm; the 30s watchdog used to make a 350ms /status control round-trip +
    a SOCKS connect every tick regardless (~960 overnight wakeups that could
    only ever confirm a healthy session — the 3.4.21 liveness sensor owns
    real mid-session deaths from the engine's own log). Now with the screen
    off, only isSessionActive (running-flag AND live-process, zero I/O)
    decides; the probes run only when the cheap fact says the session is
    gone, or when the screen is on.

    FIX 2 — the Lantern traffic poller's gate order. It called isRunning (the
    350ms round-trip) BEFORE shouldSampleTraffic (two boolean reads), so a
    dark screen still woke the sidecar every 5s. Screen check now comes
    first: 14 of 15 dark ticks never touch the engine."""

    def lantern_branch(self) -> str:
        start = SVC.find('if (currentProtocol.contains("LANTERN")) {')
        self.assertGreater(start, 0, "Lantern watchdog branch not found")
        end = SVC.find("// SHARD: three things can die independently", start)
        return SVC[start:end]

    def test_fix1_screen_off_skips_the_probe_pair(self):
        b = self.lantern_branch()
        self.assertIn("if (!isScreenInteractive()) {", b)
        self.assertIn("LanternEngine.isSessionActive", b)

    def test_fix1_a_real_death_is_still_caught(self):
        b = self.lantern_branch()
        # the dead branch must still return the honest reason, not null
        self.assertIn('return "the Lantern/Radiance tunnel stopped"', b)
        # and it must appear in the screen-off path itself (the cheap-gate
        # only short-cuts HEALTHY sessions)
        self.assertIn(
            "if (!LanternEngine.isSessionActive && !LanternEngine.isRunning)",
            b)

    def test_fix1_screen_on_behaviour_is_byte_identical(self):
        b = self.lantern_branch()
        # the original two probes stay, after the screen-off gate
        self.assertIn("if (!LanternEngine.isRunning) return \"the Lantern/Radiance tunnel stopped\"", b)
        self.assertIn("if (!LanternEngine.isSocksReady()) return \"the Lantern SOCKS listener stopped\"", b)

    def test_fix1_session_active_is_the_cheap_fact(self):
        # isSessionActive must stay the network-free check: flag + process
        self.assertIn("val isSessionActive: Boolean", ENGINE)
        self.assertIn("running.get() && process?.isAlive == true", ENGINE)

    def test_fix2_poller_checks_the_screen_before_the_engine(self):
        start = SVC.find("private fun startLanternTrafficPolling")
        end = SVC.find("}, 1L, 5L, TimeUnit.SECONDS)", start)
        block = SVC[start:end]
        screen_pos = block.find("if (!shouldSampleTraffic()) {")
        engine_pos = block.find("if (!LanternEngine.isRunning) {")
        self.assertGreater(screen_pos, 0, "screen gate missing in the Lantern poller")
        self.assertGreater(engine_pos, 0, "engine gate missing in the Lantern poller")
        self.assertLess(screen_pos, engine_pos,
                        "the cheap screen check must run BEFORE the 350ms engine round-trip")

    def test_no_new_machinery(self):
        # EXIT-STOP: neither fix may add a scheduler, timer, alarm or receiver
        for banned in ["JobScheduler", "AlarmManager", "WorkManager",
                       "setExactAndAllowWhileIdle", "registerReceiver"]:
            self.assertNotIn(banned, self.lantern_branch())


if __name__ == "__main__":
    unittest.main()
