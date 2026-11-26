import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()
ENGINE = (ROOT / "app/src/main/java/com/msnguard/vpn/LanternEngine.kt").read_text()


class LanternMidSessionRecoveryContract(unittest.TestCase):
    """3.4.21: the mid-session engine-death recovery, from the field log
    (msn-guard-log__2_, 2026-11-26). The Lantern front path died at 13:40 and
    the dial stayed green for 1h42m: app-retry noise crossing the TUN read as
    'busy, healthy' to the byte-based watchdog, and the carrier-side probe
    was counted as tunnel-proof. Two fixes, pinned here:

    1. EVENT-DRIVEN LIVENESS SENSOR in LanternEngine — reads the sidecar's
       own stdout (already walked by the log thread): 3× `mutableautoselect`
       + (`i/o timeout`|`context deadline exceeded`) within 60s = front
       path dead; 2× `no recent network activity` within 60s = keepalive
       dead. No polling loop, no timer, no battery — nothing runs unless
       the engine itself errors. Debounced (one verdict in flight, 90s
       cooldown) and session-gated (list-only/boot errors are not deaths).

    2. THE RECOVERY in MainActivity: only when the dial is CONNECTED and the
       protocol is Lantern; teardown + reconnect via the exact path a user
       tap takes (fresh draw over the phone's own IP, ping, auto-select);
       bounded ×3 with an honest stop, counters reset at both verified gates.
       The probe-evidence fix: an engine-owned Lantern session's probe is
       carrier-side — it may paint latency, never a health verdict."""

    # ── the sensor (LanternEngine) ──
    def test_sensor_feeds_behind_the_log_thread_before_the_spam_gate(self):
        self.assertIn("feedHealthSensor(lower)", ENGINE)
        gate = ENGINE.find("// 3.4.6 TEMP DIAGNOSTIC")
        feed = ENGINE.find("feedHealthSensor(lower)")
        self.assertLess(feed, gate, "the sensor must see every line, even ones the spam gate drops")

    def test_the_two_death_signatures_from_the_field_log(self):
        self.assertIn('lower.contains("mutableautoselect")', ENGINE)
        self.assertIn('lower.contains("i/o timeout") || lower.contains("context deadline exceeded")', ENGINE)
        self.assertIn('lower.contains("no recent network activity")', ENGINE)

    def test_debounce_and_session_gate(self):
        self.assertIn("FRONT_PATH_TRIGGERS = 3", ENGINE)
        self.assertIn("FRONT_PATH_SPAN_MS = 60_000L", ENGINE)
        self.assertIn("KEEPALIVE_TRIGGERS = 2", ENGINE)
        self.assertIn("KEEPALIVE_SPAN_MS = 60_000L", ENGINE)
        self.assertIn("VERDICT_COOLDOWN_MS = 90_000L", ENGINE)
        self.assertIn("if (!isSessionActive) return", ENGINE,
                      "list-only/boot errors must not be read as a session dying")
        self.assertIn("fun healthVerdictHandled()", ENGINE)

    def test_no_background_loops_in_the_engine_side(self):
        block = ENGINE[ENGINE.find("MID-SESSION LIVENESS SENSOR"):ENGINE.find("private fun binary")]
        for banned in ["Timer(", "postDelayed", "scheduleAtFixedRate", "while (true)", "Thread {", "Thread("]:
            self.assertNotIn(banned, block, f"{banned} — the sensor must be purely event-driven")

    # ── the recovery + evidence fix (MainActivity) ──
    def test_callback_registered_on_start_bounces_to_ui_thread(self):
        self.assertIn("LanternEngine.onEngineHealthVerdict = { reason ->", MAIN)
        self.assertIn("runOnUiThread { if (!isFinishing && !isDestroyed) onLanternEngineDeath(reason) }", MAIN)

    def test_recovery_gates_protocol_and_state(self):
        fn = MAIN[MAIN.find("private fun onLanternEngineDeath"):MAIN.find("private fun reportVerifyState")]
        self.assertIn("visualState != OrbitDialView.State.CONNECTED", fn)
        self.assertIn("selectedProtocol != Protocol.LANTERN", fn)
        self.assertIn("if (engineRecoveryInFlight) return", fn)

    def test_recovery_is_bounded_and_honest(self):
        fn = MAIN[MAIN.find("private fun onLanternEngineDeath"):MAIN.find("private fun reportVerifyState")]
        self.assertGreaterEqual(fn.count("consecutiveEngineDeaths"), 3)
        self.assertIn("consecutiveEngineDeaths >= 3", fn)
        self.assertIn("stopping auto-recovery", fn)
        self.assertIn("showFailure(", fn)

    def test_recovery_takes_the_same_path_a_user_tap_takes(self):
        fn = MAIN[MAIN.find("private fun onLanternEngineDeath"):MAIN.find("private fun reportVerifyState")]
        self.assertIn("MsnGuardVpnService.ACTION_DISCONNECT", fn)
        self.assertIn("connect(configJson())", fn)
        # the same 1.2s settle the 3.4.13 auto-reconnect uses
        self.assertIn("}, 1_200)", fn)

    def test_counters_reset_when_a_session_verifies(self):
        bytes_gate = MAIN.find("verified from inside the tunnel")
        reach_gate = MAIN.find("Reachability probe passed in $attempts")
        for pos in [bytes_gate, reach_gate]:
            block = MAIN[pos:pos + 400]
            self.assertIn("consecutiveEngineDeaths = 0", block)

    def test_probe_evidence_fix_lantern_probe_is_carrier_side(self):
        self.assertIn("val lanternCarrierProbe = selectedProtocol == Protocol.LANTERN &&", MAIN)
        self.assertIn("!reverseWireguardEngineProbe && !lanternCarrierProbe &&", MAIN)
        # and bit-noise in TUN no longer reads 'busy, healthy' on Lantern:
        self.assertIn("movedBytes >= BUSY_TUNNEL_RX_BYTES && !lanternCarrierProbe || counterRestarted", MAIN)

    def test_the_watchdogs_loop_cannot_stack_recoveries(self):
        fn = MAIN[MAIN.find("private fun onLanternEngineDeath"):MAIN.find("private fun reportVerifyState")]
        self.assertIn("engineRecoveryInFlight = true", fn)
        self.assertIn("engineRecoveryInFlight = false", fn)
        self.assertIn("LanternEngine.healthVerdictHandled()", fn)


if __name__ == "__main__":
    unittest.main()
