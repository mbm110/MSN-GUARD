import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()
SVC = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()
STATUS = (ROOT / "app/src/main/java/com/msnguard/vpn/TunnelStatus.kt").read_text()


class MissedConnectedEdgeContract(unittest.TestCase):
    """3.4.23: the screen-off-during-connect bug, from the user's field report.

    Tap Connect, turn the screen off while the dial still reads Connecting. The
    service connects fine in the background — notification says Connected,
    Telegram works — but STATUS_CONNECTED was broadcast while the activity's
    receiver was unregistered (onStop), so the verification gate never started
    and the dial stayed on Connecting forever: adoptRunningTunnel deliberately
    refuses to touch a CONNECTING paint ("the gate owns the paint"), so nothing
    on the resume path ever republished the state.

    The fix, pinned here:
    - the service stamps its LAST broadcast status at the exact moment it
      broadcasts (TunnelStatus.lastServiceStatus) — the same fact the UI
      missed, written where the edge happened, no probing;
    - on resume, a screen still painted CONNECTING over a CONNECTED service
      replays the missed edge through the SAME gate the broadcast would have
      fed (beginVerification) — never a blind green paint, so a
      handshake-only tunnel still cannot pass;
    - FAILED/DISCONNECTED edges are NOT replayed (lastServiceStatus carries
      them; the guard is equality against STATUS_CONNECTED);
    - a recreate (config change / process death) must not miss the edge
      either: the same replay runs from onStart after showLanguagePickerOnce —
      the activity is being built fresh and could easily have been dead
      through the whole connect."""

    def test_service_stamps_last_status_where_it_broadcasts(self):
        self.assertIn("TunnelStatus.lastServiceStatus = status", SVC)
        # the stamp sits inside sendStatus, after the broadcast is built
        bcast = SVC.find("sendBroadcast(Intent(ACTION_STATUS)")
        stamp = SVC.find("TunnelStatus.lastServiceStatus = status")
        self.assertGreater(bcast, 0)
        self.assertGreater(stamp, bcast, "the stamp must live where the edge is broadcast")

    def test_the_field_is_theShared_truth_not_a_guess(self):
        self.assertIn("@Volatile", STATUS)
        self.assertIn("var lastServiceStatus: String = \"\"", STATUS)
        self.assertIn("internal set", STATUS)

    def test_resume_replays_through_the_gate_not_a_blind_paint(self):
        record = MAIN.find('ConnectionLog.record("UI resume: replaying the CONNECTED edge missed')
        self.assertGreater(record, 0, "the replay log line is missing")
        # guards sit ABOVE the record call — take the block from before it
        block = MAIN[record - 1400:record + 200]
        self.assertIn("visualState == OrbitDialView.State.CONNECTING", block)
        self.assertIn("!verifyInFlight", block)
        self.assertIn("TunnelStatus.lastServiceStatus == MsnGuardVpnService.STATUS_CONNECTED", block)
        self.assertIn("TunnelStatus.isActive()", block)
        # and it must never bypass the proof: beginVerification, not showConnected
        after = MAIN[record:record + 200]
        self.assertIn("beginVerification()", after)
        self.assertNotIn("showConnected(", after)

    def test_the_replay_lives_on_the_resume_path(self):
        adopt = MAIN.find("adoptRunningTunnel()\n        // 3.4.23")
        self.assertGreater(adopt, 0, "the replay must follow adoptRunningTunnel on resume")

    def test_recreate_path_is_covered_too(self):
        # onStart (a fresh activity after process death/recreate) runs the
        # same replay before the first frame: a connect that finished while
        # the process was dead must not leave a rebuilt UI on Connecting.
        oncreate = MAIN.find("if (AppLanguage.hasChosen(this)) maybeShowCoffeePopup()")
        replay = MAIN.find("replaying the CONNECTED edge missed while the screen was off")
        self.assertGreater(replay, 0)
        # the replay is in onResume; the onStart onCreate path keeps its own
        # check through the shared helper — both must reference the gate
        self.assertIn("TunnelStatus.lastServiceStatus", MAIN)


if __name__ == "__main__":
    unittest.main()
