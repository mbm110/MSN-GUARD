#!/usr/bin/env python3
"""Contract: the notification row and the screen must never disagree.

Field report (3.2.43, WoW): while the app's dial was still on Connecting, the
notification already said Connected. Root cause: the service flips the row at
its handshake edge (the SOCKS listener answering), while the UI deliberately
withholds Connected until beginVerification() proves payload crosses — two
different moments by design. The fix threads the UI's verification phase to
the service so the row holds "Connecting…" for exactly as long as the screen
does, on EVERY transport (they all go through the same gate).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
SERVICE = (APP / "MsnGuardVpnService.kt").read_text()
ACTIVITY = (APP / "MainActivity.kt").read_text()
STATUS = (APP / "TunnelStatus.kt").read_text()


import unittest


class NotificationVerifySyncContract(unittest.TestCase):
    def test_notification_holds_connecting_while_the_ui_verifies(self):
        # The row must not claim a tunnel the screen is still proving; when no
        # activity is verifying (app closed) it falls back to the handshake edge.
        self.assertIn(
            'TunnelStatus.uiVerifying && !TunnelStatus.sessionVerified -> Strings.t("Connecting…")',
            SERVICE,
        )

    def test_shared_state_carries_the_gate(self):
        self.assertIn("var uiVerifying: Boolean = false", STATUS)
        self.assertIn("var sessionVerified: Boolean = false", STATUS)

    def test_service_handles_the_phase_action(self):
        self.assertIn('const val ACTION_VERIFY_STATE = "com.msnguard.vpn.VERIFY_STATE"', SERVICE)
        self.assertIn("VERIFY_PHASE_VERIFYING -> {", SERVICE)
        self.assertIn("VERIFY_PHASE_CONNECTED -> {", SERVICE)
        self.assertIn("VERIFY_PHASE_ABANDONED -> TunnelStatus.uiVerifying = false", SERVICE)

    def test_fresh_sessions_start_unverified(self):
        # A stale verified flag from the previous session would flip the row at
        # the first mid-connect repost.
        self.assertIn("TunnelStatus.sessionVerified = false", SERVICE)

    def test_activity_reports_every_phase(self):
        # beginVerification holds the row on Connecting; showConnected (every
        # route: gate pass, engine bypasses, restored paint) releases it; a
        # destroyed activity abandons so the row cannot stick on Connecting.
        self.assertIn(
            "reportVerifyState(MsnGuardVpnService.VERIFY_PHASE_VERIFYING)", ACTIVITY
        )
        self.assertIn(
            "reportVerifyState(MsnGuardVpnService.VERIFY_PHASE_CONNECTED)", ACTIVITY
        )
        self.assertIn(
            "reportVerifyState(MsnGuardVpnService.VERIFY_PHASE_ABANDONED)", ACTIVITY
        )

    def test_the_timer_does_not_run_before_the_gate_passes(self):
        self.assertIn(
            "if (connectedSince > 0L && !TunnelStatus.uiVerifying) {", SERVICE
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
