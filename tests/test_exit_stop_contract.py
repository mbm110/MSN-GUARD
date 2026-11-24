import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()
JOB = (ROOT / "app/src/main/java/com/msnguard/vpn/ShardRefreshJob.kt").read_text()


class ExitStopContract(unittest.TestCase):
    """3.4.15 EXIT-STOP: after the user disconnects and leaves the app, the
    app draws ZERO battery — no background wake-up of any kind."""

    def test_the_shard_background_job_is_gone(self):
        # The manifest must NOT register the job service: a manifest entry
        # is what lets JobScheduler start it while the app is closed.
        self.assertNotIn('android:name=".ShardRefreshJob"', MANIFEST)
        self.assertNotIn("BIND_JOB_SERVICE", MANIFEST)

    def test_no_periodic_registration_survives(self):
        # schedule() is GONE; nothing may re-register the job.
        self.assertNotIn("fun schedule(", JOB)
        self.assertNotIn("setPeriodic", JOB)
        self.assertNotIn("ShardRefreshJob.schedule", MAIN)
        # The historical id survives only as the cancel target.
        self.assertIn("private const val JOB_ID = 0x5A4D", JOB)
        self.assertIn("scheduler.cancel(JOB_ID)", JOB)

    def test_launch_cancels_stale_registrations(self):
        # Every launch retires registrations left by upgraded-from builds.
        self.assertIn("ShardRefreshJob.cancel(this)", MAIN)

    def test_the_foreground_refresh_still_exists(self):
        # The feature itself is preserved: opening the app refreshes every
        # list. Those calls must stay — removing the background job must not
        # take the foreground refresh with it.
        self.assertIn("ShardSubscription.refreshIfDue(this)", MAIN)
        self.assertIn("RemotePolicy.refreshIfDue(this)", MAIN)
        self.assertIn("SmartSplitSub.refreshIfDue(this)", MAIN)

    def test_no_other_background_waker_exists(self):
        # No wake locks, no exact alarms, no boot receiver anywhere: the grep
        # that found ShardRefreshJob found nothing else, and this pins it.
        sources = "\n".join(
            p.read_text() for p in
            (ROOT / "app/src/main/java/com/msnguard/vpn").glob("*.kt")
        )
        self.assertNotIn("newWakeLock", sources)
        self.assertNotIn("setExactAndAllowWhileIdle", sources)
        self.assertNotIn("RECEIVE_BOOT_COMPLETED\"", MANIFEST)


if __name__ == "__main__":
    unittest.main()
