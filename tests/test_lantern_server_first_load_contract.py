#!/usr/bin/env python3
"""Contract: the Lantern Server picker loads its list on FIRST entry.

Field report (3.2.47): opening Settings → Lantern → Server showed only
"Automatic" and the servers appeared only after backing out one level and
re-entering. Root cause: the first offline open boots the list-only sidecar,
whose control socket answers immediately, but Radiance's first config fetch
(user-create + POST /config-new) can outlast the picker's 5s snapshot read on
the raw Iranian link — the sheet was built from the (still empty) result and
never refreshed. The fix: when that first read comes back empty, wait for the
config behind a visible progress sheet (bounded, worker-thread) and only then
open the picker.
"""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
UI = (APP / "MainActivity.kt").read_text()
STRINGS = (APP / "Strings.kt").read_text()
RUSSIAN = (APP / "RussianStrings.kt").read_text()


class LanternServerPickerFirstLoadContract(unittest.TestCase):
    def test_first_open_waits_for_the_config_fetch(self):
        # loadLanternServers: after the list-only boot, an empty 5s snapshot
        # must hand off to the bounded waiter instead of opening the sheet
        # with "Automatic" only.
        self.assertIn("snapshot = LanternEngine.serversSnapshot(timeoutMs = 5_000)", UI)
        self.assertIn("if (snapshot == null) {", UI)
        self.assertIn("snapshot = awaitLanternServerConfig()", UI)

    def test_the_waiter_is_bounded_and_visible(self):
        # A progress sheet while waiting (the tap must not look frozen), a
        # 25s deadline so a dead network still opens the picker, polling the
        # snapshot on the worker thread, and a guaranteed dismiss in finally.
        self.assertIn("private fun awaitLanternServerConfig(): JSONObject?", UI)
        self.assertIn("System.currentTimeMillis() + 25_000L", UI)
        self.assertIn("Thread.sleep(1_500L)", UI)
        self.assertIn("serversSnapshot(timeoutMs = 3_000)", UI)
        self.assertIn("runOnUiThread { loading.get()?.dismiss() }", UI)
        # The dismiss is posted after the show from the same worker thread, so
        # ordering is guaranteed — the invariant the AtomicReference relies on.
        show_idx = UI.index("dialog.show()")
        dismiss_post_idx = UI.index("runOnUiThread { loading.get()?.dismiss() }")
        self.assertLess(show_idx, dismiss_post_idx)

    def test_progress_caption_exists_in_every_locale_column(self):
        key = "Fetching Lantern servers…"
        self.assertIn(f'"{key}" to Triple("{key}",', STRINGS)
        self.assertIn(f'"{key}" to "', RUSSIAN)

    def test_the_empty_state_fallback_is_unchanged(self):
        # On timeout the waiter returns null and the picker still opens with
        # its empty-state text — the sheet's behavior for a dead network is
        # byte-identical to the pre-fix fallback.
        self.assertIn('"Connect with Lantern once, then pick a server here"', STRINGS)
        self.assertIn(
            'subtitle = if (servers.isEmpty()) {', UI
        )


if __name__ == "__main__":
    unittest.main()
