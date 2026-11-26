import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt").read_text()


class CoffeePopupContract(unittest.TestCase):
    """3.4.20: the first-run coffee popup. The user's spec, pinned:
    - a modern popup right after the first-run language choice,
    - EN/FA languages only; the ✕ behaves exactly like «بعداً»,
    - the author's Persian note, verbatim, never routed through Strings.t,
    - three Foxy-family ring buttons, each its own color, per the user's
      explicit palette: «یه قهوه مهمونم کن» GREEN, «بعداً» BLUE,
      «دیگه نشون نده» RED,
    - coffee → the browser opens daramet.com/MSN.GUARD and never show again,
    - بعداً → re-shows in 7 days (install-day arithmetic in preferences),
    - دیگه نشون نده → never again,
    - zero background work: no scheduler, no alarms, no receivers."""

    def popup_block(self) -> str:
        start = MAIN.find("private fun maybeShowCoffeePopup")
        self.assertGreater(start, 0, "popup entry function not found")
        end = MAIN.find("private fun chooseEgressRegion", start)
        block = MAIN[start:end]
        # Comments legitimately NAME the banned machinery to state we NOT use
        # it ("no JobScheduler…"). Only the CODE may not use it: strip comments.
        return "\n".join(l.split("//")[0] for l in block.splitlines())

    def test_shown_after_the_language_pick_and_not_under_the_sheet(self):
        lang = MAIN.find("showLanguagePickerOnce()")
        popup = MAIN.find("if (AppLanguage.hasChosen(this)) maybeShowCoffeePopup()")
        self.assertGreater(lang, 0)
        self.assertGreater(popup, lang, "the popup check must follow the language pick, behind hasChosen")

    def test_only_english_or_persian(self):
        self.assertIn('if (lang != "en" && lang != "fa") return', MAIN)

    def test_the_note_is_verbatim_and_persian_forever(self):
        for fragment in [
            "درود دوستان، بنده MSN-GUARD رو تنهایی ساختم",
            "همیشه رایگان بمونه",
            "☕ یه قهوه مهمونم کن",
            "مرسی که هستید.",
        ]:
            self.assertIn(fragment, MAIN)
            self.assertNotIn(f'Strings.t("{fragment}', MAIN,
                             "the popup copy went through Strings.t — it would be translated")

    def test_three_ring_buttons_with_the_exact_palette(self):
        for text, color in [
            ("یه قهوه مهمونم کن ☕", "0xFF27C93F"),   # GREEN ring
            ("بعداً", "palette.neonBlue"),              # BLUE ring
            ("دیگه نشون نده", "0xFFFF5F56"),          # RED ring
        ]:
            btn = MAIN.find(f'foxyActionButton("{text}", true)')
            self.assertGreater(btn, 0, f"button {text} missing")
            block = MAIN[btn:btn + 340]
            self.assertIn(color, block, f"button {text} lost its ring color")
            self.assertIn("roundedBackground(Color.TRANSPARENT, 10", block)

    def test_coffee_button_opens_daramet_and_records_never(self):
        btn = MAIN.find('foxyActionButton("یه قهوه مهمونم کن ☕", true)')
        block = MAIN[btn:btn + 700]
        self.assertIn('openLink("https://daramet.com/MSN.GUARD")', block)
        self.assertIn("COFFEE_POPUP_NEVER", block)

    def test_later_rearms_seven_days_in_plain_preferences(self):
        self.assertIn("COFFEE_POPUP_DUE_AT, System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000", MAIN)

    def test_no_background_work_in_the_popup_block(self):
        block = self.popup_block()
        for banned in ["JobScheduler", "AlarmManager", "WorkManager",
                       "setExact", "Receiver", "registerReceiver", "WakeLock"]:
            self.assertNotIn(banned, block, f"{banned} in the popup block — battery cost")

    def test_x_button_behaves_like_later(self):
        self.assertIn('closeX.setOnClickListener { dismissCoffeeAsLater(dialog) }', MAIN)
        self.assertIn("«بعداً» and the ✕: same behavior", MAIN)

    def test_never_is_permanent_and_back_dismiss_is_later(self):
        self.assertIn("COFFEE_POPUP_NEVER -> return", MAIN)
        self.assertIn("== COFFEE_POPUP_UNDECIDED) {\n                armCoffeePopupLater()", MAIN)


if __name__ == "__main__":
    unittest.main()
