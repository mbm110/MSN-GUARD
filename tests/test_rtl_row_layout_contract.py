import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
V = ROOT / "app/src/main/java/com/msnguard/vpn"
MAIN = (V / "MainActivity.kt").read_text()
ORBIT = (V / "OrbitSettings.kt").read_text()
CARDS = (V / "OrbitCards.kt").read_text()
GOOL = (V / "GoolCard.kt").read_text()
MIM = (V / "MimCard.kt").read_text()
SPLIT = (V / "SmartSplitCard.kt").read_text()


class RtlRowLayoutContract(unittest.TestCase):
    """3.4.25 RTL ROW RULE — the screenshots' bug, pinned forever.

    In Persian the row titles floated in the MIDDLE of their boxes and the
    values sat at the physical right edge — because no shared row component
    pinned its texts to the START/END edges, and gaps used physical
    leftMargin/rightMargin which do not flip in RTL.

    THE RULE (user's exact words): title at the START edge, value at the END
    edge; START/END follow the locale (fa: title right / value left; en/zh/ru:
    title left / value right); texts touch the edges, NEVER centered; only
    START/END gravity and start/end margins — never LEFT/RIGHT, never CENTER
    for row texts. English must stay pixel-identical (START == LEFT there).

    Applied in the SHARED components so every screen inherits it:
    OrbitSettingsRow (every settings-list row), OrbitToggleRow (every toggle
    row + the switch thumb's RTL position), foxyInfoRow (Foxy connection
    rows), the choice-sheet option rows, and the five home cards
    (GoolCard/MimCard/SmartSplitCard/ChainModeCard/ExitNodeCard)."""

    # ── OrbitSettingsRow: every settings page row ──
    def test_settings_row_title_start_value_end(self):
        self.assertIn("gravity = Gravity.START", ORBIT)
        self.assertIn("textAlignment = TEXT_ALIGNMENT_VIEW_START", ORBIT)
        self.assertIn("gravity = Gravity.END", ORBIT)
        self.assertIn("textAlignment = TEXT_ALIGNMENT_VIEW_END", ORBIT)

    def test_settings_row_value_caps_at_half_and_keeps_gap(self):
        # QOBEAR PATTERN (3.4.26): the value is WRAP_CONTENT pinned to the END
        # edge — the title's weight pushes it there. A half-width weight made
        # long Persian values wrap to 2 lines and GROW the row height (the
        # field report: "why did you make the buttons taller").
        self.assertIn(
            "addView(valueView, LayoutParams(\n"
            "            ViewGroup.LayoutParams.WRAP_CONTENT,\n"
            "            ViewGroup.LayoutParams.WRAP_CONTENT,\n"
            "        ).apply { marginStart = dp(10) })", ORBIT)
        self.assertIn("marginStart = dp(10)", ORBIT)

    # ── OrbitToggleRow: the switch must mirror too ──
    def test_toggle_thumb_flips_with_layout_direction(self):
        self.assertIn("layoutDirection == LAYOUT_DIRECTION_RTL", ORBIT)
        block = ORBIT[ORBIT.find("private fun restingThumbX"):ORBIT.find("private fun renderSwitch")]
        self.assertIn("if (rtl) thumbInset.toFloat()", block,
                      "ON must sit at the row's END side in RTL")

    def test_toggle_title_and_subtitle_pin_start(self):
        # OrbitSettingsRow title+value, OrbitToggleRow title+subtitle = 4 sites
        self.assertGreaterEqual(ORBIT.count("gravity = Gravity.START"), 3)

    # ── foxyInfoRow: the Foxy connection rows from the screenshots ──
    def test_foxy_info_row_pins_title_start_value_end(self):
        block = MAIN[MAIN.find("private fun foxyInfoRow"):MAIN.find("/** A country code")]
        self.assertIn("gravity = Gravity.START", block)
        self.assertIn("TEXT_ALIGNMENT_VIEW_START", block)
        self.assertIn("gravity = Gravity.END", block)
        self.assertIn("TEXT_ALIGNMENT_VIEW_END", block)
        self.assertIn("marginStart = dp(12)", block)

    # ── choice sheets ──
    def test_choice_sheet_option_pins_start(self):
        # both sheet families: the generic choice sheet and the language picker
        self.assertGreaterEqual(MAIN.count("val optionTitle = label"), 2)
        for i, site in enumerate([m.start() for m in __import__("re").finditer(r"val optionTitle = label", MAIN)]):
            block = MAIN[site:site + 700]
            self.assertIn("gravity = Gravity.START", block, f"optionTitle site {i} not START-pinned")
            self.assertIn("TEXT_ALIGNMENT_VIEW_START", block, f"optionTitle site {i} not START-aligned")

    def test_choice_sheet_subtitle_and_indicator_use_start_margins(self):
        self.assertIn("marginStart = dp(48)", MAIN)
        self.assertGreaterEqual(MAIN.count("marginStart = dp(12)"), 5,
                                "the indicator gaps must be start-side")

    # ── the five home cards ──
    def test_cards_pin_title_start_and_use_directional_gaps(self):
        for name, src in [("GoolCard", GOOL), ("MimCard", MIM),
                         ("SmartSplitCard", SPLIT), ("ChainModeCard", CARDS)]:
            self.assertIn("gravity = Gravity.START", src, f"{name} title not START-pinned")
            self.assertIn("TEXT_ALIGNMENT_VIEW_START", src, f"{name} title not START-aligned")
            self.assertIn("marginStart = px(11)", src, f"{name} gap not start-side")
            self.assertNotIn("leftMargin = px(11)", src, f"{name} still physical")

    def test_cards_fa_tracking_zeroed(self):
        for name, src in [("GoolCard", GOOL), ("MimCard", MIM),
                         ("SmartSplitCard", SPLIT), ("ChainModeCard", CARDS)]:
            self.assertIn('if (AppLanguage.current() == "fa") 0f else spacing(0.1f)', src,
                          f"{name} title still tracks Persian")

    # ── 3.4.25 second sweep: the components the first pass missed ──
    def test_exit_node_card_texts_pin_start(self):
        block = CARDS[CARDS.find("class ExitNodeCard"):CARDS.find("fun render(")]
        # all three texts (key/ip/loc) START-pinned
        self.assertGreaterEqual(block.count("gravity = Gravity.START"), 3)

    def test_mode_option_pins_title_start_and_badge_end(self):
        block = MAIN[MAIN.find("private fun createModeOption"):]  # last fun of the group
        self.assertIn("gravity = Gravity.START", block)
        self.assertIn("TEXT_ALIGNMENT_VIEW_START", block)
        self.assertGreaterEqual(block.count("gravity = Gravity.END"), 2,
                                "CURRENT/DESKTOP ONLY badges must pin END")

    def test_section_headers_use_directional_gaps(self):
        raw = (V / "ExpandableSection.kt").read_text()
        # comments may NAME the banned API while explaining why we don't use it
        code = "\n".join(l.split("//")[0] for l in raw.splitlines())
        self.assertIn("marginEnd = dp(9)", code)   # tick gap
        self.assertIn("marginEnd = dp(7)", code)   # brand mark gap
        self.assertIn("marginStart = dp(8)", code) # chevron gap
        self.assertNotIn("leftMargin", code)
        self.assertNotIn("rightMargin", code)

    def test_metric_tile_unit_gap_is_start_side(self):
        VIEWS = (V / "OrbitViews.kt").read_text()
        self.assertIn("marginStart = context.px(3)", VIEWS)
        self.assertIn("?.marginStart ?: 0", VIEWS)
        self.assertNotIn("leftMargin", VIEWS)

    # ── no physical row margins survive in the shared components ──
    def test_no_physical_margins_left_in_shared_rows(self):
        # MainActivity: only the dial's symmetric negative bleed remains
        self.assertEqual(MAIN.count("leftMargin"), 1, "physical leftMargin outside the dial bleed")
        self.assertEqual(MAIN.count("rightMargin"), 1, "physical rightMargin outside the dial bleed")
        for name, src in [("OrbitSettings", ORBIT), ("OrbitCards", CARDS),
                          ("GoolCard", GOOL), ("MimCard", MIM), ("SmartSplitCard", SPLIT)]:
            self.assertNotIn("leftMargin", src, f"physical margin left in {name}")
            self.assertNotIn("rightMargin", src, f"physical margin left in {name}")


if __name__ == "__main__":
    unittest.main()


class QobearRtlPatternContract(unittest.TestCase):
    """3.4.26: the two REAL roots behind 'nothing changed in Persian'.

    Learned from the reference project (QobearVPN, github.com/Qorvhex/
    QobearVPN) — mined, not cloned:

    1. android:supportsRtl="true" in the Manifest (theirs: line 25 of
       AndroidManifest.xml). WITHOUT it the framework resolves START/END
       and start/end margins as LEFT/RIGHT no matter what the views say,
       so every gravity change is a no-op in Persian — the reason the
       previous sweep 'did nothing' on the device.
    2. Rows are SpaceBetween-shaped: title weight(1f) at the START edge,
       value WRAP_CONTENT pushed to the END edge, ONE line each — the
       row height never grows. Their typography: Vazirmatn
       regular/medium/bold, row titles 13sp/15sp regular-to-medium,
       values 11-13sp, lineHeight MULT ~1.2-1.45 — and MSN already ships
       Vazirmatn via Typefaces with the SAME compression idea
       (lineHeightMult 0.80 fa / 0.85 zh).
    3. The layout direction is chosen by the APP's language picker (theirs:
       LocalLayoutDirection provides Rtl iff language == FA), exactly the
       pattern MSN's pageHost/mainRoot already follow."""

    MANIFEST = (ROOT / "app/src/main/AndroidManifest.xml").read_text()
    THEME = (ROOT / "app/src/main/java/com/msnguard/vpn/Typefaces.kt").read_text()

    def test_supports_rtl_is_enabled(self):
        self.assertIn('android:supportsRtl="true"', self.MANIFEST,
                      "without supportsRtl every START/END pin is resolved "
                      "as LEFT/RIGHT — the whole RTL sweep was a no-op")

    def test_foxy_rows_keep_single_line_fixed_height(self):
        # both texts one-line: the row cannot grow (the 'taller buttons' bug)
        block = MAIN[MAIN.find("private fun foxyInfoRow"):
                     MAIN.find("private fun foxyFlag")]
        self.assertNotIn("maxLines = 2", block)
        self.assertIn("minimumHeight = dp(52)", block)

    def test_vazirmatn_line_height_compression_stays(self):
        # the reference app pairs Vazirmatn with ~1.37x headroom; MSN's
        # Typefaces already compress fa to 0.80 — pin it so nobody 'fixes'
        # the tight Persian rows by growing them again
        self.assertIn('"fa" -> 0.80f', self.THEME)
        self.assertIn('"zh" -> 0.85f', self.THEME)
