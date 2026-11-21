"""Contract: Radiance's locale must encode WHERE the device is, not its UI
language (3.3.2 fix, correcting the 3.2.52 attempt).

Field log 3.3.1 (Lantern session, 20 minutes): mid-session the connection
stalled repeatedly — Telegram and sites stopped loading while the dial stayed
Connected — then DNS lookups inside Radiance died with
`lookup failed for [domain]: (exchange6: EOF | exchange4: EOF)` and the
watchdog finally tore the session down ("3 consecutive failed pbs").

Root cause, code-verified in Radiance (vpn/dnsoptions.go): sing-box's
direct-path DNS server is chosen purely from the LOCALE STRING Radiance is
started with — fa-IR (or any IR/CN locale) means AliDNS (reachable from
Iranian carriers), ru means Yandex, anything else means Quad9 DoH
9.9.9.9:443, which Iranian DPI resets. There is NO IP-geo detection in that
path. The sidecar hardcoded Locale "en", so every direct-outbound lookup
rode DoH to Quad9 and died — the exact EOF cascade in the log.

The first fix forwarded the DEVICE LOCALE. The field user corrected it:
their menus are English while they stand in Tehran, so the locale string
would still select Quad9. The locale passed to Radiance must encode the
device's COUNTRY: in Iran (detected from the radio — SIM / registered
network country, Tehran timezone for SIM-less devices) the engine passes
fa-IR so AliDNS is chosen; anywhere else the device locale is passed
unchanged, giving the non-Iran behavior.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
BRIDGE = ROOT / "core/lanternbridge"

ENGINE_KT = (APP / "LanternEngine.kt").read_text()
BRIDGE_GO = (BRIDGE / "bridge.go").read_text()
SIDECAR_GO = (BRIDGE / "cmd/lanternsidecar" / "main.go").read_text()


class LanternLocaleContract(unittest.TestCase):
    def test_iran_comes_from_the_radio_not_the_menu_language(self):
        # A phone with English menus and an Iranian SIM is still in Iran:
        # SIM / registered-network country first, Tehran timezone only when
        # no radio answer exists at all (tablets on Wi-Fi).
        self.assertIn("private fun isInIran(context: Context): Boolean", ENGINE_KT)
        self.assertIn("tm?.simCountryIso?.trim()?.uppercase()", ENGINE_KT)
        self.assertIn("tm?.networkCountryIso?.trim()?.uppercase()", ENGINE_KT)
        self.assertIn('if (sim == "IR" || network == "IR")', ENGINE_KT)
        self.assertIn('TimeZone.getDefault().id == "Asia/Tehran"', ENGINE_KT)

    def test_the_locale_passed_encodes_the_country(self):
        # In Iran: fa-IR, which Radiance normalizes to FAIR and maps to
        # AliDNS. Anywhere else: the device locale unchanged (Quad9's path).
        self.assertIn("val radianceLocale = if (isInIran(context)) {", ENGINE_KT)
        self.assertIn('"fa-IR"', ENGINE_KT)
        self.assertIn("java.util.Locale.getDefault().toLanguageTag()", ENGINE_KT)
        self.assertIn('"--locale", radianceLocale,', ENGINE_KT)

    def test_the_sidecar_accepts_and_passes_the_locale(self):
        self.assertIn('locale := flag.String("locale", ""', SIDECAR_GO)
        self.assertIn(
            "lanternbridge.Init(*dataDir, *logDir, *socksAddress, *locale)",
            SIDECAR_GO,
        )

    def test_the_bridge_no_longer_hardcodes_english(self):
        # The hardcoded "en" selected Quad9 DoH for every direct-path lookup.
        self.assertIn(
            "func Init(dataDir, logDir, socksAddress, locale string) error",
            BRIDGE_GO,
        )
        self.assertIn("Locale:                  locale,", BRIDGE_GO)
        self.assertNotIn('Locale:                  "en",', BRIDGE_GO)

    def test_no_other_transport_is_touched(self):
        # The fix is confined to the Lantern sidecar plumbing: no warp,
        # masque, psiphon, tor, shard or foxy env or engine change rides along.
        self.assertIn("RADIANCE_USE_SOCKS_PROXY", BRIDGE_GO)
        self.assertIn('socksAddress = "127.0.0.1:1831"', BRIDGE_GO)


if __name__ == "__main__":
    unittest.main()
