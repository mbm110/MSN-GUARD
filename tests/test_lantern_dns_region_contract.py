#!/usr/bin/env python3
"""Contract: the Lantern DNS region setting (3.3.3) is real, not cosmetic.

The locale string the sidecar is started with IS the DNS choice — verified in
Radiance's vpn/dnsoptions.go: FAIR/ZHCN/CN/IR → AliDNS 223.5.5.5, RU/RURU →
Yandex 77.88.8.8, anything else → Quad9 DoH 9.9.9.9 (which Iranian DPI resets,
the 3.3.1 EOF cascade). There is no IP-geo detection in that path, and the
reference project defines exactly these three families — no Europe/America/
Asia variants — so the manual setting offers Iran (default), Auto (the 3.3.2
radio detection), Russia and International.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "app/src/main/java/com/msnguard/vpn"
CORE = (APP / "CoreConfig.kt").read_text()
ENGINE = (APP / "LanternEngine.kt").read_text()
UI = (APP / "MainActivity.kt").read_text()
STRINGS = (APP / "Strings.kt").read_text()
RUSSIAN = (APP / "RussianStrings.kt").read_text()
RADIANCE = pathlib.Path(
    "/root/.hermes/cache/scratch/radiance-src/vpn/dnsoptions.go"
)


class LanternDnsRegionContract(unittest.TestCase):
    def test_the_setting_maps_to_a_real_radiance_locale(self):
        # The stored coreName decides the --locale the sidecar starts with:
        # iran → fa-IR (AliDNS), russia → ru-RU (Yandex), international →
        # en-US (Quad9), auto → the 3.3.2 radio detection.
        self.assertIn('const val LANTERN_DNS_REGION = "lantern_dns_region"', CORE)
        self.assertIn(
            'getString(LANTERN_DNS_REGION, "iran")', CORE
        )
        self.assertIn(
            'val radianceLocale = when (CoreConfig.lanternDnsRegion(context)) {',
            ENGINE,
        )
        self.assertIn('"russia" -> "ru-RU"', ENGINE)
        self.assertIn('"international" -> "en-US"', ENGINE)
        # Auto keeps the radio detection; the forced regions must NOT depend
        # on the radio — a forced choice is a forced choice.
        self.assertIn('"auto" -> if (isInIran(context)) {', ENGINE)

    def test_the_radiance_source_backs_the_mapping(self):
        # The reference's actual DNS table, quoted so a future Radiance bump
        # that renames the families fails here loudly instead of silently
        # turning the setting cosmetic.
        self.assertTrue(RADIANCE.exists(), "radiance source copy missing")
        src = RADIANCE.read_text()
        self.assertIn('"FAIR": {}', src)
        self.assertIn('"ZHCN": {}', src)
        self.assertIn('aliDNS    = "223.5.5.5"', src)
        self.assertIn('yandexDNS = "77.88.8.8"', src)
        self.assertIn('quad9DNS  = "9.9.9.9"', src)
        # IR is an AliDNS locale, so fa-IR really reaches the AliDNS branch.
        self.assertIn('normalizedLocale == "RU" || normalizedLocale == "RURU"', src)

    def test_the_chooser_offers_only_real_options(self):
        # Iran default, Auto = the 3.3.2 detection, plus the two other real
        # DNS families. No invented Europe/America/Asia entries.
        self.assertIn("private enum class LanternDnsRegion", UI)
        for entry in (
            'IRAN("Iran", "iran",',
            'AUTO("Auto (SIM detection)", "auto",',
            'RUSSIA("Russia (Yandex DNS)", "russia",',
            'INTERNATIONAL("International (Quad9)", "international",',
        ):
            self.assertIn(entry, UI)
        self.assertNotIn('"europe"', UI)
        self.assertNotIn('"america"', UI)
        # The pref write goes through the enum's coreName, never an index.
        self.assertIn(
            "putString(CoreConfig.LANTERN_DNS_REGION, chosen.coreName)", UI
        )

    def test_the_row_lives_in_the_lantern_section(self):
        self.assertIn("private var lanternDnsRow: OrbitSettingsRow? = null", UI)
        self.assertIn('navRow(Strings.t("Lantern DNS"), lanternDnsChoice().label)', UI)
        self.assertIn("private fun chooseLanternDns(", UI)
        # Takes-effect wording, because it does not take effect now.
        self.assertIn("applies next connection", UI)

    def test_strings_exist_in_every_locale_column(self):
        for key in (
            "Lantern DNS",
            "The DNS the Lantern tunnel resolves through · applies next connection",
            "Iran",
            "Auto (SIM detection)",
            "Russia (Yandex DNS)",
            "International (Quad9)",
        ):
            self.assertIn(f'"{key}" to Triple(', STRINGS)
            self.assertIn(f'"{key}" to "', RUSSIAN)


if __name__ == "__main__":
    unittest.main()
