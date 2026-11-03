from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FOXY = ROOT / 'app/src/main/java/com/msnguard/vpn/foxy'

class FoxyAutomaticContract(unittest.TestCase):
    def test_default_preserves_explicit_choice(self):
        text = (FOXY / 'FoxySettings.kt').read_text()
        self.assertIn('getInt(MULTIPLEX_PREF_KEY, 32)', text)

    def test_connect_measures_only_automatic_without_persisting_winner(self):
        text = (FOXY / 'FoxyTunnel.kt').read_text()
        selection = text.split('val chosen = FoxySettings.selectedCountryCode(context) ?: run {')[1].split('// The redial loops')[0]
        self.assertIn('FoxyCountryPing.measure', selection)
        self.assertIn('it.pingMs >= 0L', selection)
        self.assertIn('minByOrNull { it.pingMs }', selection)
        self.assertIn('candidatesForCountry(countries, chosen)', selection)
        self.assertNotIn('saveSelectedCountryCode', selection)
        self.assertNotIn('firstOrNull', selection)

    def test_probe_matches_connection_targets_and_protects_before_connect(self):
        text = (FOXY / 'FoxyCountryPing.kt').read_text()
        self.assertIn('ServerListClient.candidatesForCountry', text)
        self.assertLess(text.index('protector(socket)'), text.index('socket.connect('))
        self.assertIn('take(3)', text)
        self.assertIn('Semaphore(MAX_COUNTRIES_IN_FLIGHT)', text)

if __name__ == '__main__':
    unittest.main()
