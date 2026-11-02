from pathlib import Path
import unittest

ROOT = Path(__file__).parents[1]
SERVER = ROOT / "app/src/main/java/com/msnguard/vpn/foxy/ServerListClient.kt"
TOKENS = ROOT / "app/src/main/java/com/msnguard/vpn/foxy/FxoTokenStore.kt"
UI = ROOT / "app/src/main/java/com/msnguard/vpn/MainActivity.kt"


class FoxyReferenceParityContract(unittest.TestCase):
    def test_server_list_is_bounded_validated_and_cached(self):
        text = SERVER.read_text()
        for marker in (
            "MAX_REMOTE_BYTES",
            "MAX_CACHE_AGE_MS",
            "readBounded",
            "validHost",
            "validPort",
            "distinctByStable",
            "MAX_COUNTRIES",
            "MAX_SERVERS_PER_CITY",
        ):
            self.assertIn(marker, text)
        self.assertIn("byteStream().use", text)
        self.assertIn("file.lastModified()", text)

    def test_token_storage_has_epoch_and_explicit_write_error(self):
        text = TOKENS.read_text()
        self.assertIn("KEY_SESSION_EPOCH", text)
        self.assertIn("sessionEpoch", text)
        self.assertIn("commit()", text)
        self.assertIn("StorageException", text)

    def test_visible_login_is_browser_only(self):
        text = UI.read_text()
        self.assertIn('Strings.t("Sign in with Firefox")', text)
        self.assertNotIn('Strings.t("Send Code")', text)
        self.assertNotIn('Strings.t("Password")', text)
        self.assertNotIn('Strings.t("Verification code")', text)


if __name__ == "__main__":
    unittest.main()
