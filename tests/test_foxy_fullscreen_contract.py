import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOGIN = (ROOT / 'app/src/main/java/com/msnguard/vpn/foxy/FoxyBrowserLogin.kt').read_text()
MAIN = (ROOT / 'app/src/main/java/com/msnguard/vpn/MainActivity.kt').read_text()

class FoxyFullscreenContract(unittest.TestCase):
    def test_login_is_activity_page_not_popup(self):
        self.assertNotIn('AlertDialog', LOGIN)
        self.assertNotIn('dialog.show()', LOGIN)
        self.assertIn('host.addView(page, ViewGroup.LayoutParams(-1, -1))', LOGIN)
        self.assertIn('LinearLayout.LayoutParams(-1, 0, 1f)', LOGIN)

    def test_native_ime_ownership_and_cleanup(self):
        self.assertNotIn('SOFT_INPUT_STATE_ALWAYS_VISIBLE', LOGIN)
        self.assertNotIn('showSoftInput', LOGIN)
        self.assertIn('WindowInsets.Type.ime()', LOGIN)
        self.assertIn('setSoftInputMode(oldSoftInputMode)', LOGIN)
        self.assertIn('host.removeView(page)', LOGIN)
        self.assertIn('FoxyBrowserLogin.close()', MAIN)
        self.assertIn('FoxyBrowserLogin.handleBack()', MAIN)

    def test_auth_path_preserved(self):
        for symbol in ['completeBrowserLogin(token)',
                       'addJavascriptInterface(bridge, "foxyWebChannel")',
                       'cookieJar.syncFromWebView()', 'web.canGoBack()']:
            self.assertIn(symbol, LOGIN)

if __name__ == '__main__':
    unittest.main()
