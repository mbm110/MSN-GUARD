from pathlib import Path
import unittest

ROOT = Path(__file__).parents[1]
FOXY = ROOT / "app/src/main/java/com/msnguard/vpn/foxy"

class Foxy202Contract(unittest.TestCase):
    def test_control_plane_uses_shared_headers_and_http2_doh(self):
        http = (FOXY / "FxoControlPlaneHttp.kt").read_text()
        auth = (FOXY / "FxaAuth.kt").read_text()
        solver = (FOXY / "FxoFastlyChallengeSolver.kt").read_text()
        self.assertIn("DnsOverHttps", http)
        self.assertIn("Protocol.HTTP_2", http)
        self.assertIn("FirefoxAccountHeaders.apply", auth)
        self.assertIn("FirefoxAccountHeaders.controlPlaneUserAgent", auth)
        self.assertIn("FirefoxAccountHeaders.apply", solver)

    def test_406_refresh_and_offline_server_cache(self):
        auth = (FOXY / "FxaAuth.kt").read_text()
        guardian = (FOXY / "GuardianClient.kt").read_text()
        servers = (FOXY / "ServerListClient.kt").read_text()
        remote = (FOXY / "FoxyRemoteConfig.kt").read_text()
        self.assertGreaterEqual(auth.count("response.code == 406"), 1)
        self.assertIn("FoxyRemoteConfig.triggerRefresh()", auth)
        self.assertIn("FoxyRemoteConfig.triggerRefresh()", guardian)
        self.assertIn("using verified local cache", servers)
        self.assertIn("tempFile", remote)
        self.assertIn("FALLBACK_URL", remote)

    def test_webchannel_preserves_upstream_envelope_and_mobile_browser_ua(self):
        login = (FOXY / "FoxyBrowserLogin.kt").read_text()
        headers = (FOXY / "FirefoxAccountHeaders.kt").read_text()
        self.assertIn("val channelId = envelope.optString(\"id\").ifBlank { CHANNEL_ID }", login)
        self.assertIn("data: data", login)
        self.assertIn("settings.userAgentString = FirefoxAccountHeaders.browserUserAgent", login)
        self.assertIn("Mozilla/5.0 (Android $release; Mobile; rv:159.0)", headers)
        self.assertIn("JSON.parse(d)", login.split("private val HOOK", 1)[1])
        self.assertIn("data: data", login.split("window.__foxyReply", 1)[1])

    def test_browser_login_uses_verified_session_and_pkce_authorization_code(self):
        auth = (FOXY / "FxaAuth.kt").read_text()
        self.assertIn("recovery_email/status", auth)
        self.assertIn("isSessionVerified(sessionToken)", auth)
        self.assertIn('put("response_type", "code")', auth)
        self.assertIn('put("code_challenge_method", "S256")', auth)
        self.assertIn('put("grant_type", "authorization_code")', auth)
        self.assertIn('"/oauth/authorization"', auth)
        self.assertIn('"/token"', auth)
        browser = (FOXY / "FoxyBrowserLogin.kt").read_text()
        self.assertNotIn("onOAuthResult", browser)
        self.assertNotIn("api.accounts.firefox.com/v1/oauth/token", browser)

    def test_runtime_config_is_initialized_before_login_and_service_start(self):
        login = (FOXY / "FoxyBrowserLogin.kt").read_text()
        service = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()
        self.assertIn("FoxyRemoteConfig.init(activity.applicationContext)", login)
        self.assertIn("FoxyRemoteConfig.init(applicationContext)", service)

if __name__ == "__main__":
    unittest.main()
