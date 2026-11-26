from pathlib import Path
import unittest

ROOT = Path(__file__).parents[1]
FOXY = ROOT / "app/src/main/java/com/msnguard/vpn/foxy"

class Foxy202Contract(unittest.TestCase):
    """Pins as of Foxy 2.0.3: the 202 tests originally pinned the bootstrap-DoH
    chain and a hardcoded rv:159 UA. The v3.2.27 audit REMOVED the dead DoH code
    (the client uses Dns.SYSTEM directly) and FirefoxAccountHeaders moved to a
    major-version-derived UA — both deliberate product changes the old pins
    fought. The pins now assert what the code intends TODAY: system DNS only,
    HTTP/2 kept, and the UA template dynamic."""
    def test_control_plane_uses_system_dns_and_http2(self):
        http = (FOXY / "FxoControlPlaneHttp.kt").read_text()
        auth = (FOXY / "FxaAuth.kt").read_text()
        solver = (FOXY / "FxoFastlyChallengeSolver.kt").read_text()
        self.assertIn(".dns(okhttp3.Dns.SYSTEM)", http)
        self.assertIn("Protocol.HTTP_2", http)
        self.assertIn("DIRECT_SYSTEM", http)
        # the whole point of the v3.2.27 audit: the dead DoH path stays dead.
        # Comments may NAME bootstrapDoh (explaining its removal); code may
        # not call it. Strip comments, then forbid the call.
        code_lines = [l.split("//")[0] for l in http.splitlines()]
        code = "\n".join(code_lines)
        self.assertNotIn(".dns(bootstrapDoh)", code)
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
        # 2.0.3: the UA is derived from the running major version, not the
        # hardcoded rv:159 the old pin wanted.
        self.assertIn("Mobile; rv:$major.0", headers)
        self.assertIn("JSON.parse(d)", login.split("private val HOOK", 1)[1])
        self.assertIn("data: data", login.split("window.__foxyReply", 1)[1])

    def test_browser_login_uses_verified_session_and_pkce_authorization_code(self):
        auth = (FOXY / "FxaAuth.kt").read_text()
        self.assertIn("endpoints.controlPlane.recoveryStatus.toHttpUrl()", auth)
        self.assertIn("isSessionVerified(sessionToken)", auth)
        self.assertIn('put("response_type", "code")', auth)
        self.assertIn('put("code_challenge_method", "S256")', auth)
        self.assertIn('put("grant_type", "authorization_code")', auth)
        self.assertIn("endpoints.controlPlane.authorization", auth)
        self.assertIn("endpoints.controlPlane.oauthToken", auth)
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
