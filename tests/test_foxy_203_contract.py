from pathlib import Path
import json
import subprocess
import unittest

ROOT = Path(__file__).parents[1]
FOXY = ROOT / 'app/src/main/java/com/msnguard/vpn/foxy'

class Foxy203Contract(unittest.TestCase):
    def test_javascript_bridge_executes_with_correlated_object_reply(self):
        source = (FOXY / 'FoxyBrowserLogin.kt').read_text()
        hook = source.split('private val HOOK = """', 1)[1].split('"""', 1)[0]
        fixture = '''
const assert = require('assert');
const listeners = {}; const sent = []; const replies = [];
global.window = {location:{hostname:'accounts.firefox.com',href:'https://accounts.firefox.com/'},
 addEventListener:(k,f)=>listeners[k]=f,dispatchEvent:e=>replies.push(e.detail)};
global.document = {addEventListener:()=>{},dispatchEvent:e=>replies.push(e.detail)};
global.CustomEvent = function(k,o){return o};
global.foxyWebChannel = {onMessage:(p,o)=>sent.push([JSON.parse(p),o])};
'''
        fixture += hook + '''
listeners.WebChannelMessageToChrome({detail:JSON.stringify({id:'account_updates',message:{command:'fxaccounts:login',messageId:'42',data:{sessionToken:'abc'}}})});
assert.equal(sent.length,1); assert.equal(sent[0][0].message.messageId,'42');
window.__foxyReply('account_updates','42','fxaccounts:login',{ok:true});
assert.equal(replies[0].message.messageId,'42'); assert.deepEqual(replies[0].message.data,{ok:true});
console.log('WebChannel fixture passed');
'''
        result = subprocess.run(['node', '-e', fixture], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_callback_deduplication_uses_dispatched_token(self):
        source = (FOXY / 'FoxyBrowserLogin.kt').read_text()
        notify = source.split('private fun notifySessionToken', 1)[1].split('private fun reply', 1)[0]
        self.assertIn('token == dispatchedSessionToken', notify)
        self.assertNotIn('token == pendingSessionToken', notify)
        self.assertIn('loginScope.cancel()', source)
        self.assertIn('if (result.isSuccess) finish(result)', source)
        self.assertNotIn('Thread {', source)

    def test_control_plane_uses_reference_system_dns_default(self):
        source = (FOXY / 'FxoControlPlaneHttp.kt').read_text()
        self.assertIn('.dns(okhttp3.Dns.SYSTEM)', source)
        self.assertIn('DIRECT_SYSTEM', source)
        self.assertNotIn('.dns(bootstrapDoh)', source)

    def test_verification_exits_immediately_and_refresh_has_fastly_fallback(self):
        source = (FOXY / 'FxaAuth.kt').read_text()
        complete = source.split('private suspend fun completeLogin', 1)[1].split('private suspend fun exchangeSession', 1)[0]
        self.assertIn('0 until 100', complete)
        self.assertIn('verified = true; break', complete)
        self.assertIn('delay(3000L)', complete)
        refresh = source.split('suspend fun ensureFreshAccessToken', 1)[1].split('suspend fun currentAccessToken', 1)[0]
        self.assertIn('catch (_: FastlyBlockedException)', refresh)
        self.assertIn('endpoints.controlPlane.oauthFallback', refresh)
        self.assertNotIn('FXA_OAUTH_SERVER', source)

if __name__ == '__main__':
    unittest.main()
