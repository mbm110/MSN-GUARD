from pathlib import Path
import unittest

MAIN = (Path(__file__).resolve().parents[1] / 'app/src/main/java/com/msnguard/vpn/MainActivity.kt').read_text()


def section(start, end):
    return MAIN.split(start, 1)[1].split(end, 1)[0]


class IpLookupStateContract(unittest.TestCase):
    def test_connecting_invalidates_both_workers_and_pending_retry(self):
        text = section('private fun showConnectionProgress(', 'private fun showConnected(')
        for marker in ['exitLookupAllowed = false', 'ipRequest++', 'countryRequest++',
                       'ipRefreshPending = false', 'removeCallbacks(ipRetryRunnable)']:
            self.assertIn(marker, text)

    def test_only_stable_states_enable_lookup(self):
        for name, end in [('showConnected', 'showDegraded'), ('showDisconnected', 'startSessionTimer')]:
            self.assertIn('exitLookupAllowed = true', section('private fun '+name+'(', 'private fun '+end+'('))
        self.assertIn('if (!exitLookupAllowed)', section('private fun refreshPublicIp(', 'private fun fetchPublicIp('))
        self.assertIn('if (ip.isBlank() || !exitLookupAllowed) return', MAIN)

    def test_retries_and_each_endpoint_check_request_generation(self):
        ip = section('private fun refreshPublicIp(', 'private fun fetchPublicIp(')
        self.assertIn('check(exitLookupAllowed && request == ipRequest)', ip)
        self.assertIn('check(allowed())', section('private fun fetchPublicIp(', 'private fun resolveExitCountry('))
        self.assertIn('if (!allowed()) return null', section('private fun fetchCountryFor(', '// The four main-screen'))
        self.assertIn('exitLookupAllowed && request == countryRequest', MAIN)

if __name__ == '__main__':
    unittest.main()
