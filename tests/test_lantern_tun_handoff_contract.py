#!/usr/bin/env python3
"""Contract: the Lantern TUN handoff (3.4.0) is real, not cosmetic.

The official Lantern app runs the engine with its real TUN inbound: the app's
VpnService.establish() fd reaches sing-tun through the gomobile OpenTun hook.
MSN's sidecar is a separate process, so the fd crosses the boundary over a
private Unix socket with SCM_RIGHTS and the bridge's OpenTun serves a fresh
dup of the master per tunnel (re)start — sing-tun closes its copy, restarts
ask again, so a raw fd would come back closed.

The Hev+SOCKS bridge (novpn build) is REMOVED from the Lantern path — Hev
still fronts every other method untouched. With one box owning DNS, routing
and fake-IP, the cross-engine fake-IP mismatch ("missing fakeip record") and
the DNS round-trip class are structurally gone.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "core/lanternbridge"
HANDOFF = (BRIDGE / "handoff.go").read_text()
PLATFORM = (BRIDGE / "android_platform.go").read_text()
MAIN = (BRIDGE / "cmd/lanternsidecar/main.go").read_text()
BUILD_SH = (BRIDGE / "build-android.sh").read_text()
KOTLIN = ROOT / "app/src/main/java/com/msnguard/vpn"
ENGINE = (KOTLIN / "LanternEngine.kt").read_text()
SERVICE = (KOTLIN / "MsnGuardVpnService.kt").read_text()


class LanternTunHandoffContract(unittest.TestCase):
    def test_the_sidecar_builds_the_real_tun_inbound(self):
        # novpn must be gone from the build tags: baseInbounds returns the
        # tun-in + bypass + tunnel-proxy inbounds of the official app.
        self.assertNotIn('TAGS="novpn', BUILD_SH)
        self.assertIn('TAGS="with_gvisor', BUILD_SH)

    def test_the_handoff_socket_serves_scm_rights(self):
        self.assertIn("tun-handoff.sock", MAIN)
        self.assertIn("ReadMsgUnix", MAIN)
        self.assertIn("unix.ParseSocketControlMessage", MAIN)
        self.assertIn("unix.ParseRights", MAIN)
        self.assertIn("lanternbridge.SetTunFd", MAIN)

    def test_opentun_serves_a_fresh_dup_per_tunnel(self):
        self.assertIn("func (p *androidPlatform) OpenTun(options box.TunOptions) (int32, error)", PLATFORM)
        self.assertIn("openTunFd()", PLATFORM)
        self.assertIn("func openTunFd() (int, error) {", HANDOFF)
        # The master outlives every tunnel restart; each OpenTun dups.
        self.assertIn("syscall.Dup(fd)", HANDOFF)

    def test_the_app_hands_off_before_connect_and_runs_no_hev(self):
        self.assertIn("fun handoffTun(context: Context, fd: ParcelFileDescriptor)", ENGINE)
        self.assertIn("setFileDescriptorsForSend(arrayOf(fd.fileDescriptor))", ENGINE)
        handoff_idx = SERVICE.index("LanternEngine.handoffTun(this, establishedTun)")
        connect_idx = SERVICE.index("LanternEngine.connect(this, attempt)")
        self.assertLess(handoff_idx, connect_idx)
        # The Hev bridge is gone from the Lantern path...
        lantern = SERVICE[SERVICE.index("private fun startLanternTunnel()"):]
        lantern = lantern[: lantern.index("private fun startLanternTrafficPolling()")]
        self.assertNotIn("HevEngine.start", lantern)
        # ...but the shared tun2socks engine registry still fronts every
        # other method (the dispatch is untouched outside startLanternTunnel).
        self.assertIn("TunEnginePref.HEV", SERVICE)

    def test_the_engine_address_plan_is_the_official_one(self):
        # tunPrefix4/tunPrefix6 from radiance vpn/boxoptions_default.go.
        lantern = SERVICE[SERVICE.index("private fun startLanternTunnel()"):]
        lantern = lantern[: lantern.index("private fun startLanternTrafficPolling()")]
        self.assertIn('"10.10.1.1"', lantern)
        self.assertIn('"fdfe:dcba:9876::1"', lantern)
        # Outside 198.18.0.0/15 (the fake range rejects unknown destinations)
        # and outside the TUN's own subnet.
        self.assertIn('"172.19.0.2"', lantern)
        self.assertNotIn("MAP_DNS_ADDRESS", lantern)

    def test_probes_ride_the_engines_own_tunnel_proxy(self):
        # Radiance's TunnelProxyAddr (127.0.0.1:14986) — the inbound the
        # official app uses from its UI process. The watchdog's port check
        # and the UI probes keep working through it.
        self.assertIn("const val SOCKS_PORT = 14986", ENGINE)

    def test_the_watchdog_no_longer_demands_tun2socks_for_lantern(self):
        idx = SERVICE.index("val needsRouting = psiphonVpnMode")
        # Only the two-line needsRouting expression: LANTERN must be absent
        # from it, while the Lantern-specific health checks that follow stay.
        end = SERVICE.index("if (needsRouting &&", idx)
        expr = SERVICE[idx:end]
        self.assertNotIn("LANTERN", expr)


if __name__ == "__main__":
    unittest.main()
