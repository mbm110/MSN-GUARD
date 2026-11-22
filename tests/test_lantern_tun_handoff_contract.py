#!/usr/bin/env python3
"""Contract: the Lantern TUN handoff follows the REFERENCE openTun semantics.

The official app (getlantern/lantern, LanternVpnService) does NOT pre-establish
a TUN: sing-tun calls the platform's openTun(tunOptions) DURING the tunnel
start, the app builds the VpnService Builder from the ENGINE'S OWN options
(createVPNBuilder), closes the previous interface first, and returns
establish().fd. The 3.4.0–3.4.3 pre-staged push kept racing the sidecar boot
and — worse — ensureSidecar's armForStart() invalidated the connect attempt so
the worker silently bailed and the idle reaper killed the orphaned sidecar
240s later ("list-only sidecar idle 240s — stopping", no error, no progress).

3.4.4 implements the pull model across the process boundary: OpenTun
serializes the engine's TunOptions into an OPEN line, the relay forwards it to
the app's waiting handoff service, and the app mirrors createVPNBuilder with
the engine's own addresses/MTU/DNS/routes, establish()es and returns the fd
via SCM_RIGHTS. The connect path never re-arms its own attempt.
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
        self.assertNotIn('TAGS="novpn', BUILD_SH)
        self.assertIn('TAGS="with_gvisor', BUILD_SH)

    def test_the_engine_drives_the_tun_pull_model(self):
        # OpenTun serializes the ENGINE'S OWN options and pulls the fd.
        self.assertIn("func (p *androidPlatform) OpenTun(options box.TunOptions) (int32, error)", PLATFORM)
        self.assertIn("requestTun(payload, 120*time.Second)", PLATFORM)
        self.assertIn("GetInet4Address()", PLATFORM)
        self.assertIn("GetDNSServerAddress()", PLATFORM)
        # The rendezvous: OpenTun pushes, the relay pulls (reference timing).
        self.assertIn("func PullTunRequest(timeout time.Duration)", HANDOFF)
        self.assertIn("func requestTun(payload []byte, timeout time.Duration) (int, error)", HANDOFF)
        self.assertNotIn("SetTunFd", HANDOFF)

    def test_the_relay_never_buffers_a_message_that_carries_an_fd(self):
        self.assertIn("relayTunHandoff(conn)", MAIN)
        # The app's reply line and its SCM_RIGHTS descriptor arrive in ONE
        # message: the reply must be read raw (a bufio.Reader swallows OOB).
        self.assertIn("unixConn.ReadMsgUnix(buf, oob)", MAIN)
        self.assertIn('fmt.Fprintf(unixConn, "OPEN %s\\n", payload)', MAIN)
        self.assertIn("syscall.ParseSocketControlMessage", MAIN)
        self.assertIn("binary.LittleEndian.Uint32", MAIN)

    def test_the_connect_path_never_re_arms_its_attempt(self):
        # THE 3.4.0–3.4.3 stall fix: ensureSidecar() re-arms when it boots,
        # invalidating the connect attempt — the worker silently bailed at
        # the next isCurrent() check and the idle reaper killed the orphaned
        # sidecar 240s later. The connect path boots via its OWN attempt.
        self.assertIn("fun ensureSidecarForConnect(context: Context, attempt: Long): Boolean", ENGINE)
        self.assertIn("return startProcess(context, attempt)", ENGINE)
        # ...and the list-only ensureSidecar keeps its armForStart (the picker
        # has no attempt of its own).
        self.assertIn("fun ensureSidecar(context: Context): Boolean", ENGINE)
        service_start = SERVICE.index("private fun startLanternTunnel()")
        connect_block = SERVICE[service_start:SERVICE.index("establishLanternTun", service_start)]
        self.assertIn("LanternEngine.ensureSidecarForConnect(this, attempt)", connect_block)
        self.assertNotIn("LanternEngine.ensureSidecar(this)", connect_block)

    def test_the_app_answers_open_requests_with_the_engines_own_options(self):
        self.assertIn("fun startTunHandoffService(", ENGINE)
        self.assertIn("class TunRequest(payload: String)", ENGINE)
        self.assertIn('line.startsWith("OPEN ")', ENGINE)
        self.assertIn("setFileDescriptorsForSend(arrayOf(pfd.fileDescriptor))", ENGINE)
        # establishLanternTun is the createVPNBuilder mirror: engine options
        # drive addresses/MTU/DNS/routes; no pre-established TUN exists.
        service_start = SERVICE.index("private fun startLanternTunnel()")
        self.assertIn("private fun establishLanternTun(request: LanternEngine.TunRequest)", SERVICE)
        establish_block = SERVICE[
            SERVICE.index("private fun establishLanternTun(request: LanternEngine.TunRequest)"):
        ]
        establish_block = establish_block[: establish_block.index("/** \"10.10.1.1/30\" → \"10.10.1.0\"")]
        self.assertIn("setMtu(request.mtu)", establish_block)
        self.assertIn("builder.addDnsServer", establish_block)
        self.assertIn("runCatching { tun?.close() }", establish_block)
        # The hardcoded pre-establish plan is gone.
        lantern_start = SERVICE[service_start:SERVICE.index("establishLanternTun", service_start)]
        self.assertNotIn('"10.10.1.1"', lantern_start)
        self.assertNotIn("builder.establish()", lantern_start)
        # The service is armed BEFORE /connect (OpenTun fires inside it).
        service_idx = SERVICE.index("LanternEngine.startTunHandoffService(this, ::establishLanternTun)")
        connect_idx = SERVICE.index("LanternEngine.connect(this, attempt)", service_idx)
        self.assertLess(service_idx, connect_idx)

    def test_probes_ride_the_engines_own_tunnel_proxy(self):
        self.assertIn("const val SOCKS_PORT = 14986", ENGINE)

    def test_the_watchdog_no_longer_demands_tun2socks_for_lantern(self):
        idx = SERVICE.index("val needsRouting = psiphonVpnMode")
        end = SERVICE.index("if (needsRouting &&", idx)
        self.assertNotIn("LANTERN", SERVICE[idx:end])


if __name__ == "__main__":
    unittest.main()
