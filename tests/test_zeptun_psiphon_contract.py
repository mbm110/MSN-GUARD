"""Psiphon's strict SOCKS seam; no Android build or network access required."""
import ctypes
import platform
import re
import socket
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'app/src/main/java/com/msnguard/vpn'


class ZeptunPsiphonContract(unittest.TestCase):
    def test_strict_mode_is_explicit_and_only_psiphon_opts_in(self):
        engine = (JAVA / 'ZeptunEngine.kt').read_text()
        manager = (JAVA / 'TunEngine.kt').read_text()
        service = (JAVA / 'MsnGuardVpnService.kt').read_text()
        self.assertIn('strictSocks = false', engine)
        self.assertIn('strictSocks = true', engine)
        self.assertIn('if (strictSocks) appendLine("pipeline = false")', engine)
        self.assertIn('if (strictSocks) "tcp" else "udp"', engine)
        self.assertIn('psiphon: Boolean = false', manager)
        self.assertIn('if (psiphon && engine === ZeptunEngine)', manager)
        self.assertIn('ZeptunEngine.startPsiphon(fd, socksPort, mtu, dnsOnly)', manager)
        calls = re.findall(r'TunEngineManager\.start\([^\n]+', service)
        opted_in = [call for call in calls if 'psiphon = true' in call]
        self.assertEqual(len(opted_in), 1)
        self.assertIn('tunFd, port, mtu = currentTunMtu', opted_in[0])
        self.assertIn('else engine.start(fd, socksPort, mtu, dnsOnly)', manager)
        self.assertIn('LegacyEngine.start(fd, socksPort, mtu, dnsOnly)', manager)

    @unittest.skipUnless(platform.machine() == 'x86_64' and platform.system() == 'Linux',
                         'uses the checked-in x86_64 native library')
    def test_actual_native_parser_accepts_emitted_toml_and_boolean_pipeline(self):
        lib = ctypes.CDLL(str(ROOT / 'app/src/main/jniLibs/x86_64/libzeptun.so'))
        lib.zeptun_create_from_toml.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                                               ctypes.POINTER(ctypes.c_void_p)]
        lib.zeptun_destroy.argtypes = [ctypes.c_void_p]
        engine = (JAVA / 'ZeptunEngine.kt').read_text()
        template = engine.split('val toml = buildString {', 1)[1].split('lastToml = toml', 1)[0]
        # Exercise the complete production TOML against the actual bundled parser.
        tun, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with tun, peer:
            for strict in (False, True):
                lines = []
                for line in template.splitlines():
                    match = re.search(r'appendLine\("(.*)"\)', line)
                    if not match or ('if (strictSocks)' in line and not strict):
                        continue
                    text = match[1].replace('\\"', '"')
                    text = text.replace('${if (strictSocks) "tcp" else "udp"}',
                                        'tcp' if strict else 'udp')
                    for name, value in {'rawFd': tun.fileno(), 'mtu': 1424,
                                        'upstream': '1.1.1.1', 'socksPort': 1819}.items():
                        text = text.replace('$' + name, str(value))
                    lines.append(text)
                config = '\n'.join(lines).encode()
                pointer = ctypes.c_void_p()
                rc = lib.zeptun_create_from_toml(config, len(config), ctypes.byref(pointer))
                try:
                    self.assertEqual(rc, 0, (strict, config))
                    self.assertTrue(pointer.value)
                    self.assertEqual(b'pipeline = false' in config, strict)
                finally:
                    if pointer.value:
                        lib.zeptun_destroy(pointer)
                if strict:
                    # A parser that ignored the setting would accept this too.
                    invalid = config.replace(b'pipeline = false', b'pipeline = "off"')
                    pointer = ctypes.c_void_p()
                    rc = lib.zeptun_create_from_toml(invalid, len(invalid), ctypes.byref(pointer))
                    try:
                        self.assertEqual(rc, -16)
                    finally:
                        if pointer.value:
                            lib.zeptun_destroy(pointer)


if __name__ == '__main__':
    unittest.main()
