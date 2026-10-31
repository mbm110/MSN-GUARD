"""DNSTT must remain an isolated Tor PT and use Orbot's Iran bridges."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOR = (ROOT / "app/src/main/java/com/msnguard/vpn/TorManager.kt").read_text()
BRIDGES = (ROOT / "app/src/main/java/com/msnguard/vpn/DnsttBridges.kt").read_text()
WORKFLOW = (ROOT / ".github/workflows/build.yml").read_text()
SCRIPT = (ROOT / "tools/build-dnstt.sh").read_text()

assert 'DNSTT("dnstt", "DNS Tunnel"' in TOR
assert 'TorMode.DNSTT -> listOf("dnstt")' in TOR
assert 'TorMode.DNSTT -> DnsttBridges.lines(context, File(context.filesDir, "tor_data"))' in TOR
assert 'binaryName = if (transports == listOf("dnstt")) "libdnstt.so"' in TOR
assert 'DnsttResolverScanner.cachedPaths(dataDir)' in BRIDGES
assert 'udp=$resolver:53' in BRIDGES
SCANNER = (ROOT / "app/src/main/java/com/msnguard/vpn/DnsttResolverScanner.kt").read_text()
VPN = (ROOT / "app/src/main/java/com/msnguard/vpn/MsnGuardVpnService.kt").read_text()
RESOLVERS = ROOT / "app/src/main/assets/dnstt-resolvers-ir.txt"
assert 'dnstt-working-resolvers-ir.txt' in SCANNER
assert 'DNSTT_FRESH_SCAN_PREF' in SCANNER
assert 'scanning 7629 resolvers in order' in SCANNER
assert 'private const val WORKERS = 40' in SCANNER
assert 'fun awaitHealthy(context: Context, dataDir: File, cancelled: () -> Boolean)' in SCANNER
assert TOR.index('DnsttResolverScanner.awaitHealthy(context, dataDir)') < TOR.index('val transports = transportsFor(context, mode)', TOR.index('private fun attempt('))
assert 'if (resolver == null)' in TOR and 'Tor was not started' in TOR
assert 'DnsttBridges.advanceAfterFailure(context, dataDir)' in TOR
assert 'val paths = DnsttResolverScanner.cachedPaths(dataDir)' in BRIDGES
assert 'val batch = paths.drop(normalizedOffset).take(BATCH_SIZE)' in BRIDGES
assert 'val pubkey = if (domain == DOMAIN_1) PUBKEY_1 else PUBKEY_2' in BRIDGES
assert 'private const val BATCH_SIZE = 1' in BRIDGES
assert 'Probe and Tor must use the same single verified path' in BRIDGES
assert 'DnsttBridges.reset(context)' in SCANNER
assert 'currentProtocol.contains("TOR") && TorManager.selectedMode(this) == TorManager.TorMode.DNSTT' in VPN
assert 'teardownService = !sealing && !pendingDnsttRetry' in VPN
assert 'val paths = DnsttResolverScanner.cachedPaths(dataDir)' in BRIDGES
assert 'if (paths.isEmpty()) return emptyList()' in BRIDGES
assert 'doh=https://' not in BRIDGES
assert 'udp=$resolver:53 pubkey=$pubkey domain=$domain' in BRIDGES
assert 'probePath(context, dataDir, ip, DnsttBridges.PUBKEY_1, DnsttBridges.DOMAIN_1) -> DnsttBridges.DOMAIN_1' in SCANNER
assert 'probePath(context, dataDir, ip, DnsttBridges.PUBKEY_2, DnsttBridges.DOMAIN_2) -> DnsttBridges.DOMAIN_2' in SCANNER
assert 'val args = "udp=$resolver:53;pubkey=$pubkey;domain=$domain"' in SCANNER
assert 'fun cachedPaths(dataDir: File): List<Pair<String, String>>' in SCANNER
assert 'appendCache(File(dataDir, PATHS_NAME), "$index $ip $domain")' in SCANNER
assert 'File(dataDir, PATHS_NAME).delete()' in SCANNER
assert 'val finished = (cachedPaths(dataDir).map { it.first } + readIps(rejected)).toHashSet()' in SCANNER
assert 'if (ip in finished) continue' in SCANNER
assert 'if (stored) synchronized(progressLock)' in SCANNER
assert 'DNSTT resolver scan progress: $done/${resolvers.size}' in SCANNER
assert 'const val DNSTT_MIN_TUN_MTU = 512' in SCANNER
assert 'const val DNSTT_MAX_TUN_MTU = 1400' in SCANNER
assert 'DNSTT resolver scan started: ${resolvers.size} candidates' in SCANNER
assert 'scannedTorMtu.coerceIn(' in VPN
assert 'DNSTT TUN MTU $torMtu applied (allowed range 512..1400)' in VPN
assert 'DNSTT resolver scan progress: $done/${resolvers.size}' in SCANNER
assert 'val next = AtomicInteger(start)' in SCANNER
assert 'repeat(WORKERS)' in SCANNER
assert 'REJECTED_NAME' in SCANNER
assert 'cachedPaths(dataDir).firstOrNull()?.let { return it.first }' in SCANNER
assert '        stopDnsttScan()' not in TOR
assert 'cache.delete()' in SCANNER
assert 'first.await(FIRST_RESULT_TIMEOUT_MS' in SCANNER
assert 'executor.shutdown()' in SCANNER
assert 'process.inputStream.bufferedReader().useLines' in SCANNER
assert 'process.errorStream.bufferedReader()' in SCANNER
assert 'fields[2] == "socks5"' in SCANNER
assert 'done.await(METHOD_TIMEOUT_MS, TimeUnit.MILLISECONDS)' in SCANNER
assert 'FIRST_RESULT_TIMEOUT_MS = 15_000L' in SCANNER
assert 'PROBE_TIMEOUT_MS = 18_000' in SCANNER
assert 'METHOD_TIMEOUT_MS = 10_000L' in SCANNER
assert 'waiting for first verified path' in SCANNER
assert 'doh=https://dns.google/dns-query' not in BRIDGES
assert 'process start failed' in SCANNER
assert 'catch (_: java.io.IOException)' in SCANNER
assert 'scanner log reader reach the process default exception handler' in SCANNER
BUILD = (ROOT / "app/build.gradle.kts").read_text()
assert 'versionCode = 436' in BUILD and 'versionName = "3.1.39"' in BUILD
assert 'private const val PROBE_TIMEOUT_MS = 18_000' in SCANNER
assert 'private const val METHOD_TIMEOUT_MS = 10_000L' in SCANNER
assert 'val paths = DnsttResolverScanner.cachedPaths(dataDir)' in BRIDGES
assert 'HEAD /generate_204 HTTP/1.1' in SCANNER
assert 'Host: www.gstatic.com' in SCANNER
assert 'code in 200..399' in SCANNER
assert 'index to (ip to domain)' in SCANNER
assert '.sortedBy { it.first }' in SCANNER
assert 'DNSTT resolver scan complete: ${cachedPaths(dataDir).size} verified path(s)' in SCANNER
assert 'mode != TorMode.DNSTT && now - lastProgressMs.get() > STALL_TIMEOUT_S * 1_000' in TOR
assert 'DNSTT handshake:' in TOR
assert 'executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS)' in SCANNER
assert 'complete asset is the scan budget' in SCANNER
assert RESOLVERS.exists() and sum(1 for line in RESOLVERS.read_text().splitlines() if line.strip()) == 7629
assert 'tools/build-dnstt.sh' in WORKFLOW
assert "go-version: '1.25'" in WORKFLOW
assert 'f1b9b97a269f83bad41d2ceef291b4d2c161cd11' in SCRIPT
assert 'libdnstt.so' in SCRIPT
print("PASS DNSTT is an isolated managed PT with Orbot Iran bridge lines")
