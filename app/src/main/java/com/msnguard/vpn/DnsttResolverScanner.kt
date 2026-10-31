package com.msnguard.vpn

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** Ordered DNSTT resolver discovery with persistent, engine-scoped cache. */
internal object DnsttResolverScanner {
    private const val CACHE_NAME = "dnstt-working-resolvers-ir.txt"
    private const val PATHS_NAME = "dnstt-working-paths-ir.txt"
    private const val PROGRESS_NAME = "dnstt-resolver-scan-index.txt"
    private const val REJECTED_NAME = "dnstt-rejected-resolvers-ir.txt"
    private const val INPUT_ASSET = "dnstt-resolvers-ir.txt"
    // Each worker owns a native PT process. Keep concurrency bounded to avoid
    // starving Tor while it bootstraps.
    private const val WORKERS = 40
    // The tunnel handshake and the first proxied request need their full
    // network budget. A short socket timeout can cache a false negative while
    // the native client is still completing Noise/KCP setup.
    private const val PROBE_TIMEOUT_MS = 18_000
    private const val METHOD_TIMEOUT_MS = 10_000L
    private const val PROGRESS_LOG_EVERY = 100
    private val progressLock = Any()
    private const val FIRST_RESULT_TIMEOUT_MS = 15_000L
    // DNSTT's effective MTU is determined by the DNS name and the server's
    // negotiated payload. The TUN value is separate; this range is enforced on
    // every DNSTT session so a bad profile cannot pass 134 or another tiny value.
    const val DNSTT_MIN_TUN_MTU = 512
    const val DNSTT_MAX_TUN_MTU = 1400
    private val running = AtomicBoolean(false)
    private val completed = AtomicInteger(0)
    @Volatile private var scanExecutor: java.util.concurrent.ExecutorService? = null
    @Volatile private var scanProcesses = mutableListOf<Process>()

    fun prepare(context: Context, dataDir: File): String? {
        val cache = File(dataDir, CACHE_NAME)
        val fresh = context.profiled().getBoolean(TorManager.DNSTT_FRESH_SCAN_PREF, false)

        if (fresh) {
            DnsttBridges.reset(context)
            cache.delete()
            File(dataDir, PATHS_NAME).delete()
            File(dataDir, PROGRESS_NAME).delete()
            File(dataDir, REJECTED_NAME).delete()
            context.profiled().edit().putBoolean(TorManager.DNSTT_FRESH_SCAN_PREF, false).apply()
            ConnectionLog.record("DNSTT Fresh Scan: cache and progress cleared; scanning 7629 resolvers in order")
        }

        // The old cache format proved only SOCKS reachability and had no source
        // index. Never reuse it as a verified E2E path after this scanner change.
        val pathFile = File(dataDir, PATHS_NAME)
        if (!fresh && pathFile.isFile && pathFile.readLines().any { it.trim().split(Regex("\\s+")).size < 3 }) {
            pathFile.delete()
            cache.delete()
            File(dataDir, PROGRESS_NAME).delete()
            ConnectionLog.record("DNSTT cache format changed; discarded legacy paths and restarting probes")
        }

        val cached = cachedPaths(dataDir)
        if (!fresh && cached.isNotEmpty()) {
            ConnectionLog.record("DNSTT cache: using ${cached.size} verified resolver/profile path(s)")
            return cached.first().first
        }

        val resolvers = readIpsFromAsset(context)
        if (resolvers.isEmpty()) return null
        if (running.get()) {
            ConnectionLog.record("DNSTT resolver scan already running; using current scan")
            return cachedPaths(dataDir).firstOrNull()?.first
        }
        val progress = File(dataDir, PROGRESS_NAME)
        val rejected = File(dataDir, REJECTED_NAME)
        // Older builds counted failed probes as complete. A fully rejected
        // cache without any healthy path must be retried after the probe fix.
        if (readIps(cache).isEmpty() && readIps(rejected).size >= resolvers.size) {
            rejected.delete()
            progress.delete()
            ConnectionLog.record("DNSTT retrying all candidates after zero verified paths")
        }
        val finished = (cachedPaths(dataDir).map { it.first } + readIps(rejected)).toHashSet()
        val start = 0
        running.set(true)
        completed.set(finished.size)
        ConnectionLog.record("DNSTT resolver scan started: ${resolvers.size} candidates, ${finished.size} previously completed")
        val first = CountDownLatch(1)
        val firstResult = arrayOfNulls<String>(1)
        val next = AtomicInteger(start)
        val executor = Executors.newFixedThreadPool(WORKERS)
        scanExecutor = executor
        repeat(WORKERS) {
            executor.execute {
                while (running.get()) {
                    val index = next.getAndIncrement()
                    if (index >= resolvers.size) break
                    val ip = resolvers[index]
                    if (ip in finished) continue
                    var stored = false
                    runCatching {
                        val domain = probe(context, dataDir, ip)
                        if (domain != null) {
                            appendCache(File(dataDir, PATHS_NAME), "$index $ip $domain")
                            appendCache(cache, ip)
                            stored = true
                            synchronized(firstResult) {
                                if (firstResult[0] == null) {
                                    firstResult[0] = ip
                                    first.countDown()
                                    ConnectionLog.record("DNSTT resolver #${index + 1}/${resolvers.size} healthy: $ip")
                                }
                            }
                        } else {
                            appendRejected(File(dataDir, REJECTED_NAME), ip)
                            stored = true
                        }
                    }.onFailure { error ->
                        if (running.get()) ConnectionLog.record("DNSTT resolver #${index + 1} probe error: ${error.message ?: "unknown"}")
                    }
                    // Only a stored outcome is complete. An in-flight process
                    // interrupted by app teardown must be retried on the next scan.
                    if (stored) synchronized(progressLock) {
                        val done = completed.incrementAndGet()
                        writeProgress(progress, done)
                        if (done % PROGRESS_LOG_EVERY == 0 || done == resolvers.size) {
                            ConnectionLog.record("DNSTT resolver scan progress: $done/${resolvers.size}")
                        }
                    }
                }
            }
        }
        Thread({
            executor.shutdown()
            // The complete asset is the scan budget. Do not cancel it because
            // Tor has already timed out; the next resolver session resumes from
            // the persisted index and consumes the remaining entries.
            runCatching {
                executor.awaitTermination(Long.MAX_VALUE, TimeUnit.DAYS)
            }
            ConnectionLog.record("DNSTT resolver scan complete: ${cachedPaths(dataDir).size} verified path(s), ${readIps(File(dataDir, REJECTED_NAME)).size} rejected")
            running.set(false)
        }, "dnstt-resolver-scan-wait").apply { isDaemon = true }.start()
        first.await(FIRST_RESULT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        val selected = firstResult[0] ?: cachedPaths(dataDir).firstOrNull()?.first
        if (selected == null) ConnectionLog.record("DNSTT resolver scan still running; waiting for first verified path")
        return selected
    }

    fun cachedPaths(dataDir: File): List<Pair<String, String>> =
        readIps(File(dataDir, PATHS_NAME))
            .mapNotNull { line ->
                val fields = line.split(Regex("\\s+"))
                // New entries carry the source index so concurrent probes still
                // produce an ordered cache. Legacy two-field entries are read at
                // the end and are deliberately treated as lower-confidence.
                when {
                    fields.size >= 3 -> {
                        val index = fields[0].toIntOrNull() ?: return@mapNotNull null
                        val ip = fields[1]
                        val domain = fields[2]
                        if (domain == DnsttBridges.DOMAIN_1 || domain == DnsttBridges.DOMAIN_2) {
                            index to (ip to domain)
                        } else null
                    }
                    fields.size == 2 -> {
                        val ip = fields[0]
                        val domain = fields[1]
                        if (domain == DnsttBridges.DOMAIN_1 || domain == DnsttBridges.DOMAIN_2) {
                            Int.MAX_VALUE to (ip to domain)
                        } else null
                    }
                    else -> null
                }
            }
            .sortedBy { it.first }
            .map { it.second }

    /** Wait for a real end-to-end probe before allowing Tor to start. */
    fun awaitHealthy(context: Context, dataDir: File, cancelled: () -> Boolean): String? {
        prepare(context, dataDir)
        while (!cancelled()) {
            cachedPaths(dataDir).firstOrNull()?.let { return it.first }
            if (!running.get()) return null
            try {
                Thread.sleep(250)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return null
            }
        }
        return null
    }

    fun cached(dataDir: File): List<String> = readIps(File(dataDir, CACHE_NAME))

    fun stopScan() {
        running.set(false)
        val processes = synchronized(scanProcesses) {
            val snapshot = scanProcesses.toList()
            scanProcesses.clear()
            snapshot
        }
        processes.forEach { process ->
            runCatching { process.destroy() }
            runCatching { process.destroyForcibly() }
        }
        scanExecutor?.shutdownNow()
        scanExecutor = null
    }

    fun requestFreshScan(context: Context) {
        context.profiled().edit().putBoolean(TorManager.DNSTT_FRESH_SCAN_PREF, true).apply()
        ConnectionLog.record("DNSTT Fresh Scan requested — cache will be cleared on next Tor connect")
    }

    private fun probe(context: Context, dataDir: File, ip: String): String? = when {
        probePath(context, dataDir, ip, DnsttBridges.PUBKEY_1, DnsttBridges.DOMAIN_1) -> DnsttBridges.DOMAIN_1
        probePath(context, dataDir, ip, DnsttBridges.PUBKEY_2, DnsttBridges.DOMAIN_2) -> DnsttBridges.DOMAIN_2
        else -> null
    }

    private fun probePath(context: Context, dataDir: File, ip: String, pubkey: String, domain: String): Boolean {
        val state = File(dataDir, "dnstt-scan/$ip").apply { mkdirs() }
        val process = runCatching {
            ProcessBuilder(File(context.applicationInfo.nativeLibraryDir, "libdnstt.so").absolutePath)
                .redirectErrorStream(false)
                .apply {
                    environment()["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
                    environment()["TOR_PT_CLIENT_TRANSPORTS"] = "dnstt"
                    environment()["TOR_PT_STATE_LOCATION"] = state.absolutePath + "/"
                    environment()["TOR_PT_EXIT_ON_STDIN_CLOSE"] = "1"
                    environment()["HOME"] = dataDir.absolutePath
                }.start()
        }.onFailure { error ->
            ConnectionLog.record("DNSTT resolver #$ip process start failed: ${error.message ?: "unknown"}")
        }.getOrNull() ?: return false
        synchronized(scanProcesses) { scanProcesses += process }
        Thread({
            try {
                val reader = process.errorStream.bufferedReader()
                while (true) {
                    val line = try {
                        reader.readLine()
                    } catch (_: java.io.IOException) {
                        break
                    }
                    if (line == null) break
                    if (line.isNotBlank()) {
                        runCatching { ConnectionLog.record("DNSTT scan[$ip]: $line") }
                    }
                }
                runCatching { reader.close() }
            } catch (_: Throwable) {
                // Closing a PT stream during teardown is normal. Never let the
                // scanner log reader reach the process default exception handler.
            }
        }, "dnstt-scan-log-$ip").apply { isDaemon = true }.start()
        return try {
            val listener = readMethod(process)
            if (listener == null) {
                ConnectionLog.record("DNSTT resolver #$ip: no SOCKS listener")
                return false
            }
            val healthy = socksProbe(listener, ip, pubkey, domain)
            if (!healthy) ConnectionLog.record("DNSTT resolver #$ip: tunnel probe failed ($domain)")
            healthy
        } finally {
            runCatching { process.outputStream.close() }
            runCatching { process.destroy() }
            synchronized(scanProcesses) { scanProcesses.remove(process) }
        }
    }

    private fun readMethod(process: Process): String? {
        val result = arrayOfNulls<String>(1)
        val done = CountDownLatch(1)
        Thread({
            try {
                process.inputStream.bufferedReader().useLines { lines ->
                    for (raw in lines) {
                        val fields = raw.trim().split(Regex("\\s+"))
                        if (fields.size >= 4 && fields[0] == "CMETHOD" && fields[2] == "socks5") {
                            result[0] = fields[3]
                            break
                        }
                        if (raw.trim() == "CMETHODS DONE") break
                    }
                }
            } catch (_: Throwable) {
                // The process is deliberately terminated after a failed probe.
            } finally {
                done.countDown()
            }
        }, "dnstt-method-reader").apply { isDaemon = true }.start()
        done.await(METHOD_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        return result[0]
    }

    private fun socksProbe(listener: String, resolver: String, pubkey: String, domain: String): Boolean {
        val parts = listener.substringAfterLast(':').toIntOrNull() ?: return false
        return runCatching {
            Socket().use { socket ->
                socket.soTimeout = PROBE_TIMEOUT_MS
                socket.connect(InetSocketAddress("127.0.0.1", parts), PROBE_TIMEOUT_MS)
                val input = socket.getInputStream()
                val output = socket.getOutputStream()
                output.write(byteArrayOf(5, 1, 2)); output.flush()
                check(input.read() == 5 && input.read() == 2)
                val args = "udp=$resolver:53;pubkey=$pubkey;domain=$domain"
                // goptlib's PT argument channel is RFC1929 username+password.
                // Use username for the first part and password for the remainder,
                // because Android's SOCKS probe must keep each field <=255 bytes.
                val split = args.indexOf(';').coerceAtLeast(1)
                val username = args.substring(0, split).toByteArray(Charsets.ISO_8859_1)
                val password = args.substring(split).toByteArray(Charsets.ISO_8859_1)
                output.write(byteArrayOf(1, username.size.toByte())); output.write(username)
                output.write(byteArrayOf(password.size.toByte())); output.write(password); output.flush()
                check(input.read() == 1 && input.read() == 0)
                val destination = "www.gstatic.com".toByteArray(Charsets.US_ASCII)
                output.write(byteArrayOf(5, 1, 0, 3, destination.size.toByte())); output.write(destination)
                output.write(byteArrayOf(0, 80)); output.flush()
                val version = input.read()
                val reply = input.read()
                val reserved = input.read()
                val atyp = input.read()
                check(version == 5 && reply == 0 && reserved == 0)
                when (atyp) {
                    1 -> repeat(4) { input.read() }
                    3 -> { val length = input.read(); repeat(length.coerceAtLeast(0)) { input.read() } }
                    4 -> repeat(16) { input.read() }
                    else -> error("invalid SOCKS5 address type")
                }
                check(input.read() >= 0 && input.read() >= 0)

                // A SOCKS CONNECT reply only proves that the local bridge
                // accepted a stream. The reference scanners perform a second
                // end-to-end request through that stream. Do the same here so
                // a resolver is cached only after bidirectional tunnel data has
                // crossed the remote SOCKS server.
                val request = "HEAD /generate_204 HTTP/1.1\r\n" +
                    "Host: www.gstatic.com\r\n" +
                    "Connection: close\r\n\r\n"
                output.write(request.toByteArray(Charsets.US_ASCII))
                output.flush()
                val status = StringBuilder()
                while (status.length < 256) {
                    val value = input.read()
                    check(value >= 0)
                    status.append(value.toChar())
                    if (status.endsWith("\r\n")) break
                }
                val statusLine = status.toString().trim()
                check(statusLine.startsWith("HTTP/1.1 ") || statusLine.startsWith("HTTP/1.0 "))
                val code = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
                check(code in 200..399)
                true
            }
        }.getOrDefault(false)
    }

    private fun readIpsFromAsset(context: Context): List<String> = runCatching {
        context.assets.open(INPUT_ASSET).bufferedReader().useLines { lines ->
            lines.map(String::trim).filter { it.matches(Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$")) }.toList()
        }
    }.getOrDefault(emptyList())

    private fun readProgress(file: File): Int = runCatching {
        file.readText().trim().toInt()
    }.getOrDefault(0)

    private fun writeProgress(file: File, index: Int) {
        runCatching {
            file.parentFile?.mkdirs()
            file.writeText(index.toString())
        }
    }

    private fun readIps(file: File): List<String> = runCatching {
        if (!file.isFile) emptyList() else file.readLines().map(String::trim).filter(String::isNotEmpty).distinct()
    }.getOrDefault(emptyList())

    private fun appendCache(file: File, ip: String) {
        synchronized(file.absolutePath.intern()) {
            val current = readIps(file)
            if (ip !in current) file.parentFile?.mkdirs().also { file.appendText(if (current.isEmpty()) ip else "\n$ip") }
        }
    }

    private fun appendRejected(file: File, ip: String) {
        synchronized(file.absolutePath.intern()) {
            val current = readIps(file)
            if (ip !in current) file.parentFile?.mkdirs().also { file.appendText(if (current.isEmpty()) ip else "\n$ip") }
        }
    }
}
