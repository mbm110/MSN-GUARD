package com.msnguard.vpn

import java.net.InetSocketAddress
import java.net.Socket

/**
 * Real Delay for SHARD — mo-be-mo PattNG RealPingWorkerService logic.
 *
 * Two modes exactly like PattNG:
 *  - onlyTcp=false (Test Real Delay): for each node, TCP fast-path 1s (socketConnectTime),
 *    then real HTTP probe through the node's own SOCKS inbound. Failure of fast-path => -1,
 *    exactly like PattNG startRealPing.
 *  - onlyTcp=true (Test TCP Ping): TCP connect only, no HTTP. PattNG startTcping predicate
 *    uses all-h3 check (split(',').all startsWith h3), while real-ping uses single startsWith.
 *
 * Configs are taken verbatim — only TlsSettingsCheck.fixImportedAlpn (ws/httpUpgrade) at
 * ShardImport.parse time, nothing else touched.
 *
 * Xray model: no gomobile libv2ray, so HTTP probe runs through the same probeConfig
 * (one inbound per node, one process) as ShardManager.race, but batched: one process
 * for the whole batch, each inbound timed individually → true per-node Real Delay.
 */
object ShardRealDelayTester {

    const val UNTESTED = -1L
    const val DELAY_TEST_URL = "https://www.gstatic.com/generate_204"
    const val DELAY_TEST_URL2 = "https://www.google.com/generate_204"

    private const val TCP_TIMEOUT_MS = 1000
    private const val CONCURRENCY = 16
    private const val BATCH_BASE_PORT = 21400
    private const val PROBE_TIMEOUT_MS = 5000
    private const val PORT_WAIT_MS = 4000

    data class NodeResult(val node: ShardNode, val delayMs: Long)

    fun measureOne(
        context: android.content.Context,
        node: ShardNode,
        onlyTcp: Boolean,
        testUrl: String = DELAY_TEST_URL,
    ): Long {
        val isHysteria = node.protocol == "hysteria2" || node.protocol == "hysteria"
        val isWireguard = node.protocol == "wireguard"
        val serverOk = node.address.isNotBlank()
        val portOk = node.port in 1..65535
        val allH3 = node.alpn.isNotEmpty() && node.alpn.split(",").all { it.trim().lowercase().startsWith("h3") }
        val singleH3 = node.alpn.trim().lowercase().startsWith("h3")

        if (onlyTcp) {
            if (!isHysteria && !isWireguard && !allH3 && serverOk && portOk) {
                return SpeedtestManager.socketConnectTime(node.address, node.port, TCP_TIMEOUT_MS)
            }
            return UNTESTED
        }
        if (!isHysteria && !isWireguard && !singleH3 && serverOk && portOk) {
            val tcp = SpeedtestManager.socketConnectTime(node.address, node.port, TCP_TIMEOUT_MS)
            if (tcp <= -1L) return -1L
        }
        return httpProbeSingle(context, node)
    }

    /**
     * Measure all nodes. For onlyTcp=false the HTTP phase is batched into one xray
     * process (one inbound per candidate) — mo-be-mo PattNG MeasureOutboundDelayInBatch
     * batch semantics, adapted to the exec-xray model.
     */
    fun measureAll(
        context: android.content.Context,
        nodes: List<ShardNode>,
        onlyTcp: Boolean = false,
        testUrl: String = DELAY_TEST_URL,
        concurrency: Int = CONCURRENCY.coerceIn(1, 128),
        cancelFlag: () -> Boolean = { false },
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
        onResult: ((NodeResult) -> Unit)? = null,
    ): List<NodeResult> {
        if (nodes.isEmpty()) return emptyList()
        if (onlyTcp) return measureAllTcpOnly(nodes, concurrency, cancelFlag, onProgress, onResult)
        return measureAllRealDelay(context, nodes, concurrency, cancelFlag, onProgress, onResult)
    }

    private fun measureAllTcpOnly(
        nodes: List<ShardNode>,
        concurrency: Int,
        cancelFlag: () -> Boolean,
        onProgress: ((Int, Int) -> Unit)?,
        onResult: ((NodeResult) -> Unit)?,
    ): List<NodeResult> {
        val results = java.util.Collections.synchronizedList(mutableListOf<NodeResult>())
        val pool = java.util.concurrent.Executors.newFixedThreadPool(concurrency)
        val done = java.util.concurrent.atomic.AtomicInteger(0)
        val latch = java.util.concurrent.CountDownLatch(nodes.size)
        nodes.forEach { node ->
            pool.execute {
                try {
                    if (cancelFlag()) return@execute
                    val ms = measureOneTcp(node)
                    val r = NodeResult(node, ms)
                    results.add(r); onResult?.invoke(r)
                } catch (_: Exception) {
                    val r = NodeResult(node, UNTESTED); results.add(r); onResult?.invoke(r)
                } finally { onProgress?.invoke(done.incrementAndGet(), nodes.size); latch.countDown() }
            }
        }
        try { latch.await() } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        pool.shutdownNow()
        return results.toList()
    }

    private fun measureOneTcp(node: ShardNode): Long {
        val isHysteria = node.protocol == "hysteria2" || node.protocol == "hysteria"
        val isWireguard = node.protocol == "wireguard"
        val allH3 = node.alpn.isNotEmpty() && node.alpn.split(",").all { it.trim().lowercase().startsWith("h3") }
        if (!isHysteria && !isWireguard && !allH3 && node.address.isNotBlank() && node.port in 1..65535) {
            return SpeedtestManager.socketConnectTime(node.address, node.port, TCP_TIMEOUT_MS)
        }
        return UNTESTED
    }

    private fun measureAllRealDelay(
        context: android.content.Context,
        nodes: List<ShardNode>,
        concurrency: Int,
        cancelFlag: () -> Boolean,
        onProgress: ((Int, Int) -> Unit)?,
        onResult: ((NodeResult) -> Unit)?,
    ): List<NodeResult> {
        val results = java.util.Collections.synchronizedList(mutableListOf<NodeResult>())
        val done = java.util.concurrent.atomic.AtomicInteger(0)
        fun emit(r: NodeResult) { results.add(r); onResult?.invoke(r); onProgress?.invoke(done.incrementAndGet(), nodes.size) }

        // Phase 1: TCP fast-path — same predicate as PattNG startRealPing single-h3
        val needHttp = mutableListOf<ShardNode>()
        val fastPool = java.util.concurrent.Executors.newFixedThreadPool(concurrency)
        val fastLatch = java.util.concurrent.CountDownLatch(nodes.size)
        // Track per-node tcp outcome to emit -1 immediately on tcp failure
        val tcpFailed = java.util.Collections.synchronizedSet(mutableSetOf<ShardNode>())
        nodes.forEach { node ->
            fastPool.execute {
                try {
                    if (cancelFlag()) return@execute
                    val isHysteria = node.protocol == "hysteria2" || node.protocol == "hysteria"
                    val isWireguard = node.protocol == "wireguard"
                    val singleH3 = node.alpn.trim().lowercase().startsWith("h3")
                    val serverOk = node.address.isNotBlank()
                    val portOk = node.port in 1..65535
                    val gate = !isHysteria && !isWireguard && !singleH3 && serverOk && portOk
                    if (gate) {
                        val tcp = SpeedtestManager.socketConnectTime(node.address, node.port, TCP_TIMEOUT_MS)
                        if (tcp <= -1L) {
                            ShardHealth.recordFailure(context, node)
                            emit(NodeResult(node, -1L)); tcpFailed.add(node)
                        } else {
                            synchronized(needHttp) { needHttp.add(node) }
                        }
                    } else {
                        synchronized(needHttp) { needHttp.add(node) }
                    }
                } catch (_: Exception) {
                    synchronized(needHttp) { needHttp.add(node) }
                } finally { fastLatch.countDown() }
            }
        }
        try { fastLatch.await() } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        fastPool.shutdownNow()
        if (cancelFlag()) {
            // Emit UNTESTED for anything not yet emitted
            val emitted = results.map { it.node }.toSet() + tcpFailed
            nodes.filter { it !in emitted }.forEach { emit(NodeResult(it, UNTESTED)) }
            return results.toList()
        }
        if (needHttp.isEmpty()) return results.toList()

        // Phase 2: batched HTTP probe — one xray process, N inbounds
        val basePort = BATCH_BASE_PORT
        val portOf = HashMap<ShardNode, Int>(needHttp.size * 2)
        needHttp.forEachIndexed { i, n -> portOf[n] = basePort + i }

        val config = ShardConfigs.probeConfig(context, needHttp, basePort)
        val configFile = ShardConfigs.writeConfig(context, "real-delay-batch.json", config)
        var proc: Process? = null
        try {
            proc = launchXray(context, configFile) ?: run {
                needHttp.forEach { node ->
                    if (node !in tcpFailed) { ShardHealth.recordFailure(context, node); emit(NodeResult(node, -1L)) }
                }
                return results.toList()
            }
            if (!portAccepts(basePort, PORT_WAIT_MS) || cancelFlag()) {
                needHttp.forEach { node -> ShardHealth.recordFailure(context, node); emit(NodeResult(node, -1L)) }
                return results.toList()
            }
            val httpPool = java.util.concurrent.Executors.newFixedThreadPool(concurrency.coerceAtMost(needHttp.size))
            val httpLatch = java.util.concurrent.CountDownLatch(needHttp.size)
            needHttp.forEach { node ->
                httpPool.execute {
                    try {
                        if (cancelFlag()) { ShardHealth.recordFailure(context, node); emit(NodeResult(node, -1L)); return@execute }
                        val port = portOf.getValue(node)
                        val start = System.nanoTime()
                        val ok = ShardProbe.check(port, PROBE_TIMEOUT_MS)
                        val elapsed = (System.nanoTime() - start) / 1_000_000L
                        val ms = if (ok) elapsed.coerceAtLeast(0L) else -1L
                        if (ms >= 0) ShardHealth.recordSuccess(context, node, ms.toInt()) else ShardHealth.recordFailure(context, node)
                        emit(NodeResult(node, ms))
                    } catch (_: Exception) {
                        ShardHealth.recordFailure(context, node); emit(NodeResult(node, -1L))
                    } finally { httpLatch.countDown() }
                }
            }
            try { httpLatch.await() } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            httpPool.shutdownNow()
        } finally {
            try { proc?.destroy(); if (proc != null && !proc.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) proc.destroyForcibly() } catch (_: Exception) {}
            // Drain thread is daemon, no need to join
            try { configFile.delete() } catch (_: Exception) {}
        }
        return results.toList()
    }

    private fun httpProbeSingle(context: android.content.Context, node: ShardNode): Long {
        val port = BATCH_BASE_PORT + (Math.random() * 400).toInt()
        val config = ShardConfigs.probeConfig(context, listOf(node), port)
        val f = ShardConfigs.writeConfig(context, "real-delay-${node.key.hashCode()}.json", config)
        var proc: Process? = null
        try {
            proc = launchXray(context, f) ?: return -1L
            if (!portAccepts(port, PORT_WAIT_MS)) return -1L
            val start = System.nanoTime()
            val ok = ShardProbe.check(port, PROBE_TIMEOUT_MS)
            return if (ok) ((System.nanoTime() - start) / 1_000_000L).coerceAtLeast(0L) else -1L
        } finally {
            try { proc?.destroy(); if (proc != null && !proc.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) proc.destroyForcibly() } catch (_: Exception) {}
            try { f.delete() } catch (_: Exception) {}
        }
    }

    private fun launchXray(context: android.content.Context, configFile: java.io.File): Process? {
        val bin = java.io.File(context.applicationInfo.nativeLibraryDir, "libxray.so")
        if (!bin.exists()) return null
        val b = ProcessBuilder(bin.absolutePath, "run", "-c", configFile.absolutePath)
        b.directory(configFile.parentFile); b.redirectErrorStream(true)
        b.environment()["HOME"] = context.filesDir.absolutePath
        b.environment()["XRAY_LOCATION_ASSET"] = configFile.parent
        return try {
            val p = b.start()
            Thread({ try { java.io.BufferedReader(java.io.InputStreamReader(p.inputStream)).forEachLine { _ -> } } catch (_: Exception) {} }, "real-delay-log").apply { isDaemon = true }.also { it.start() }
            p
        } catch (_: Exception) { null }
    }

    private fun portAccepts(port: Int, timeoutMs: Int): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try { Socket().use { it.connect(InetSocketAddress("127.0.0.1", port), 300); return true } } catch (_: Exception) {}
            Thread.sleep(100)
        }
        return false
    }
}
