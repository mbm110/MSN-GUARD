package com.msnguard.vpn

import com.msnguard.vpn.ConnectionLog.record
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The udpgw bridge for the WARP path when the engine is BadVPN.
 *
 * badvpn's tun2socks does not issue SOCKS5 UDP ASSOCIATE. It speaks its own
 * udpgw protocol instead, and reaches the udpgw peer by issuing a SOCKS CONNECT
 * to it. Psiphon has a udpgw server listening on that address; xray has
 * [ShardSocksFront]; Tor has [TorSocksFront]. The Rust core (aether) has
 * nothing — it answers the CONNECT like any other destination and relays it
 * through the tunnel, where nothing is bound on 7300. UDP then dies, and with
 * it DNS, so Telegram (hardcoded IPs) keeps working while every site that needs
 * a name does not. This was the field symptom that motivated this class.
 *
 * What it does:
 *  - listens on [LISTEN_PORT] as a plain SOCKS5 front, no auth;
 *  - CONNECT to `127.0.0.1:7300` is answered by this class itself, which then
 *    speaks udpgw on that stream;
 *  - every other CONNECT is relayed verbatim to aether on the upstream port,
 *    which applies the routing rules and the tunnel — so a transparent pass-
 *    through, not a second routing decision;
 *  - udpgw datagrams are carried over a real SOCKS5 UDP ASSOCIATE to aether,
 *    which already implements one. DNS gets no special treatment here: the
 *    header address is usually the TUN resolver, and aether resolves it through
 *    `dns_resolve` on the same stack every other flow uses.
 *
 * Deliberately shares no state with [ShardSocksFront]. That class's byte
 * counters feed SHARD's node-rotation watchdog, so reusing it would make a
 * WARP session look like SHARD traffic and rotate nodes that do not exist.
 */
object WarpUdpgwFront {

    private const val TAG = "WarpUdpgwFront"

    /** badvpn's udpgw rendezvous, as Psiphon and the other fronts define it. */
    private const val UDPGW_HOST = "127.0.0.1"
    private const val UDPGW_PORT = 7300

    /**
     * The port this front listens on.
     *
     * 1825 is [ShardSocksFront]'s. They are never both up: this one only starts
     * on the WARP path with BadVPN, that one only on SHARD. Sharing the number
     * would be confusing in logs, so this takes the next free slot in the same
     * block.
     */
    const val LISTEN_PORT = 1827

    private const val SOCKS_VERSION = 5
    private const val CMD_CONNECT = 1
    private const val CMD_UDP_ASSOCIATE = 3
    private const val ATYP_IPV4 = 1
    private const val ATYP_DOMAIN = 3
    private const val ATYP_IPV6 = 4
    private const val REP_SUCCESS = 0
    private const val REP_GENERAL_FAILURE = 1

    // badvpn udpgw wire format, from protocol/udpgw_proto.h.
    private const val FLAG_KEEPALIVE = 1 shl 0
    private const val FLAG_REBIND = 1 shl 1
    private const val FLAG_IPV6 = 1 shl 3

    private const val UPSTREAM_CONNECT_TIMEOUT_MS = 15_000
    private const val UDP_BUFFER = 32 * 1024
    private const val ASSOCIATION_IDLE_MS = 60_000L
    private const val MAX_ASSOCIATIONS = 192

    private val running = AtomicBoolean(false)

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var connPool: ExecutorService? = null

    @Volatile
    private var acceptThread: Thread? = null

    @Volatile
    private var upstreamPort: Int = 0

    val isRunning: Boolean
        get() = running.get()

    /**
     * @param socksPort aether's SOCKS listener ([CoreConfig.SOCKS_PORT]).
     * @param context loads the persisted answers; null keeps the current set.
     */
    @Synchronized
    fun start(socksPort: Int, context: android.content.Context? = null): Boolean {
        context?.let { WarpDnsCache.configure(it) }
        if (running.get()) {
            if (upstreamPort == socksPort) {
                record("$TAG already running")
                return true
            }
            // A reconnect can replace WARP's listener with the final Exit
            // listener. Refusing the switch leaves BadVPN/DNS on the old route.
            record("$TAG switching upstream $upstreamPort → $socksPort")
            stop()
        }
        upstreamPort = socksPort
        if (socksPort <= 0) {
            record("$TAG invalid upstream port $socksPort")
            upstreamPort = 0
            return false
        }

        val server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), LISTEN_PORT))
            }
        } catch (e: Exception) {
            record("$TAG could not bind 127.0.0.1:$LISTEN_PORT: ${e.message}")
            return false
        }

        serverSocket = server
        connPool = Executors.newCachedThreadPool()
        running.set(true)

        acceptThread = Thread({
            try {
                while (running.get()) {
                    val client = try {
                        server.accept()
                    } catch (e: Exception) {
                        if (running.get()) record("$TAG accept failed: ${e.message}")
                        break
                    }
                    val pool = connPool
                    if (pool == null) {
                        closeQuietly(client)
                        break
                    }
                    try {
                        pool.execute {
                            // A pool task's uncaught exception reaches the worker's
                            // default handler and kills the process. One dead flow
                            // must never do that.
                            try {
                                handleClient(client)
                            } catch (_: Throwable) {
                                closeQuietly(client)
                            }
                        }
                    } catch (e: Exception) {
                        closeQuietly(client)
                    }
                }
            } catch (t: Throwable) {
                record("$TAG accept loop ended: ${t.message}")
            }
        }, "warp-udpgw-accept").apply { isDaemon = true }
        acceptThread?.start()

        record("$TAG listening on 127.0.0.1:$LISTEN_PORT → aether SOCKS $socksPort")
        return true
    }

    @Synchronized
    fun stop() {
        if (!running.getAndSet(false)) return
        WarpDnsCache.flush()
        associations.values.forEach { closeQuietly(it.udp) }
        associations.clear()
        val server = serverSocket
        closeQuietly(server)
        serverSocket = null
        connPool?.shutdownNow()
        connPool = null
        val accept = acceptThread
        acceptThread = null
        if (accept != null && accept !== Thread.currentThread()) {
            try { accept.join(250) } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
        }
        record("$TAG stopped")
    }

    // ---------------------------------------------------------------- SOCKS5

    private fun handleClient(client: Socket) {
        try {
            client.tcpNoDelay = true
            val input = DataInputStream(BufferedInputStream(client.getInputStream()))
            val output = BufferedOutputStream(client.getOutputStream())

            // Greeting. tun2socks offers "no authentication" only.
            if (input.read() != SOCKS_VERSION) {
                closeQuietly(client)
                return
            }
            val methodCount = input.read()
            if (methodCount < 0) {
                closeQuietly(client)
                return
            }
            input.readFully(ByteArray(methodCount))
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0x00))
            output.flush()

            // Request.
            if (input.read() != SOCKS_VERSION) {
                closeQuietly(client)
                return
            }
            val command = input.read()
            input.read() // reserved
            val addressType = input.read()
            val host = when (addressType) {
                ATYP_IPV4 -> {
                    val bytes = ByteArray(4)
                    input.readFully(bytes)
                    InetAddress.getByAddress(bytes).hostAddress.orEmpty()
                }
                ATYP_IPV6 -> {
                    val bytes = ByteArray(16)
                    input.readFully(bytes)
                    InetAddress.getByAddress(bytes).hostAddress.orEmpty()
                }
                ATYP_DOMAIN -> {
                    val length = input.read()
                    if (length <= 0) {
                        closeQuietly(client)
                        return
                    }
                    val bytes = ByteArray(length)
                    input.readFully(bytes)
                    String(bytes, Charsets.US_ASCII)
                }
                else -> {
                    replyFailure(output, REP_GENERAL_FAILURE)
                    closeQuietly(client)
                    return
                }
            }
            val port = ((input.read() and 0xFF) shl 8) or (input.read() and 0xFF)

            if (command != CMD_CONNECT) {
                // tun2socks never issues UDP ASSOCIATE itself — it uses udpgw for
                // UDP — so anything else here is a client we do not serve.
                replyFailure(output, REP_GENERAL_FAILURE)
                closeQuietly(client)
                return
            }

            // The udpgw rendezvous. Answering it ourselves is the whole point of
            // this class; relaying it to aether would send it through the tunnel,
            // where nothing is listening on 7300 and UDP dies.
            if (host == UDPGW_HOST && port == UDPGW_PORT) {
                replySuccess(output)
                serveUdpgw(client, input, output)
                return
            }

            relayToUpstream(client, host, port, output)
        } catch (_: Throwable) {
            closeQuietly(client)
        }
    }

    private fun replySuccess(output: OutputStream) {
        try {
            // Bound address 0.0.0.0:0 — tun2socks does not read it.
            output.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(), REP_SUCCESS.toByte(), 0,
                    ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0,
                )
            )
            output.flush()
        } catch (_: Exception) {}
    }

    private fun replyFailure(output: OutputStream, code: Int) {
        try {
            output.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(), code.toByte(), 0,
                    ATYP_IPV4.toByte(), 0, 0, 0, 0, 0, 0,
                )
            )
            output.flush()
        } catch (_: Exception) {}
    }

    /**
     * A transparent pass-through to aether. Every byte is relayed as-is, so
     * aether still applies its routing rules and the tunnel; this front makes no
     * routing decision of its own.
     */
    private fun relayToUpstream(client: Socket, host: String, port: Int, clientOut: OutputStream) {
        val upstream = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress("127.0.0.1", upstreamPort), UPSTREAM_CONNECT_TIMEOUT_MS)
            }
        } catch (e: Exception) {
            replyFailure(clientOut, REP_GENERAL_FAILURE)
            closeQuietly(client)
            return
        }

        try {
            val upIn = DataInputStream(BufferedInputStream(upstream.getInputStream()))
            val upOut = BufferedOutputStream(upstream.getOutputStream())

            upOut.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, 0x00))
            upOut.flush()
            if (upIn.read() != SOCKS_VERSION || upIn.read() != 0x00) {
                replyFailure(clientOut, REP_GENERAL_FAILURE)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }

            upOut.write(buildRequest(CMD_CONNECT, host, port))
            upOut.flush()

            if (upIn.read() != SOCKS_VERSION) {
                replyFailure(clientOut, REP_GENERAL_FAILURE)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }
            val reply = upIn.read()
            upIn.read() // reserved
            skipBoundAddress(upIn)

            if (reply != REP_SUCCESS) {
                // Pass aether's own code back so lwIP resets this one flow rather
                // than retrying a dead destination forever.
                replyFailure(clientOut, reply)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }

            replySuccess(clientOut)

            // Resolved on THIS thread, not inside the pump lambda: a closed socket
            // makes getInputStream() throw, and as the first statement of a bare
            // thread body that throw reaches the default handler and kills the
            // process.
            val clientIn = client.getInputStream()
            Thread({
                try {
                    pipe(clientIn, upOut)
                } catch (_: Throwable) {
                } finally {
                    closeQuietly(upstream)
                    closeQuietly(client)
                }
            }, "warp-udpgw-up").apply { isDaemon = true }.start()

            try {
                pipe(upIn, clientOut)
            } catch (_: Throwable) {
            } finally {
                closeQuietly(upstream)
                closeQuietly(client)
            }
        } catch (_: Throwable) {
            closeQuietly(upstream)
            closeQuietly(client)
        }
    }

    // ----------------------------------------------------------------- udpgw

    /**
     * Warm the DNS cache right after the tunnel is up (3.2.47, experimental).
     *
     * Re-sends the queries whose cached answers are nearly expired — or just
     * expired — through ONE SOCKS5 UDP ASSOCIATE, and offers the fresh
     * replies back to the cache. Nothing is served to any app from here, and
     * nothing is fabricated: an answer only becomes servable after a real
     * resolver answered through the real tunnel. The point is timing — by the
     * time the user opens an app, the names it will ask about are already
     * fresh, so its first query does not pay the two tunnel crossings.
     */
    fun warmDnsCache() {
        if (!running.get() || upstreamPort <= 0) return
        val port = upstreamPort
        Thread({
            try {
                val batch = WarpDnsCache.takeRefreshBatch()
                if (batch.isEmpty()) return@Thread
                record("$TAG warming ${batch.size} DNS answers")

                val control = try {
                    Socket().apply {
                        tcpNoDelay = true
                        connect(InetSocketAddress("127.0.0.1", port), UPSTREAM_CONNECT_TIMEOUT_MS)
                    }
                } catch (e: Exception) {
                    return@Thread
                }
                try {
                    val upIn = DataInputStream(BufferedInputStream(control.getInputStream()))
                    val upOut = BufferedOutputStream(control.getOutputStream())
                    upOut.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, 0x00))
                    upOut.flush()
                    if (upIn.read() != SOCKS_VERSION || upIn.read() != 0x00) return@Thread
                    upOut.write(buildRequest(CMD_UDP_ASSOCIATE, "0.0.0.0", 0))
                    upOut.flush()
                    if (upIn.read() != SOCKS_VERSION) return@Thread
                    if (upIn.read() != REP_SUCCESS) return@Thread
                    upIn.read() // reserved

                    // The UDP relay address this datagram socket must send to —
                    // parsed exactly like openAssociation does.
                    var relayHost = InetAddress.getByName("127.0.0.1")
                    when (upIn.read()) {
                        ATYP_IPV4 -> {
                            val bytes = ByteArray(4)
                            upIn.readFully(bytes)
                            if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                        }
                        ATYP_IPV6 -> {
                            val bytes = ByteArray(16)
                            upIn.readFully(bytes)
                            if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                        }
                        else -> return@Thread
                    }
                    val relayPort = ((upIn.read() and 0xFF) shl 8) or (upIn.read() and 0xFF)
                    val relay = InetSocketAddress(relayHost, relayPort)

                    val udp = DatagramSocket()
                    udp.soTimeout = 250
                    try {
                        val received = java.util.concurrent.atomic.AtomicInteger(0)
                        val reader = Thread({
                            val buf = ByteArray(UDP_BUFFER)
                            try {
                                val deadline = System.currentTimeMillis() + 8_000
                                while (System.currentTimeMillis() < deadline &&
                                    received.get() < batch.size && !udp.isClosed
                                ) {
                                    val packet = DatagramPacket(buf, buf.size)
                                    try {
                                        udp.receive(packet)
                                    } catch (_: java.net.SocketTimeoutException) {
                                        continue
                                    }
                                    val payload = decapsulateSocks5(buf, packet.length) ?: continue
                                    if (WarpDnsCache.offer(payload, ByteArray(0))) {
                                        received.incrementAndGet()
                                    }
                                }
                            } catch (_: Throwable) {
                            }
                        }, "warp-dns-warm").apply { isDaemon = true }
                        reader.start()

                        // Send the queries to the resolver that originally
                        // answered them — reproducing today's path exactly.
                        batch.forEachIndexed { index, (resolver, query) ->
                            val q = query.copyOf()
                            q[0] = ((index + 1) shr 8).toByte()
                            q[1] = ((index + 1) and 0xFF).toByte()
                            val address = try {
                                InetAddress.getByAddress(resolver)
                            } catch (_: Exception) {
                                return@forEachIndexed
                            }
                            if (address.address.size != 4) return@forEachIndexed
                            val datagram = encapsulateSocks5(address, 53, q)
                            try {
                                udp.send(DatagramPacket(datagram, datagram.size, relay))
                            } catch (_: Exception) {
                            }
                        }
                        // Give the reader its window.
                        val joinBy = System.currentTimeMillis() + 9_000
                        while (reader.isAlive && System.currentTimeMillis() < joinBy) {
                            try { Thread.sleep(100) } catch (_: InterruptedException) { break }
                        }
                        record("$TAG warm pass done: ${received.get()}/${batch.size} refreshed")
                    } finally {
                        closeQuietly(udp)
                    }
                } finally {
                    closeQuietly(control)
                }
            } catch (_: Throwable) {
            }
        }, "warp-dns-warmup").apply { isDaemon = true }.start()
    }

    private class Association(
        val udp: DatagramSocket,
        val relayHost: InetAddress,
        val relayPort: Int,
        lastUsed: Long,
    ) {
        val lastUsed = java.util.concurrent.atomic.AtomicLong(lastUsed)
    }

    private val associations = ConcurrentHashMap<Int, Association>()
    private val udpgwLock = Any()

    private fun serveUdpgw(socket: Socket, input: DataInputStream, output: OutputStream) {
        record("$TAG udpgw stream up — UDP via aether SOCKS $upstreamPort")
        associations.values.forEach { closeQuietly(it.udp) }
        associations.clear()

        val reaper = Thread({
            while (running.get() && !socket.isClosed) {
                try {
                    Thread.sleep(20_000)
                } catch (e: InterruptedException) {
                    return@Thread
                }
                if (associations.isEmpty()) continue
                val now = System.currentTimeMillis()
                associations.entries.removeAll { entry ->
                    val stale = now - entry.value.lastUsed.get() > ASSOCIATION_IDLE_MS
                    if (stale) closeQuietly(entry.value.udp)
                    stale
                }
            }
        }, "warp-udpgw-reap").apply { isDaemon = true }
        reaper.start()

        try {
            while (running.get()) {
                val low = input.read()
                if (low < 0) break
                val high = input.read()
                if (high < 0) break
                val length = (high shl 8) or low
                if (length < 0 || length > 65535) break
                val body = ByteArray(length)
                input.readFully(body)

                if (body.size < 3) continue
                val flags = body[0].toInt() and 0xFF
                val conid = ((body[2].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)

                if (flags and FLAG_KEEPALIVE != 0) {
                    // Header-only, exists purely to keep the stream warm.
                    continue
                }

                if (flags and FLAG_REBIND != 0) {
                    // The client is reusing this conid for a different flow. The old
                    // association's relay binding is wrong now, so drop it and let
                    // the code below build a fresh one.
                    associations.remove(conid)?.let { a -> closeQuietly(a.udp) }
                }

                val isIpv6 = flags and FLAG_IPV6 != 0
                val addressLength = if (isIpv6) 18 else 6
                if (body.size < 3 + addressLength) continue
                val address = body.copyOfRange(3, 3 + addressLength)
                val payload = body.copyOfRange(3 + addressLength, body.size)
                if (payload.isEmpty()) continue

                val destination = try {
                    InetAddress.getByAddress(address.copyOfRange(0, addressLength - 2))
                } catch (e: Exception) {
                    continue
                }
                val destinationPort = ((address[addressLength - 2].toInt() and 0xFF) shl 8) or
                    (address[addressLength - 1].toInt() and 0xFF)

                // 3.2.47 DNS cache: a port-53 query with a live cached answer
                // is answered HERE, before any association is opened — the
                // two tunnel crossings the answer would otherwise pay are the
                // app-open delay the field report measured on every
                // WARP-class connect. Misses and non-DNS continue untouched.
                if (destinationPort == 53 && payload.size >= 12) {
                    val cached = WarpDnsCache.lookup(payload)
                    if (cached != null) {
                        writeUdpgwReply(conid, isIpv6, address, cached, output)
                        continue
                    }
                }

                val association = associations[conid] ?: run {
                    if (associations.size >= MAX_ASSOCIATIONS) {
                        // Evict the least recently used rather than refusing: a
                        // refusal is a silently dead flow to the app.
                        val victim = associations.entries.minByOrNull { it.value.lastUsed.get() }
                        if (victim != null) {
                            associations.remove(victim.key)?.let { a -> closeQuietly(a.udp) }
                        }
                    }
                    val fresh = openAssociation(conid, output, isIpv6, address) ?: return@run null
                    associations[conid] = fresh
                    fresh
                } ?: continue

                association.lastUsed.set(System.currentTimeMillis())
                val datagram = encapsulateSocks5(destination, destinationPort, payload)
                try {
                    association.udp.send(
                        DatagramPacket(
                            datagram, datagram.size,
                            association.relayHost, association.relayPort,
                        )
                    )
                } catch (e: Exception) {
                    associations.remove(conid)?.let { a -> closeQuietly(a.udp) }
                }
            }
        } catch (_: Throwable) {
        } finally {
            associations.values.forEach { closeQuietly(it.udp) }
            associations.clear()
            closeQuietly(socket)
        }
    }

    /**
     * One SOCKS5 UDP ASSOCIATE to aether per udpgw conid, exactly as
     * [ShardSocksFront] does per xray association.
     */
    private fun openAssociation(conid: Int, output: OutputStream, isIpv6: Boolean, clientAddress: ByteArray): Association? {
        val control = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress("127.0.0.1", upstreamPort), UPSTREAM_CONNECT_TIMEOUT_MS)
            }
        } catch (e: Exception) {
            return null
        }

        return try {
            val upIn = DataInputStream(BufferedInputStream(control.getInputStream()))
            val upOut = BufferedOutputStream(control.getOutputStream())

            upOut.write(byteArrayOf(SOCKS_VERSION.toByte(), 1, 0x00))
            upOut.flush()
            if (upIn.read() != SOCKS_VERSION || upIn.read() != 0x00) {
                closeQuietly(control)
                return null
            }

            // 0.0.0.0:0 as the bind address: we do not know which local port our
            // datagrams will leave from, and aether does not require us to.
            upOut.write(buildRequest(CMD_UDP_ASSOCIATE, "0.0.0.0", 0))
            upOut.flush()

            if (upIn.read() != SOCKS_VERSION) {
                closeQuietly(control)
                return null
            }
            val reply = upIn.read()
            upIn.read() // reserved
            if (reply != REP_SUCCESS) {
                closeQuietly(control)
                return null
            }

            // The relay address is the reply's bound address, and unlike CONNECT it
            // matters here — this is where datagrams have to be sent.
            var relayHost = InetAddress.getByName("127.0.0.1")
            when (upIn.read()) {
                ATYP_IPV4 -> {
                    val bytes = ByteArray(4)
                    upIn.readFully(bytes)
                    // aether may answer 0.0.0.0, meaning "same host as the control
                    // connection". Sending there would go nowhere.
                    if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                }
                ATYP_IPV6 -> {
                    val bytes = ByteArray(16)
                    upIn.readFully(bytes)
                    if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                }
                ATYP_DOMAIN -> {
                    val len = upIn.read()
                    if (len > 0) {
                        val bytes = ByteArray(len)
                        upIn.readFully(bytes)
                        relayHost = InetAddress.getByName(String(bytes, Charsets.US_ASCII))
                    }
                }
                else -> {
                    closeQuietly(control)
                    return null
                }
            }
            val relayPort = ((upIn.read() and 0xFF) shl 8) or (upIn.read() and 0xFF)

            val udp = DatagramSocket()
            udp.soTimeout = 0

            // The association's destination port: the only flows offered to
            // the DNS cache are port-53 ones (mDNS on 5353 and QUIC on 443
            // must never be parsed as DNS).
            val clientPort = ((clientAddress[clientAddress.size - 2].toInt() and 0xFF) shl 8) or
                (clientAddress[clientAddress.size - 1].toInt() and 0xFF)
            val isDnsFlow = clientPort == 53

            // Return path: every datagram the association receives is a SOCKS5 UDP
            // reply from aether. Strip that header, reframe it as udpgw with this
            // association's conid and the address the client asked about, and write
            // it back on the shared stream. The control socket is held open for the
            // lifetime of the association — aether tears the association down when
            // the control connection closes, and this listener goes with it.
            val lastSeen = java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis())
            Thread({
                val buf = ByteArray(UDP_BUFFER)
                try {
                    while (running.get() && !udp.isClosed) {
                        val packet = DatagramPacket(buf, buf.size)
                        udp.receive(packet)
                        val payload = decapsulateSocks5(buf, packet.length) ?: continue
                        lastSeen.set(System.currentTimeMillis())
                        // 3.2.47 DNS cache: a clean DNS response on a port-53
                        // association is offered to the cache. The datagram
                        // itself still flows to the app byte-identically —
                        // caching only arms the next identical query.
                        if (isDnsFlow && payload.size >= 12) {
                            WarpDnsCache.offer(payload, clientAddress)
                        }
                        writeUdpgwReply(conid, isIpv6, clientAddress, payload, output)
                    }
                } catch (_: Throwable) {
                } finally {
                    closeQuietly(udp)
                    associations.remove(conid)
                    closeQuietly(control)
                }
            }, "warp-udpgw-relay").apply { isDaemon = true }.start()

            Association(udp, relayHost, relayPort, lastSeen.get())
        } catch (_: Throwable) {
            closeQuietly(control)
            null
        }
    }

    /**
     * Wrap a payload in a SOCKS5 UDP request header (RFC 1928 §7) for aether.
     */
    private fun encapsulateSocks5(destination: InetAddress, port: Int, payload: ByteArray): ByteArray {
        val address = destination.address
        val header = 4 + address.size + 2
        return ByteArray(header + payload.size).apply {
            // RSV RSV FRAG
            this[0] = 0
            this[1] = 0
            this[2] = 0
            this[3] = (if (address.size == 16) ATYP_IPV6 else ATYP_IPV4).toByte()
            System.arraycopy(address, 0, this, 4, address.size)
            this[4 + address.size] = ((port shr 8) and 0xFF).toByte()
            this[5 + address.size] = (port and 0xFF).toByte()
            System.arraycopy(payload, 0, this, header, payload.size)
        }
    }

    /**
     * Strip the SOCKS5 UDP reply header.
     *
     * Fragmented replies (FRAG != 0) are dropped: nothing in this path emits them,
     * and reassembling them wrongly is worse than losing a datagram.
     */
    private fun decapsulateSocks5(buffer: ByteArray, length: Int): ByteArray? {
        if (length < 10) return null
        if (buffer[2] != 0.toByte()) return null
        val header = when (buffer[3].toInt() and 0xFF) {
            ATYP_IPV4 -> 10
            ATYP_IPV6 -> 22
            ATYP_DOMAIN -> {
                val nameLength = buffer[4].toInt() and 0xFF
                5 + nameLength + 2
            }
            else -> return null
        }
        if (length <= header) return null
        return buffer.copyOfRange(header, length)
    }

    /**
     * Frame a reply for badvpn's udpgw: the conid the client used, and the
     * address it asked about rather than the datagram's real source — badvpn
     * matches on it, and aether's reply source is the resolver, not the host
     * the app dialled.
     */
    private fun writeUdpgwReply(
        conid: Int,
        isIpv6: Boolean,
        clientAddress: ByteArray,
        payload: ByteArray,
        output: OutputStream,
    ) {
        val body = ByteArray(3 + clientAddress.size + payload.size)
        body[0] = (if (isIpv6) FLAG_IPV6 else 0).toByte()
        body[1] = (conid and 0xFF).toByte()
        body[2] = ((conid shr 8) and 0xFF).toByte()
        System.arraycopy(clientAddress, 0, body, 3, clientAddress.size)
        System.arraycopy(payload, 0, body, 3 + clientAddress.size, payload.size)
        synchronized(udpgwLock) {
            try {
                output.write(body.size and 0xFF)
                output.write((body.size shr 8) and 0xFF)
                output.write(body)
                output.flush()
            } catch (e: Exception) {
                // Stream gone; the udpgw read loop will notice and exit.
            }
        }
    }

    private fun buildRequest(command: Int, host: String, port: Int): ByteArray {
        val addrBytes = InetAddress.getByName(host).address
        return when (addrBytes.size) {
            4 -> byteArrayOf(
                SOCKS_VERSION.toByte(), command.toByte(), 0, ATYP_IPV4.toByte(),
                addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3],
                ((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte(),
            )
            else -> byteArrayOf(
                SOCKS_VERSION.toByte(), command.toByte(), 0, ATYP_IPV6.toByte(),
                addrBytes[0], addrBytes[1], addrBytes[2], addrBytes[3],
                addrBytes[4], addrBytes[5], addrBytes[6], addrBytes[7],
                addrBytes[8], addrBytes[9], addrBytes[10], addrBytes[11],
                addrBytes[12], addrBytes[13], addrBytes[14], addrBytes[15],
                ((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte(),
            )
        }
    }

    private fun skipBoundAddress(input: DataInputStream) {
        when (input.read()) {
            ATYP_IPV4 -> input.skipBytes(4 + 2)
            ATYP_IPV6 -> input.skipBytes(16 + 2)
            ATYP_DOMAIN -> {
                val len = input.read()
                input.skipBytes(len + 2)
            }
            else -> input.skipBytes(4 + 2)
        }
    }

    private fun pipe(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(UDP_BUFFER)
        while (running.get()) {
            val n = input.read(buffer)
            if (n < 0) break
            synchronized(output) {
                output.write(buffer, 0, n)
                output.flush()
            }
        }
    }

    private fun closeQuietly(closeable: java.io.Closeable?) {
        try {
            closeable?.close()
        } catch (_: Exception) {}
    }
}
