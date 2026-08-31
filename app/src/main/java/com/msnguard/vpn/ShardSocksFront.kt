package com.msnguard.vpn

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
import java.util.concurrent.atomic.AtomicLong

/**
 * The SOCKS5 server tun2socks talks to in SHARD mode.
 *
 * ## Why a front-end is needed at all
 *
 * tun2socks does not speak plain SOCKS for UDP. It carries every UDP flow — DNS
 * included, because `udpgw_transparent_dns = 1` — over badvpn's udpgw protocol,
 * tunnelled inside a CONNECT to `127.0.0.1:7300`. Psiphon gets away with pointing
 * tun2socks straight at its own listener only because the Psiphon *server*
 * intercepts that exact address (`UDPInterceptUdpgwServerAddress`) and does the
 * forwarding remotely.
 *
 * An xray node does no such thing. Aimed at it directly, tun2socks would ask the
 * node to CONNECT to `127.0.0.1:7300` — the node's own loopback — and every UDP
 * flow plus all DNS would die, which looks exactly like a broken tunnel.
 *
 * ```
 *   tun2socks ──CONNECT <ip:port>─────► relay ──► xray SOCKS 1824 ──► node
 *             └─CONNECT 127.0.0.1:7300─► udpgw server
 *                                          └─ per-conid SOCKS5 UDP ASSOCIATE
 *                                             ──► xray SOCKS 1824 ──► node
 * ```
 *
 * ## How this differs from [TorSocksFront]
 *
 * The wire protocol handling is the same, and deliberately so — it is proven in
 * the field. The difference is what happens to non-DNS UDP: Tor is TCP-only, so
 * that class of traffic is dropped there. xray's SOCKS inbound implements UDP
 * ASSOCIATE properly, verified against the real binary on live nodes (associate
 * granted, DNS answers returned through it), so here it is forwarded. QUIC,
 * Telegram calls and games therefore work in SHARD mode, and DNS needs no special
 * case at all — it is just UDP to port 53.
 *
 * That is also why SHARD does NOT pass `dnsOnlyUdpgw`: the flag exists because
 * Tor could only ever answer DNS, and setting it here would throw away the one
 * capability this transport has that Tor does not.
 */
object ShardSocksFront {

    private const val TAG = "ShardSocksFront"

    /** badvpn's udpgw flags, from `protocol/udpgw_proto.h`. */
    private const val FLAG_KEEPALIVE = 1 shl 0
    private const val FLAG_REBIND = 1 shl 1
    private const val FLAG_DNS = 1 shl 2
    private const val FLAG_IPV6 = 1 shl 3

    /**
     * Where tun2socks dials this front-end.
     *
     * Clear of every other port in the app: 1819 core, 1820 chain, 1821 Tor front,
     * 1822/1823 Tor SOCKS+DNS, 1824 xray's own listener.
     */
    const val LISTEN_PORT = 1825

    /** The udpgw address, the same convention Psiphon and Tor use. */
    private const val UDPGW_HOST = "127.0.0.1"
    private const val UDPGW_PORT = 7300

    private const val SOCKS_VERSION = 5
    private const val CMD_CONNECT = 1
    private const val CMD_UDP_ASSOCIATE = 3
    private const val ATYP_IPV4 = 1
    private const val ATYP_DOMAIN = 3
    private const val ATYP_IPV6 = 4

    private const val REP_SUCCESS = 0
    private const val REP_GENERAL_FAILURE = 1

    private const val RELAY_BUFFER = 32 * 1024
    private const val UPSTREAM_CONNECT_TIMEOUT_MS = 15_000

    /** Largest datagram we will relay. Above the Ethernet MTU, below jumbo. */
    private const val UDP_BUFFER = 4096

    /**
     * How long an idle UDP association is kept.
     *
     * Associations are per-conid and each holds one TCP control socket plus one
     * UDP socket, so they cannot be immortal — that is precisely the failure the
     * Tor path hit from the other direction, where never-expiring conids
     * saturated badvpn's 256-slot table and killed DNS mid-session. Expiring them
     * here keeps the slot table turning over.
     */
    private const val UDP_IDLE_TIMEOUT_MS = 60_000L

    /**
     * Ceiling on live associations.
     *
     * badvpn's own table is 256 entries; staying under it means we run out of
     * conids at the same time it does, rather than holding sockets for slots the
     * client has already recycled.
     */
    private const val MAX_ASSOCIATIONS = 192

    private val running = AtomicBoolean(false)

    /**
     * Session byte counters.
     *
     * The same reason [TorSocksFront] counts: no Go callback and no Rust core in
     * the data path, so without counting here a working tunnel would report 0 B
     * and the app's own RX verification gate would fail a healthy session.
     *
     * TCP relay bytes only. UDP is excluded so that DNS chatter alone cannot make
     * a tunnel that resolves names but carries nothing look alive.
     */
    private val txBytes = AtomicLong(0)
    private val rxBytes = AtomicLong(0)

    val sessionTx: Long get() = txBytes.get()
    val sessionRx: Long get() = rxBytes.get()

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var upstreamPort: Int = 0

    @Volatile
    private var connPool: ExecutorService? = null

    val isRunning: Boolean
        get() = running.get()

    /**
     * @param socksPort xray's SOCKS listener, i.e. [ShardManager.SOCKS_PORT].
     */
    @Synchronized
    fun start(socksPort: Int): Boolean {
        if (running.get()) {
            ConnectionLog.record("$TAG already running")
            return true
        }
        upstreamPort = socksPort

        val server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), LISTEN_PORT))
            }
        } catch (e: Exception) {
            ConnectionLog.record("$TAG could not bind 127.0.0.1:$LISTEN_PORT: ${e.message}")
            return false
        }

        serverSocket = server
        connPool = Executors.newCachedThreadPool()
        txBytes.set(0)
        rxBytes.set(0)
        running.set(true)

        Thread({
            try {
                while (running.get()) {
                    val client = try {
                        server.accept()
                    } catch (e: Exception) {
                        if (running.get()) ConnectionLog.record("$TAG accept failed: ${e.message}")
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
                ConnectionLog.record("$TAG accept loop ended: ${t.message}")
            }
        }, "shard-front-accept").apply { isDaemon = true }.start()

        ConnectionLog.record("$TAG listening on 127.0.0.1:$LISTEN_PORT → xray SOCKS $socksPort")
        return true
    }

    @Synchronized
    fun stop() {
        if (!running.getAndSet(false)) return
        closeQuietly(serverSocket)
        serverSocket = null
        connPool?.shutdownNow()
        connPool = null
        ConnectionLog.record("$TAG stopped")
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
            // this class; relaying it to the node would send it to the node's own
            // loopback.
            if (host == UDPGW_HOST && port == UDPGW_PORT) {
                replySuccess(output)
                serveUdpgw(client, input, output)
                return
            }

            relayThroughNode(client, host, port, output)
        } catch (e: Exception) {
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
        } catch (_: Exception) {
        }
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
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------ TCP relay

    /**
     * Open a SOCKS5 CONNECT on xray's listener and hand it the target verbatim.
     *
     * tun2socks only ever asks for IP literals (it is a transparent TUN and has no
     * names), and those addresses came out of DNS answers that already resolved
     * through the node — so passing them straight through is correct and leaks
     * nothing.
     */
    private fun relayThroughNode(client: Socket, host: String, port: Int, clientOut: OutputStream) {
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
                // Pass xray's own code back so lwIP resets this one flow rather
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
            // process. That exact crash was seen in the field on the Tor front.
            val clientIn = client.getInputStream()
            Thread({
                try {
                    pipe(clientIn, upOut, txBytes)
                } catch (_: Throwable) {
                } finally {
                    closeQuietly(upstream)
                    closeQuietly(client)
                }
            }, "shard-front-up").apply { isDaemon = true }.start()

            pipe(upIn, clientOut, rxBytes)
        } catch (e: Exception) {
            // Per-flow; lwIP resets the stream.
        } finally {
            closeQuietly(upstream)
            closeQuietly(client)
        }
    }

    /** SOCKS5 request bytes for [command] toward [host]:[port]. */
    private fun buildRequest(command: Int, host: String, port: Int): ByteArray {
        val literal = runCatching { InetAddress.getByName(host) }.getOrNull()
            ?.takeIf { isIpLiteral(host) }
        return if (literal != null) {
            val bytes = literal.address
            ByteArray(4 + bytes.size + 2).apply {
                this[0] = SOCKS_VERSION.toByte()
                this[1] = command.toByte()
                this[2] = 0
                this[3] = (if (bytes.size == 16) ATYP_IPV6 else ATYP_IPV4).toByte()
                System.arraycopy(bytes, 0, this, 4, bytes.size)
                this[4 + bytes.size] = ((port shr 8) and 0xFF).toByte()
                this[5 + bytes.size] = (port and 0xFF).toByte()
            }
        } else {
            val name = host.toByteArray(Charsets.US_ASCII)
            ByteArray(5 + name.size + 2).apply {
                this[0] = SOCKS_VERSION.toByte()
                this[1] = command.toByte()
                this[2] = 0
                this[3] = ATYP_DOMAIN.toByte()
                this[4] = name.size.toByte()
                System.arraycopy(name, 0, this, 5, name.size)
                this[5 + name.size] = ((port shr 8) and 0xFF).toByte()
                this[6 + name.size] = (port and 0xFF).toByte()
            }
        }
    }

    private fun isIpLiteral(host: String): Boolean =
        host.indexOf(':') >= 0 || Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)

    /** Consume a SOCKS5 reply's bound address so the stream sits at the payload. */
    private fun skipBoundAddress(input: DataInputStream) {
        when (input.read()) {
            ATYP_IPV4 -> input.readFully(ByteArray(4))
            ATYP_IPV6 -> input.readFully(ByteArray(16))
            ATYP_DOMAIN -> {
                val length = input.read()
                if (length > 0) input.readFully(ByteArray(length))
            }
        }
        input.readFully(ByteArray(2))
    }

    private fun pipe(from: InputStream, to: OutputStream, counter: AtomicLong) {
        val buffer = ByteArray(RELAY_BUFFER)
        try {
            while (true) {
                val read = from.read(buffer)
                if (read < 0) break
                to.write(buffer, 0, read)
                to.flush()
                counter.addAndGet(read.toLong())
            }
        } catch (_: Exception) {
        }
    }

    // ----------------------------------------------------------------- udpgw

    /**
     * One live UDP flow, keyed by the conid tun2socks assigned it.
     *
     * Holds both sockets an association needs: the TCP control connection (xray
     * tears the association down when it closes) and the UDP socket that carries
     * datagrams to the relay address xray handed back.
     */
    private class Association(
        val control: Socket,
        val udp: DatagramSocket,
        val relayHost: InetAddress,
        val relayPort: Int,
    ) {
        @Volatile
        var lastUsed: Long = System.currentTimeMillis()

        fun close() {
            try {
                udp.close()
            } catch (_: Exception) {
            }
            try {
                control.close()
            } catch (_: Exception) {
            }
        }
    }

    private val associations = ConcurrentHashMap<Int, Association>()

    /**
     * Serve badvpn's udpgw protocol on the stream tun2socks just opened.
     *
     * Framing, little-endian length prefix and header layout are badvpn's
     * (`protocol/udpgw_proto.h`):
     *
     * ```
     *   uint16     length of everything after this field (little-endian)
     *   uint8      flags
     *   uint16     conid (little-endian)
     *   uint8[4|16] address
     *   uint16     port (network order)
     *   uint8[]    UDP payload
     * ```
     *
     * The address and port bytes stay in network order: badvpn copies them out of
     * the IP/UDP headers and compares the echo with `BAddr_CompareOrder`, so
     * byte-swapping them would make it reject every reply.
     */
    private fun serveUdpgw(socket: Socket, input: DataInputStream, output: OutputStream) {
        ConnectionLog.record("$TAG udpgw stream up — full UDP via xray SOCKS $upstreamPort")
        // Serialises replies from every association onto the one shared stream.
        val writeLock = Any()
        associations.values.forEach { it.close() }
        associations.clear()

        val reaper = Thread({
            while (running.get() && !socket.isClosed) {
                try {
                    Thread.sleep(5_000)
                } catch (e: InterruptedException) {
                    return@Thread
                }
                val now = System.currentTimeMillis()
                associations.entries.removeAll { entry ->
                    val stale = now - entry.value.lastUsed > UDP_IDLE_TIMEOUT_MS
                    if (stale) entry.value.close()
                    stale
                }
            }
        }, "shard-front-udp-reap").apply { isDaemon = true }
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
                    associations.remove(conid)?.close()
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

                val association = associations[conid] ?: run {
                    if (associations.size >= MAX_ASSOCIATIONS) {
                        // Evict the least recently used rather than refusing: a
                        // refusal is a silently dead flow to the app.
                        associations.entries.minByOrNull { it.value.lastUsed }?.let {
                            associations.remove(it.key)?.close()
                        }
                    }
                    val fresh = openAssociation(conid, isIpv6, output, writeLock, address) ?: return@run null
                    associations[conid] = fresh
                    fresh
                } ?: continue

                association.lastUsed = System.currentTimeMillis()
                val datagram = encapsulate(destination, destinationPort, payload)
                try {
                    association.udp.send(
                        DatagramPacket(
                            datagram, datagram.size,
                            association.relayHost, association.relayPort,
                        )
                    )
                } catch (e: Exception) {
                    associations.remove(conid)?.close()
                }
            }
        } catch (e: Exception) {
            // Stream closed by tun2socks, or we are stopping.
        } finally {
            reaper.interrupt()
            associations.values.forEach { it.close() }
            associations.clear()
            closeQuietly(socket)
            ConnectionLog.record("$TAG udpgw stream closed")
        }
    }

    /**
     * Ask xray for a UDP ASSOCIATE and start pumping replies back as udpgw frames.
     *
     * Returns null when the node refuses UDP — some do — in which case that flow
     * is simply dropped. A dropped flow is recoverable (apps retry, and DNS falls
     * back to TCP); a wrong association would corrupt every later datagram on the
     * same conid.
     */
    private fun openAssociation(
        conid: Int,
        isIpv6: Boolean,
        output: OutputStream,
        writeLock: Any,
        clientAddress: ByteArray,
    ): Association? {
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
            // datagrams will leave from, and xray does not require us to.
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
                    // xray answers 0.0.0.0, meaning "same host as the control
                    // connection". Sending there would go nowhere.
                    if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                }
                ATYP_IPV6 -> {
                    val bytes = ByteArray(16)
                    upIn.readFully(bytes)
                    if (bytes.any { it != 0.toByte() }) relayHost = InetAddress.getByAddress(bytes)
                }
                ATYP_DOMAIN -> {
                    val length = upIn.read()
                    if (length > 0) {
                        val bytes = ByteArray(length)
                        upIn.readFully(bytes)
                        relayHost = runCatching {
                            InetAddress.getByName(String(bytes, Charsets.US_ASCII))
                        }.getOrDefault(relayHost)
                    }
                }
                else -> {
                    closeQuietly(control)
                    return null
                }
            }
            val relayPort = ((upIn.read() and 0xFF) shl 8) or (upIn.read() and 0xFF)
            if (relayPort <= 0) {
                closeQuietly(control)
                return null
            }

            val udp = DatagramSocket()
            udp.soTimeout = 0
            val association = Association(control, udp, relayHost, relayPort)

            Thread({
                try {
                    pumpAssociation(association, conid, isIpv6, clientAddress, output, writeLock)
                } catch (_: Throwable) {
                } finally {
                    associations.remove(conid, association)
                    association.close()
                }
            }, "shard-front-udp-$conid").apply { isDaemon = true }.start()

            // Draining the control socket too: xray closes it to signal teardown,
            // and without a reader we would keep feeding a dead association.
            Thread({
                try {
                    while (upIn.read() >= 0) {
                        // No payload is expected on this socket.
                    }
                } catch (_: Throwable) {
                } finally {
                    associations.remove(conid, association)
                    association.close()
                }
            }, "shard-front-udp-ctl-$conid").apply { isDaemon = true }.start()

            association
        } catch (e: Exception) {
            closeQuietly(control)
            null
        }
    }

    /** Read SOCKS5 UDP replies for one association and frame them back as udpgw. */
    private fun pumpAssociation(
        association: Association,
        conid: Int,
        isIpv6: Boolean,
        clientAddress: ByteArray,
        output: OutputStream,
        writeLock: Any,
    ) {
        val buffer = ByteArray(UDP_BUFFER)
        while (running.get() && !association.udp.isClosed) {
            val packet = DatagramPacket(buffer, buffer.size)
            try {
                association.udp.receive(packet)
            } catch (e: Exception) {
                return
            }
            association.lastUsed = System.currentTimeMillis()

            val payload = decapsulate(buffer, packet.length) ?: continue

            // The echoed address must be the one the client asked about, not the
            // datagram's real source — badvpn matches on it.
            val body = ByteArray(3 + clientAddress.size + payload.size)
            body[0] = (if (isIpv6) FLAG_IPV6 else 0).toByte()
            body[1] = (conid and 0xFF).toByte()
            body[2] = ((conid shr 8) and 0xFF).toByte()
            System.arraycopy(clientAddress, 0, body, 3, clientAddress.size)
            System.arraycopy(payload, 0, body, 3 + clientAddress.size, payload.size)

            synchronized(writeLock) {
                try {
                    output.write(body.size and 0xFF)
                    output.write((body.size shr 8) and 0xFF)
                    output.write(body)
                    output.flush()
                } catch (e: Exception) {
                    // Stream gone; the read loop will notice and exit.
                    return
                }
            }
        }
    }

    /** Wrap a payload in a SOCKS5 UDP request header (RFC 1928 §7). */
    private fun encapsulate(destination: InetAddress, port: Int, payload: ByteArray): ByteArray {
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
    private fun decapsulate(buffer: ByteArray, length: Int): ByteArray? {
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

    private fun closeQuietly(closeable: java.io.Closeable?) {
        try {
            closeable?.close()
        } catch (_: Exception) {
        }
    }
}
