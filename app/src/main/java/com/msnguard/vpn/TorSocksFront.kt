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
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The SOCKS5 server that tun2socks talks to in Tor mode.
 *
 * ## Why this class has to exist at all
 *
 * In Psiphon mode tun2socks is pointed straight at Psiphon's own SOCKS listener
 * and UDP works because of a coincidence of Psiphon's design: tun2socks is told
 * `udpgwServerAddress = 127.0.0.1:7300` and dials it *through* the SOCKS proxy,
 * and the Psiphon **server** intercepts that exact address
 * (`UDPInterceptUdpgwServerAddress` in tunnelServer.go) and does the UDP
 * forwarding remotely. There is no local udpgw daemon anywhere in this app.
 *
 * Tor has no such thing. Two hard facts, both verified against the sources:
 *
 *  1. **Tor's SOCKS port has no UDP ASSOCIATE.** It is CONNECT-only.
 *  2. Pointing tun2socks at Tor directly makes it try to CONNECT to
 *     `127.0.0.1:7300` *through the Tor circuit*, which Tor refuses (private
 *     address), so `SocksUdpGwClient` reconnect-loops forever.
 *
 * And UDP is not optional here, because of one line in tun2socks.c:
 *
 * ```c
 * // do nothing if we don't have udpgw
 * if (!options.udpgw_remote_server_addr) { goto fail; }
 * ```
 *
 * plus `udpgw_transparent_dns = 1`, which routes **every DNS query** down the
 * udpgw path. So with Tor and no udpgw, name resolution is dead and the app
 * looks completely broken even though the Tor circuit is fine.
 *
 * ## What this does instead
 *
 * It is the SOCKS5 server tun2socks connects to, and it splits the traffic:
 *
 * ```
 *   tun2socks ──CONNECT <any ip:port>──► relay ──► Tor SocksPort ──► circuit
 *             └─CONNECT 127.0.0.1:7300─► in-process udpgw server
 *                                          └─ DNS ──► Tor DNSPort (local UDP)
 *                                          └─ other UDP ──► dropped
 * ```
 *
 * The udpgw branch is a real implementation of badvpn's udpgw wire protocol, so
 * badvpn itself is untouched — no patching of vendored C, and the working
 * Psiphon path keeps behaving exactly as before.
 *
 * ## Why non-DNS UDP is dropped rather than proxied
 *
 * There is nowhere to send it. Tor carries TCP streams only. Dropping is the
 * correct behaviour and not a silent failure: QUIC (UDP/443) treats an
 * unanswered handshake as "no QUIC here" and browsers fall back to TCP within a
 * few hundred milliseconds. Answering with an error, or black-holing at the
 * TUN, both produce worse stalls.
 *
 * ## DNS goes to Tor's own DNSPort
 *
 * `DNSPort` is compiled into our libtor.so (verified: the `DNSPort`,
 * `DNSListenAddress` and `dnsserv` symbols are all present in the built
 * binary). It answers on plain local UDP and resolves through the circuit, so
 * there is no DNS leak and no need to hand-roll DNS-over-TCP.
 *
 * Only A/AAAA/PTR are supported by Tor's DNSPort. A Chrome HTTPS/SVCB query
 * (type 65) gets refused, which is the same answer Chrome gets from plenty of
 * real resolvers, and it falls back without a stall.
 */
object TorSocksFront {

    private const val TAG = "TorSocksFront"

    /** badvpn's udpgw flags, from `protocol/udpgw_proto.h`. */
    private const val FLAG_KEEPALIVE = 1 shl 0
    private const val FLAG_REBIND = 1 shl 1
    private const val FLAG_DNS = 1 shl 2
    private const val FLAG_IPV6 = 1 shl 3

    /**
     * The address tun2socks is told to reach udpgw on.
     *
     * Must match what [Tun2SocksManager] passes, and it is deliberately the same
     * 127.0.0.1:7300 Psiphon uses: keeping one convention means the udpgw code
     * path in badvpn is identical in both modes, and only the far end differs.
     */
    private const val UDPGW_HOST = "127.0.0.1"
    private const val UDPGW_PORT = 7300

    private const val SOCKS_VERSION = 5
    private const val CMD_CONNECT = 1
    private const val ATYP_IPV4 = 1
    private const val ATYP_DOMAIN = 3
    private const val ATYP_IPV6 = 4

    private const val REP_SUCCESS = 0
    private const val REP_GENERAL_FAILURE = 1
    private const val REP_CMD_NOT_SUPPORTED = 7

    private const val RELAY_BUFFER = 32 * 1024
    private const val TOR_CONNECT_TIMEOUT_MS = 30_000
    private const val DNS_TIMEOUT_MS = 10_000

    /**
     * Maximum DNS answer we will read back from Tor's DNSPort.
     *
     * 4096 covers EDNS0-advertised sizes; anything larger is a truncated-reply
     * case the resolver handles by retrying over TCP, which goes through the
     * CONNECT path instead.
     */
    private const val DNS_BUFFER = 4096

    private val running = AtomicBoolean(false)

    /**
     * Session byte counters.
     *
     * Tor mode has no other source of traffic numbers: the Rust core is not in
     * the data path and there is no Psiphon `onBytesTransferred` callback, so
     * without counting here the UI would show a connected tunnel moving 0 B —
     * which is exactly what every "fake connected" bug in this project looked
     * like, and would also break the app's own RX verification gate.
     *
     * Counted at the relay because that is the one place all tunnelled bytes
     * pass through. DNS is excluded on purpose: a few hundred bytes of lookups
     * would let a Tor session that resolves names but carries no real traffic
     * look alive.
     *
     * `tx`/`rx` are from the device's point of view — tx is what the phone sent.
     */
    private val txBytes = java.util.concurrent.atomic.AtomicLong(0)
    private val rxBytes = java.util.concurrent.atomic.AtomicLong(0)

    val sessionTx: Long get() = txBytes.get()
    val sessionRx: Long get() = rxBytes.get()

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    private var torSocksPort: Int = 0

    @Volatile
    private var torDnsPort: Int = 0

    /**
     * Threads for in-flight DNS lookups.
     *
     * Bounded on purpose: each task holds one ephemeral UDP socket for at most
     * [DNS_TIMEOUT_MS], and a burst of queries from a page load must not turn
     * into an unbounded thread count on a phone. 8 concurrent lookups is more
     * than a browser will usefully pipeline through a single Tor circuit.
     */
    @Volatile
    private var dnsPool: ExecutorService? = null

    @Volatile
    private var connPool: ExecutorService? = null

    val isRunning: Boolean
        get() = running.get()

    /**
     * Bind the front-end.
     *
     * @param listenPort what tun2socks will dial as its SOCKS server.
     * @param socksPort Tor's `SocksPort`.
     * @param dnsPort Tor's `DNSPort`.
     */
    @Synchronized
    fun start(listenPort: Int, socksPort: Int, dnsPort: Int): Boolean {
        if (running.get()) {
            ConnectionLog.record("$TAG already running")
            return true
        }
        torSocksPort = socksPort
        torDnsPort = dnsPort

        val server = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), listenPort))
            }
        } catch (e: Exception) {
            ConnectionLog.record("$TAG could not bind 127.0.0.1:$listenPort: ${e.message}")
            return false
        }

        serverSocket = server
        dnsPool = Executors.newFixedThreadPool(8)
        connPool = Executors.newCachedThreadPool()
        // Zeroed per session so the service's traffic deltas start from a known
        // baseline; a restart must not look like a sudden burst.
        txBytes.set(0)
        rxBytes.set(0)
        running.set(true)

        Thread({
            // The accept loop must outlive anything a single connection can do.
            // It is a bare thread, so an escape here would reach the default
            // handler and kill the process rather than merely stop accepting.
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
                            // A pool task's uncaught exception reaches the worker
                            // thread's default handler and kills the process, exactly
                            // like a bare Thread. handleClient guards itself, but the
                            // guarantee belongs here so it cannot be lost by an edit
                            // inside it.
                            try {
                                handleClient(client)
                            } catch (_: Throwable) {
                                closeQuietly(client)
                            }
                        }
                    } catch (e: Exception) {
                        // Pool shut down between accept and submit.
                        closeQuietly(client)
                    }
                }
            } catch (t: Throwable) {
                ConnectionLog.record("$TAG accept loop ended: ${t.message}")
            }
        }, "tor-front-accept").apply { isDaemon = true }.start()

        ConnectionLog.record(
            "$TAG listening on 127.0.0.1:$listenPort → Tor SOCKS $socksPort, DNS $dnsPort"
        )
        return true
    }

    @Synchronized
    fun stop() {
        if (!running.getAndSet(false)) return
        closeQuietly(serverSocket)
        serverSocket = null
        dnsPool?.shutdownNow()
        dnsPool = null
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

            // Greeting. tun2socks offers "no authentication" only, because we
            // pass no credentials to BSocksClient.
            val version = input.read()
            if (version != SOCKS_VERSION) {
                closeQuietly(client)
                return
            }
            val methodCount = input.read()
            if (methodCount <= 0) {
                closeQuietly(client)
                return
            }
            val methods = ByteArray(methodCount)
            input.readFully(methods)
            if (methods.none { it.toInt() == 0 }) {
                // 0xFF = no acceptable method.
                output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0xFF.toByte()))
                output.flush()
                closeQuietly(client)
                return
            }
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

            val host: String
            val rawAddress: ByteArray
            when (addressType) {
                ATYP_IPV4 -> {
                    rawAddress = ByteArray(4).also { input.readFully(it) }
                    host = InetAddress.getByAddress(rawAddress).hostAddress ?: ""
                }
                ATYP_IPV6 -> {
                    rawAddress = ByteArray(16).also { input.readFully(it) }
                    host = InetAddress.getByAddress(rawAddress).hostAddress ?: ""
                }
                ATYP_DOMAIN -> {
                    val length = input.read()
                    if (length <= 0) {
                        closeQuietly(client)
                        return
                    }
                    rawAddress = ByteArray(length).also { input.readFully(it) }
                    host = String(rawAddress, Charsets.US_ASCII)
                }
                else -> {
                    replyFailure(output, REP_GENERAL_FAILURE)
                    closeQuietly(client)
                    return
                }
            }
            val port = ((input.read() and 0xFF) shl 8) or (input.read() and 0xFF)

            if (command != CMD_CONNECT) {
                // UDP ASSOCIATE and BIND are genuinely unsupported: Tor cannot
                // carry either. tun2socks never asks for them.
                replyFailure(output, REP_CMD_NOT_SUPPORTED)
                closeQuietly(client)
                return
            }

            if (host == UDPGW_HOST && port == UDPGW_PORT) {
                // Report success on the SOCKS layer first — SocksUdpGwClient
                // waits for BSOCKSCLIENT_EVENT_UP before it starts framing
                // udpgw packets onto the stream.
                replySuccess(output)
                serveUdpgw(client, input, output)
                return
            }

            relayThroughTor(client, host, port, output)
        } catch (e: Exception) {
            closeQuietly(client)
        }
    }

    private fun replySuccess(output: OutputStream) {
        // BND.ADDR/BND.PORT are ignored by tun2socks for CONNECT, so a zero
        // IPv4 address is fine and is what most SOCKS servers emit.
        output.write(
            byteArrayOf(
                SOCKS_VERSION.toByte(), REP_SUCCESS.toByte(), 0, ATYP_IPV4.toByte(),
                0, 0, 0, 0, 0, 0,
            )
        )
        output.flush()
    }

    private fun replyFailure(output: OutputStream, code: Int) {
        try {
            output.write(
                byteArrayOf(
                    SOCKS_VERSION.toByte(), code.toByte(), 0, ATYP_IPV4.toByte(),
                    0, 0, 0, 0, 0, 0,
                )
            )
            output.flush()
        } catch (_: Exception) {
        }
    }

    // ------------------------------------------------------------ TCP relay

    private fun isIpLiteral(host: String): Boolean =
        host.indexOf(':') >= 0 || // bare IPv6
            Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host) // IPv4

    /**
     * Chain a CONNECT onto Tor's SOCKS port.
     *
     * tun2socks only ever asks for raw IP addresses — it is a transparent TUN
     * and has no names. That is not a DNS leak: the address it asks for came
     * out of a DNS answer that [serveUdpgw] already resolved *through* Tor.
     */
    private fun relayThroughTor(client: Socket, host: String, port: Int, clientOut: OutputStream) {
        val upstream = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress("127.0.0.1", torSocksPort), TOR_CONNECT_TIMEOUT_MS)
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

            // Pass the target to Tor exactly as we got it. An IP literal goes as
            // an IP (the common case: tun2socks has no names). A HOSTNAME must
            // go through as ATYP_DOMAIN so TOR resolves it inside the circuit —
            // resolving here first both leaks the name to the carrier resolver
            // and hands Tor an address it may reject ("private address"), which
            // is what the field log caught.
            // ⚠️ The first three bytes are NOT optional and are easy to lose in a
            // refactor: ByteArray() is zero-filled, so omitting them sends
            // `00 00 00 …` and Tor answers "Socks version 0 not recognized. (This
            // port is not an HTTP proxy…)" for every single flow — a fully
            // bootstrapped circuit that carries nothing. That is exactly what the
            // first field build did, hundreds of times per session.
            val request: ByteArray = if (isIpLiteral(host)) {
                val addressBytes = InetAddress.getByName(host).address
                val addressType = if (addressBytes.size == 16) ATYP_IPV6 else ATYP_IPV4
                ByteArray(4 + addressBytes.size + 2).apply {
                    this[0] = SOCKS_VERSION.toByte()
                    this[1] = CMD_CONNECT.toByte()
                    this[2] = 0
                    this[3] = addressType.toByte()
                    System.arraycopy(addressBytes, 0, this, 4, addressBytes.size)
                    this[4 + addressBytes.size] = ((port shr 8) and 0xFF).toByte()
                    this[5 + addressBytes.size] = (port and 0xFF).toByte()
                }
            } else {
                val name = host.toByteArray(Charsets.US_ASCII)
                check(name.size <= 255) { "hostname too long" }
                ByteArray(5 + name.size + 2).apply {
                    this[0] = SOCKS_VERSION.toByte()
                    this[1] = CMD_CONNECT.toByte()
                    this[2] = 0
                    this[3] = ATYP_DOMAIN.toByte()
                    this[4] = name.size.toByte()
                    System.arraycopy(name, 0, this, 5, name.size)
                    this[5 + name.size] = ((port shr 8) and 0xFF).toByte()
                    this[6 + name.size] = (port and 0xFF).toByte()
                }
            }
            upOut.write(request)
            upOut.flush()

            // Tor's reply. Read it fully so the stream is positioned at payload.
            if (upIn.read() != SOCKS_VERSION) {
                replyFailure(clientOut, REP_GENERAL_FAILURE)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }
            val reply = upIn.read()
            upIn.read() // reserved
            when (upIn.read()) {
                ATYP_IPV4 -> upIn.readFully(ByteArray(4))
                ATYP_IPV6 -> upIn.readFully(ByteArray(16))
                ATYP_DOMAIN -> {
                    val length = upIn.read()
                    if (length > 0) upIn.readFully(ByteArray(length))
                }
            }
            upIn.readFully(ByteArray(2)) // bound port

            if (reply != REP_SUCCESS) {
                // Pass Tor's own failure code back so lwIP resets that one flow
                // instead of retrying a dead exit forever.
                replyFailure(clientOut, reply)
                closeQuietly(upstream)
                closeQuietly(client)
                return
            }

            replySuccess(clientOut)

            // Downstream on this thread, upstream on one more. Closing both
            // sockets when either direction ends is what stops half-open
            // sockets accumulating on a phone.
            //
            // getInputStream() is resolved HERE, inside this guarded scope,
            // and not inside the pump lambda. Socket.getInputStream() throws
            // SocketException("Socket is closed") the moment the socket is
            // closed, and as the first statement of a bare Thread body that
            // throw had nothing above it to catch: a raw thread's uncaught
            // exception reaches the default handler, which kills the whole
            // process. A field crash arrived on exactly that line — Tor's
            // front proxy died and took the app with it — because the flow can
            // be torn down in the window between start() and the lambda's
            // first statement: either direction finishing closes both sockets,
            // and stop() closes every one of them at once.
            //
            // Resolved on the owning thread the throw lands in the enclosing
            // catch instead, which is the correct outcome: one dead flow,
            // reset by lwIP, and a tunnel that stays up.
            val clientIn = client.getInputStream()
            val pump = Thread({
                try {
                    pipe(clientIn, upOut, txBytes)
                } catch (_: Throwable) {
                    // Per-flow and unreportable, but never fatal. A relay
                    // thread for one TCP flow must not be able to end the
                    // session, whatever it hits.
                } finally {
                    closeQuietly(upstream)
                    closeQuietly(client)
                }
            }, "tor-front-up").apply { isDaemon = true }
            pump.start()

            pipe(upIn, clientOut, rxBytes)
        } catch (e: Exception) {
            // Nothing useful to report per-flow; lwIP will reset the stream.
        } finally {
            closeQuietly(upstream)
            closeQuietly(client)
        }
    }

    private fun pipe(
        from: InputStream,
        to: OutputStream,
        counter: java.util.concurrent.atomic.AtomicLong,
    ) {
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

    // ---------------------------------------------------------- udpgw server

    /**
     * Speak badvpn's udpgw protocol on an established stream.
     *
     * Wire format, from `protocol/packetproto.h` and `protocol/udpgw_proto.h`:
     *
     * ```
     *   uint16 LE  length of everything that follows
     *   uint8      flags        (KEEPALIVE 1, REBIND 2, DNS 4, IPV6 8)
     *   uint16 LE  conid
     *   [ipv4] uint32 addr, uint16 port      <- both NETWORK byte order
     *   [ipv6] uint8[16] addr, uint16 port
     *   uint8[]    UDP payload
     * ```
     *
     * The address bytes are network order because badvpn copies them straight
     * out of the IP and UDP headers (`BAddr_InitIPv4(&remote_addr,
     * ipv4_header.destination_address, udp_header.dest_port)`) and writes them
     * back out unswapped. Byte-swapping them here would make the client's
     * `BAddr_CompareOrder` check reject every reply.
     */
    private fun serveUdpgw(socket: Socket, input: DataInputStream, output: OutputStream) {
        ConnectionLog.record("$TAG udpgw stream up — DNS via Tor DNSPort $torDnsPort")
        // Serialises replies from the DNS pool onto the one shared stream.
        val writeLock = Any()
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

                // header is flags(1) + conid(2)
                if (body.size < 3) continue
                val flags = body[0].toInt() and 0xFF
                val conid = ((body[2].toInt() and 0xFF) shl 8) or (body[1].toInt() and 0xFF)

                if (flags and FLAG_KEEPALIVE != 0) {
                    // Header-only packet whose entire purpose is to keep the
                    // stream warm. There is nothing to answer.
                    continue
                }

                val isIpv6 = flags and FLAG_IPV6 != 0
                val addressLength = if (isIpv6) 18 else 6
                if (body.size < 3 + addressLength) continue
                val address = body.copyOfRange(3, 3 + addressLength)
                val payload = body.copyOfRange(3 + addressLength, body.size)

                val port = ((address[addressLength - 2].toInt() and 0xFF) shl 8) or
                    (address[addressLength - 1].toInt() and 0xFF)

                // Two ways a query counts as DNS: the transparent-DNS flag that
                // tun2socks sets for traffic aimed at the TUN's own resolver
                // address, and an explicit query to port 53 from an app that
                // hardcodes 8.8.8.8. Both must work or those apps go dark.
                val isDns = (flags and FLAG_DNS != 0) || port == 53
                if (!isDns || payload.isEmpty()) continue

                val pool = dnsPool ?: break
                try {
                    pool.execute {
                        // Same reason as the connection pool in start(): an
                        // uncaught throw here would kill the process, not just
                        // this query.
                        try {
                            resolveThroughTor(payload, conid, address, isIpv6, output, writeLock)
                        } catch (_: Throwable) {
                        }
                    }
                } catch (e: Exception) {
                    // Shutting down.
                    break
                }
            }
        } catch (e: Exception) {
            // Stream closed by tun2socks, or we are stopping.
        } finally {
            closeQuietly(socket)
            ConnectionLog.record("$TAG udpgw stream closed")
        }
    }

    private fun resolveThroughTor(
        query: ByteArray,
        conid: Int,
        address: ByteArray,
        isIpv6: Boolean,
        output: OutputStream,
        writeLock: Any,
    ) {
        val answer = try {
            DatagramSocket().use { socket ->
                socket.soTimeout = DNS_TIMEOUT_MS
                socket.send(
                    DatagramPacket(
                        query, query.size,
                        InetAddress.getByName("127.0.0.1"), torDnsPort,
                    )
                )
                val buffer = ByteArray(DNS_BUFFER)
                val response = DatagramPacket(buffer, buffer.size)
                socket.receive(response)
                buffer.copyOf(response.length)
            }
        } catch (e: Exception) {
            // A timeout is normal for query types Tor's DNSPort will not answer
            // (HTTPS/SVCB, SRV). Staying silent makes the client's resolver
            // retry or fall back, which is the correct outcome.
            return
        }

        val body = ByteArray(3 + address.size + answer.size)
        body[0] = (if (isIpv6) FLAG_IPV6 else 0).toByte()
        body[1] = (conid and 0xFF).toByte()
        body[2] = ((conid shr 8) and 0xFF).toByte()
        System.arraycopy(address, 0, body, 3, address.size)
        System.arraycopy(answer, 0, body, 3 + address.size, answer.size)

        synchronized(writeLock) {
            try {
                output.write(body.size and 0xFF)
                output.write((body.size shr 8) and 0xFF)
                output.write(body)
                output.flush()
            } catch (e: Exception) {
                // Stream gone; the read loop will notice and exit.
            }
        }
    }

    private fun closeQuietly(closeable: java.io.Closeable?) {
        try {
            closeable?.close()
        } catch (_: Exception) {
        }
    }
}
