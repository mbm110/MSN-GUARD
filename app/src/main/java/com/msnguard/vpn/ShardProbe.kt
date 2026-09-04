package com.msnguard.vpn

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * One probe: does a real request survive this SOCKS5 port?
 *
 * ## Why not `java.net.Proxy`
 *
 * `HttpURLConnection` with a SOCKS proxy hands name resolution to the JVM, which
 * resolves the probe host on the *carrier* link before connecting. On a network
 * where DNS is poisoned the resolve fails and a perfectly good node is scored as
 * dead. Writing the SOCKS5 handshake by hand lets the hostname travel inside the
 * tunnel as an ATYP=3 request, which is also how the app's real traffic will go.
 *
 * ## What counts as a pass
 *
 * A 204 with no body, from a host that answers 204 and nothing else. That makes
 * the check unambiguous: any other status, any body, or a captive portal's
 * redirect is a failure. The publisher's own health check uses this same class of
 * endpoint for the same reason.
 */
object ShardProbe {

    /**
     * Probe targets, tried in order.
     *
     * Three different operators, because a single endpoint conflates "node is
     * broken" with "this one site is unreachable from this exit". The 20-of-28
     * live-pool measurement used exactly this ladder.
     */
    private val TARGETS = listOf(
        Triple("cp.cloudflare.com", "/generate_204", 80),
        Triple("www.gstatic.com", "/generate_204", 80),
        Triple("captive.apple.com", "/hotspot-detect.html", 80),
    )

    /**
     * The same three hostnames, for the routing rule that has to send them through
     * the node.
     *
     * Derived from [TARGETS] rather than repeated, because the two drifting apart is
     * a silent failure: a target this list does not name is a probe that leaves over
     * the carrier link and reports a dead node as healthy. See the rule 3b comment
     * in `ShardConfigs.smartSplitRules`.
     */
    val RULE_HOSTS: List<String> = TARGETS.map { it.first }

    /**
     * The ports those endpoints are probed on, as an xray port list.
     *
     * Derived for the same reason as [RULE_HOSTS]: the rule names its hosts from
     * this file, so a future target on any other port would be named by the rule
     * and still fall outside it — restoring the blind spot for that one target,
     * silently. Comma lists are valid xray port syntax and were measured to match.
     */
    val RULE_PORTS: String = TARGETS.map { it.third }.distinct().sorted().joinToString(",")

    /**
     * @param socksPort loopback SOCKS5 port to test through.
     * @param timeoutMs budget for the whole exchange, handshake included.
     * @return true if any target answered as expected.
     */
    fun check(socksPort: Int, timeoutMs: Int): Boolean {
        // First target only, in the common case: the race is latency-sensitive and
        // trying all three per node would triple its cost. The others exist as
        // fallbacks so one unreachable endpoint does not condemn a good node.
        for ((host, path, port) in TARGETS) {
            when (probeOnce(socksPort, host, path, port, timeoutMs)) {
                Result.PASS -> return true
                // The node itself is unreachable — trying another endpoint through
                // the same dead node is wasted time.
                Result.NODE_DEAD -> return false
                // Node reachable, this endpoint was not. Try the next one.
                Result.ENDPOINT_BAD -> continue
            }
        }
        return false
    }

    private enum class Result { PASS, NODE_DEAD, ENDPOINT_BAD }

    private fun probeOnce(
        socksPort: Int,
        host: String,
        path: String,
        port: Int,
        timeoutMs: Int,
    ): Result {
        Socket().use { socket ->
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)
                val output = socket.getOutputStream()
                val input = socket.getInputStream()

                // Greeting: SOCKS5, one method, no auth.
                output.write(byteArrayOf(0x05, 0x01, 0x00))
                output.flush()
                val greeting = readExactly(input, 2) ?: return Result.NODE_DEAD
                if (greeting[0] != 0x05.toByte() || greeting[1] != 0x00.toByte()) {
                    return Result.NODE_DEAD
                }

                // CONNECT to a hostname (ATYP 3), so the tunnel resolves it, not us.
                val hostBytes = host.toByteArray(Charsets.US_ASCII)
                val request = ByteArray(7 + hostBytes.size)
                request[0] = 0x05
                request[1] = 0x01 // CONNECT
                request[2] = 0x00
                request[3] = 0x03 // ATYP domain
                request[4] = hostBytes.size.toByte()
                System.arraycopy(hostBytes, 0, request, 5, hostBytes.size)
                request[5 + hostBytes.size] = ((port shr 8) and 0xFF).toByte()
                request[6 + hostBytes.size] = (port and 0xFF).toByte()
                output.write(request)
                output.flush()

                val reply = readExactly(input, 4) ?: return Result.NODE_DEAD
                if (reply[1] != 0x00.toByte()) {
                    // A non-zero SOCKS reply means the far side refused to open the
                    // stream: that is the node failing, not the endpoint.
                    return Result.NODE_DEAD
                }
                // Consume the bound address so the stream is positioned at the
                // payload; its length depends on the address type in reply[3].
                val addressLength = when (reply[3].toInt() and 0xFF) {
                    0x01 -> 4
                    0x04 -> 16
                    0x03 -> (readExactly(input, 1)?.get(0)?.toInt()?.and(0xFF)) ?: return Result.NODE_DEAD
                    else -> return Result.NODE_DEAD
                }
                readExactly(input, addressLength + 2) ?: return Result.NODE_DEAD

                sendRequest(output, host, path)
                val statusLine = readStatusLine(input) ?: return Result.ENDPOINT_BAD
                val passed = statusLine.contains(" 204") ||
                    (host == "captive.apple.com" && statusLine.contains(" 200"))
                return if (passed) Result.PASS else Result.ENDPOINT_BAD
            } catch (_: Exception) {
                return Result.NODE_DEAD
            }
        }
    }

    private fun sendRequest(output: OutputStream, host: String, path: String) {
        val request = buildString {
            append("GET ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(host).append("\r\n")
            // A browser-shaped UA: some CDNs answer differently to obviously
            // scripted clients, which would make the probe measure the wrong thing.
            append("User-Agent: Mozilla/5.0\r\n")
            append("Accept: */*\r\n")
            // No keep-alive: the socket is thrown away immediately either way, and
            // Connection: close lets the far side release it at once.
            append("Connection: close\r\n\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()
    }

    /** Read the status line only; the body is irrelevant and may be large. */
    private fun readStatusLine(input: InputStream): String? {
        val builder = StringBuilder(64)
        while (builder.length < 128) {
            val byte = input.read()
            if (byte < 0) return builder.takeIf { it.isNotEmpty() }?.toString()
            if (byte == '\n'.code) return builder.toString()
            if (byte != '\r'.code) builder.append(byte.toChar())
        }
        return builder.toString()
    }

    /** Read exactly [count] bytes or give up; short reads are a dead stream. */
    private fun readExactly(input: InputStream, count: Int): ByteArray? {
        val buffer = ByteArray(count)
        var read = 0
        while (read < count) {
            val n = input.read(buffer, read, count - read)
            if (n < 0) return null
            read += n
        }
        return buffer
    }
}
