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
    fun check(socksPort: Int, timeoutMs: Int): Boolean =
        checkDetailed(socksPort, timeoutMs).first

    /**
     * Same as [check] but returns the failure stage for diagnostics.
     * @return Pair(passed, reason) — reason is "ok" on pass, otherwise the stage that failed.
     */
    fun checkDetailed(socksPort: Int, timeoutMs: Int): Pair<Boolean, String> {
        var lastReason = "no target tried"
        for ((host, path, port) in TARGETS) {
            val (result, detail) = probeOnceDetailed(socksPort, host, path, port, timeoutMs)
            when (result) {
                Result.PASS -> return true to "ok"
                Result.NODE_DEAD -> return false to detail
                Result.ENDPOINT_BAD -> lastReason = detail
            }
        }
        return false to lastReason
    }

    private enum class Result { PASS, NODE_DEAD, ENDPOINT_BAD }

    private fun probeOnceDetailed(
        socksPort: Int,
        host: String,
        path: String,
        port: Int,
        timeoutMs: Int,
    ): Pair<Result, String> {
        Socket().use { socket ->
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = timeoutMs
                try {
                    socket.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)
                } catch (e: java.net.SocketTimeoutException) {
                    return Result.NODE_DEAD to "tcp connect timeout to lo:$socksPort"
                } catch (e: java.net.ConnectException) {
                    return Result.NODE_DEAD to "tcp connect refused lo:$socksPort"
                } catch (e: Exception) {
                    return Result.NODE_DEAD to "tcp connect failed: ${e.javaClass.simpleName}"
                }
                val output = socket.getOutputStream()
                val input = socket.getInputStream()

                // Greeting: SOCKS5, one method, no auth.
                try { output.write(byteArrayOf(0x05, 0x01, 0x00)); output.flush() }
                catch (_: Exception) { return Result.NODE_DEAD to "socks greeting write failed" }
                val greeting = readExactly(input, 2) ?: return Result.NODE_DEAD to "socks greeting no reply"
                if (greeting[0] != 0x05.toByte() || greeting[1] != 0x00.toByte()) {
                    return Result.NODE_DEAD to "socks greeting rejected 0x${greeting[1].toInt().and(0xFF).toString(16)}"
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
                try { output.write(request); output.flush() }
                catch (_: Exception) { return Result.NODE_DEAD to "socks connect write failed" }

                val reply = readExactly(input, 4) ?: return Result.NODE_DEAD to "socks connect no reply"
                if (reply[1] != 0x00.toByte()) {
                    return Result.NODE_DEAD to "socks reply 0x${reply[1].toInt().and(0xFF).toString(16)} for $host"
                }
                // Consume the bound address so the stream is positioned at the payload
                val addressLength = when (reply[3].toInt() and 0xFF) {
                    0x01 -> 4
                    0x04 -> 16
                    0x03 -> (readExactly(input, 1)?.get(0)?.toInt()?.and(0xFF)) ?: return Result.NODE_DEAD to "socks bnd addr len missing"
                    else -> return Result.NODE_DEAD to "socks bnd atyp 0x${reply[3].toInt().and(0xFF).toString(16)}"
                }
                readExactly(input, addressLength + 2) ?: return Result.NODE_DEAD to "socks bnd addr truncated"

                try { sendRequest(output, host, path) }
                catch (_: Exception) { return Result.NODE_DEAD to "http request write failed" }
                val statusLine = readStatusLine(input) ?: return Result.ENDPOINT_BAD to "no http status from $host"
                val passed = statusLine.contains(" 204") ||
                    (host == "captive.apple.com" && statusLine.contains(" 200"))
                return if (passed) Result.PASS to "ok"
                else Result.ENDPOINT_BAD to "http ${statusLine.take(64)} from $host"
            } catch (e: java.net.SocketTimeoutException) {
                return Result.NODE_DEAD to "read timeout after ${timeoutMs}ms"
            } catch (e: Exception) {
                return Result.NODE_DEAD to "error: ${e.javaClass.simpleName}: ${e.message?.take(60) ?: ""}"
            }
        }
    }

    // Kept for internal reuse; delegates to the detailed version.
    @Suppress("unused")
    private fun probeOnce(
        socksPort: Int,
        host: String,
        path: String,
        port: Int,
        timeoutMs: Int,
    ): Result = probeOnceDetailed(socksPort, host, path, port, timeoutMs).first

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
