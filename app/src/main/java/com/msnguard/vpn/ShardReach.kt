package com.msnguard.vpn

import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Asks one question about a candidate node: will Google serve this exit, or does
 * it treat it as an unsupported country?
 *
 * ## Why this exists
 *
 * A field report showed the app connected, the routing table was correct, and the
 * page still said the service is not available in your country. The race picks the
 * node with the lowest latency, and latency says nothing about how Google
 * geolocates that node's exit. Measured on the live pool, three of nine reachable
 * exits were refused: two that Google resolves to no country at all (`ZZ`) and one
 * it resolves to the very country the user is trying to leave, despite the
 * publisher's own label claiming `US` and Cloudflare reporting `FR`.
 *
 * So the label lies, the CDN's opinion is irrelevant, and only Google's own
 * verdict counts.
 *
 * ## How it is measured, and why it is nearly free
 *
 * Google's verdict is not in any HTML it serves — the refusal is drawn
 * client-side from a boot payload ~4 KB into a ~240 KB body, so reading it
 * honestly costs a quarter of a megabyte per node. That is exactly the cost this
 * app must not pay.
 *
 * The redirect that precedes the page carries the same verdict for free. A plain
 * HTTP request to the app's own host answers `301` either way, but only for an
 * exit it intends to serve does it open a session cookie:
 *
 * ```
 * served   : 301, Set-Cookie: COMPASS=...   774 bytes
 * refused  : 301, no Set-Cookie             452 bytes
 * ```
 *
 * Validated against the expensive ground truth — Google's own country code, read
 * out of the boot payload, on the same node in the same minute — it agreed on all
 * nine reachable nodes of the live pool, including the one the phone had actually
 * chosen. Two passes per node, no disagreement.
 *
 * The check is a *named header*, not a byte count: a byte count would silently
 * invert the day Google adds a header.
 *
 * ## Why plain HTTP and not TLS
 *
 * The earlier candidate for this check needed TLS, and cost a measured +508 ms per
 * candidate. This runs on port 80, so it is one round trip with no handshake:
 * 452–774 bytes and a measured 150–2729 ms, in the same range as the liveness
 * probe the race already pays for. Nothing sensitive is exchanged — the request is
 * a bare GET for a redirect, and the answer is a redirect.
 *
 * ## Fail-open, always
 *
 * Anything other than a redirect *without* the cookie is [Verdict.UNKNOWN]:
 * connection refused, timeout, a truncated header block, an unexpected status. A
 * node is only ever excluded on positive evidence, so a check that cannot run
 * cannot cost the user a working node.
 */
object ShardReach {

    /** The app host, which answers the same redirect on port 80 as on 443. */
    private const val HOST = "gemini.google.com"
    private const val PATH = "/app"

    /**
     * Ceiling on the header block. The whole answer measured 452–774 bytes, so
     * this is generous; it exists only so a misbehaving middlebox streaming a body
     * cannot make the check read forever.
     */
    private const val MAX_HEADER_BYTES = 2048

    /**
     * A browser-shaped request. Not cosmetic: measured on a refused exit, a bare
     * `Mozilla/5.0` and a real mobile agent get *different* redirects, so the
     * shape is part of what makes the verdict reproducible.
     */
    private const val USER_AGENT =
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/140 Mobile Safari/537.36"

    enum class Verdict {
        /** Google opened a session for this exit. */
        USABLE,

        /** Google answered, and refused to open one. */
        WALLED,

        /** The check could not be completed. Never used to exclude a node. */
        UNKNOWN,
    }

    /**
     * @param socksPort loopback SOCKS5 port that reaches exactly one node.
     * @param timeoutMs budget for the whole exchange, SOCKS handshake included.
     */
    fun check(socksPort: Int, timeoutMs: Int): Verdict {
        Socket().use { socket ->
            try {
                socket.tcpNoDelay = true
                socket.soTimeout = timeoutMs
                socket.connect(InetSocketAddress("127.0.0.1", socksPort), timeoutMs)
                val output = socket.getOutputStream()
                val input = socket.getInputStream()

                if (!handshake(output, input)) return Verdict.UNKNOWN

                sendRequest(output)
                val header = readHeaderBlock(input) ?: return Verdict.UNKNOWN

                // Only a redirect carries the verdict. A 200, a 5xx or a captive
                // portal's interception says nothing about Google's opinion of the
                // exit, so it must not be read as a refusal.
                val statusLine = header.substringBefore('\n')
                if (!statusLine.contains(" 301") && !statusLine.contains(" 302")) {
                    return Verdict.UNKNOWN
                }

                // The cookie name matters: any Set-Cookie would also match a
                // consent or preference cookie, which a refused exit can still set.
                val lower = header.lowercase()
                return if (lower.contains("set-cookie:") && lower.contains("compass=")) {
                    Verdict.USABLE
                } else {
                    Verdict.WALLED
                }
            } catch (_: Exception) {
                return Verdict.UNKNOWN
            }
        }
    }

    /** SOCKS5, one method, no auth, then CONNECT by name so the node resolves it. */
    private fun handshake(output: OutputStream, input: InputStream): Boolean {
        output.write(byteArrayOf(0x05, 0x01, 0x00))
        output.flush()
        val greeting = readExactly(input, 2) ?: return false
        if (greeting[0] != 0x05.toByte() || greeting[1] != 0x00.toByte()) return false

        val hostBytes = HOST.toByteArray(Charsets.US_ASCII)
        val request = ByteArray(7 + hostBytes.size)
        request[0] = 0x05
        request[1] = 0x01 // CONNECT
        request[2] = 0x00
        request[3] = 0x03 // ATYP domain
        request[4] = hostBytes.size.toByte()
        System.arraycopy(hostBytes, 0, request, 5, hostBytes.size)
        request[5 + hostBytes.size] = 0x00 // port 80, high byte
        request[6 + hostBytes.size] = 0x50 // port 80, low byte
        output.write(request)
        output.flush()

        val reply = readExactly(input, 4) ?: return false
        if (reply[1] != 0x00.toByte()) return false
        // Consume the bound address so the stream sits at the payload.
        val addressLength = when (reply[3].toInt() and 0xFF) {
            0x01 -> 4
            0x04 -> 16
            0x03 -> (readExactly(input, 1)?.get(0)?.toInt()?.and(0xFF)) ?: return false
            else -> return false
        }
        readExactly(input, addressLength + 2) ?: return false
        return true
    }

    private fun sendRequest(output: OutputStream) {
        val request = buildString {
            append("GET ").append(PATH).append(" HTTP/1.1\r\n")
            append("Host: ").append(HOST).append("\r\n")
            append("User-Agent: ").append(USER_AGENT).append("\r\n")
            append("Accept: text/html\r\n")
            // Measured to change the answer on a refused exit; kept fixed so the
            // verdict does not depend on the phone's locale.
            append("Accept-Language: en-US,en;q=0.9\r\n")
            append("Connection: close\r\n\r\n")
        }
        output.write(request.toByteArray(Charsets.US_ASCII))
        output.flush()
    }

    /**
     * Read up to the blank line that ends the header block, and no further.
     *
     * Returns null on a truncated block, which is [Verdict.UNKNOWN] rather than a
     * refusal: a half-read answer is not evidence.
     */
    private fun readHeaderBlock(input: InputStream): String? {
        val builder = StringBuilder(1024)
        var consecutiveNewlines = 0
        while (builder.length < MAX_HEADER_BYTES) {
            val byte = input.read()
            if (byte < 0) return null
            if (byte == '\r'.code) continue
            builder.append(byte.toChar())
            if (byte == '\n'.code) {
                consecutiveNewlines++
                if (consecutiveNewlines == 2) return builder.toString()
            } else {
                consecutiveNewlines = 0
            }
        }
        return null
    }

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
