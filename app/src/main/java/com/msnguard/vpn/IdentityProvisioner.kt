package com.msnguard.vpn

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL

/**
 * Provisions a WARP identity for a fresh install on a carrier that has blocked
 * api.cloudflareclient.com.
 *
 * ## The problem
 *
 * WireGuard and MASQUE cannot handshake until the core has registered a device
 * against the Cloudflare account API. On a clean install there is no saved
 * identity, so [MsnGuardVpnService] has to make that call from the device's own
 * link. On an Iranian carrier that lookup is poisoned and the TLS handshake to
 * the API is dropped, so registration fails and every WARP-based transport fails
 * with it — the "no transport carried traffic on this network" report from a
 * phone that has never connected before, while a phone that connected once keeps
 * working because its identity file is already on disk.
 *
 * ## The fix
 *
 * SHARD is the one transport that does not depend on the account API at all:
 * xray dials its own nodes with credentials shipped in the subscription. So the
 * working order is to bring SHARD up, then register through its SOCKS listener,
 * then hand the saved identity back to the transport the user actually wanted.
 *
 * The core does its half through [CoreConfig.SOCKS_PROXY_KEY]: when that key is
 * present the account API and the camouflaged route both ride the SOCKS
 * listener instead of the carrier. This class owns the orchestration around it —
 * decide whether it is needed, get a SHARD listener, clear the key afterwards.
 *
 * ## Why the detection is a direct probe and not a retry counter
 *
 * Retrying registration N times and concluding "filtered" cannot tell a blocked
 * carrier from a phone in airplane mode, and a phone that has no data at all
 * must not be told its carrier is filtering anything. One attempt to reach the
 * API directly answers both questions: it either responds (not filtered — the
 * failure is elsewhere) or it does not (filtered — provision through SHARD).
 */
object IdentityProvisioner {

    private const val TAG = "IdentityProvisioner"

    /**
     * Whether a WARP/MASQUE identity is already saved for [protocol].
     *
     * Mirrors `load_or_provision_warp` / `load_or_provision_masque` in main.rs:
     * the core loads `aether.toml` (+ the protocol's suffix) and only registers
     * when that file has no usable credentials. Checking the same file from
     * Kotlin keeps this class from running a SHARD session for a phone that
     * already has what it needs.
     */
    fun hasIdentity(context: Context, protocol: String): Boolean {
        // Mirrors config_path in CoreConfig.json and derive_sibling_path in main.rs.
        val base = File(context.filesDir, "aether.toml")
        val configPath = when (protocol.lowercase()) {
            "masque" -> siblingFile(base, "masque")
            "gool", "warp-in-warp", "wow" -> siblingFile(base, "gool")
            else -> base
        }
        if (!configPath.exists()) return false
        return try {
            val toml = configPath.readText()
            // The account fields the core itself checks: account_id / token
            // (device registration) and the masque certificate. A file that
            // carries none of them is a placeholder, not an identity.
            toml.contains("account_id") || toml.contains("account_token") ||
                toml.contains("certificate") || toml.contains("private_key")
        } catch (e: Exception) {
            Log.w(TAG, "could not read ${configPath.name}: ${e.message}")
            false
        }
    }

    /**
     * `base` with [suffix] inserted before the extension, the same way
     * derive_sibling_path does it in the Rust core.
     */
    private fun siblingFile(base: File, suffix: String): File {
        val name = base.name
        val dot = name.lastIndexOf('.')
        return if (dot > 0) {
            File(base.parentFile, "${name.substring(0, dot)}-$suffix${name.substring(dot)}")
        } else {
            File(base.parentFile, "$name-$suffix")
        }
    }

    /**
     * Does the device's own link reach the account API?
     *
     * One request, short timeout, no retries: the answer is a boolean, not a
     * statistic. A 4xx/5xx response still proves the API is reachable — the
     * payload was malformed or the rate limit kicked in, but the route is open —
     * so only a total failure to get any HTTP status counts as filtered.
     *
     * Deliberately conservative on Iran: a plain GET on /reg answers quickly
     * while the POST that actually registers is dropped deeper in the stack
     * (the payload and headers are what the GCG objects to, not the hostname).
     * So this only trusts a response when it looks like the real call can get
     * through — a probe that proves nothing would send every fresh install
     * down a 100-second path that cannot end well.
     */
    fun accountApiReachable(context: Context): Boolean {
        return try {
            // A POST, not a GET: on an Iranian carrier a plain GET on /reg
            // answers while the real registration is dropped once its payload
            // appears — the probe has to exercise the same shape of request to
            // mean anything. A 4xx still proves the route is open; only the
            // inability to get any status counts as filtered.
            val connection = URL(API_REGISTER_URL).openConnection() as HttpURLConnection
            connection.connectTimeout = 8000
            connection.readTimeout = 8000
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("CF-Client-Version", CLIENT_VERSION)
            connection.doOutput = true
            connection.outputStream.use { it.write(PROBE_BODY.toByteArray()) }
            connection.responseCode in 200..599
        } catch (e: Exception) {
            Log.i(TAG, "account API not reachable directly: ${e.message}")
            false
        }
    }

    /**
     * Bring SHARD up just far enough to have a SOCKS listener, starting it
     * ourselves when one is not already running.
     *
     * xray is a standalone process that binds 127.0.0.1:1824 — it needs no
     * Android TUN, no tun2socks and no [ShardSocksFront], so provisioning can
     * raise it in the background while the user's screen still says
     * "WireGuard", register through its listener, then take it back down.
     *
     * Returns the listener address to route the account API through, or null
     * when SHARD could not produce one. When the listener already exists it is
     * left alone, because tearing down a working tunnel the user is relying on
     * to start our own would be destructive.
     */
    fun ensureShardListener(context: Context): String? {
        if (ShardManager.isRunning) {
            Log.i(TAG, "SHARD already running; reusing its listener")
            return "127.0.0.1:${ShardManager.liveSocksPort}"
        }
        ConnectionLog.record("Identity: starting SHARD to provision through it")
        // On a worker thread: start() races the node pool and blocks until a
        // listener accepts, which can take the full race budget.
        // Written by the starter thread, read by this one.
        @Volatile var started = false
        Thread({
            started = try {
                ShardManager.start(context)
            } catch (e: Exception) {
                Log.w(TAG, "SHARD would not start for provisioning: ${e.message}")
                ConnectionLog.record("Identity: SHARD start failed — ${e.message}")
                false
            }
            if (!started) {
                ConnectionLog.record(
                    "Identity: SHARD start failed — " +
                        "${ShardManager.lastError.ifBlank { "no node answered" }}"
                )
            }
        }, "identity-shard-start").start()
        // Wait for that thread's result: the caller is already on a worker
        // thread (startTunnel), so blocking here costs nothing.
        val deadline = System.currentTimeMillis() + START_BUDGET_MS
        while (System.currentTimeMillis() < deadline) {
            if (ShardManager.isRunning) {
                return "127.0.0.1:${ShardManager.liveSocksPort}"
            }
            if (!started && ShardManager.lastError.isNotEmpty()) break
            try {
                Thread.sleep(200)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return null
            }
        }
        return null
    }

    /**
     * Take the SHARD session this class raised back down.
     *
     * Only when [ensureShardListener] started it: a listener that was already
     * live when provisioning began belongs to the user's own session and must
     * survive it. Called after the identity is saved (or the attempt gave up),
     * so the transport the user actually wanted starts from a clean slate.
     */
    fun releaseShardListener(startedOurselves: Boolean) {
        if (!startedOurselves) return
        if (!ShardManager.isRunning) return
        ConnectionLog.record("Identity: stopping the SHARD session used for provisioning")
        ShardManager.stop()
    }

    /**
     * Register a WARP identity through the SHARD SOCKS listener, without
     * involving the core.
     *
     * The core is not started at this point — nothing else is up — so this
     * speaks SOCKS5 itself and POSTs the registration the way the core would
     * have. On success the identity is written to the file the core will read
     * on the user's next connect, so the transport they actually wanted starts
     * from a saved identity and never has to call the API.
     *
     * Returns the saved file on success, null otherwise.
     */
    fun provisionThroughShard(
        context: Context,
        protocol: String,
        socksPort: Int,
    ): File? {
        val socks = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", socksPort))
        val body = JSONObject().apply {
            // The core's own registration body in account::register. install_id
            // and fcm_token are empty there too; a fresh device has neither.
            put("install_id", "")
            put("fcm_token", "")
            put("tos", nowIso())
            put("model", android.os.Build.MODEL)
            put("serial_number", android.os.Build.SERIAL ?: "unknown")
            put("locale", java.util.Locale.getDefault().toString())
            put("key_type", "curve25519")
            put("tunnel_type", "wireguard")
        }
        return try {
            val connection = URL(API_REGISTER_URL).openConnection(socks) as HttpURLConnection
            connection.connectTimeout = 20_000
            connection.readTimeout = 20_000
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("CF-Client-Version", CLIENT_VERSION)
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            val code = connection.responseCode
            if (code !in 200..299) {
                Log.w(TAG, "registration through SHARD returned HTTP $code")
                return null
            }
            val response = connection.inputStream.bufferedReader().readText()
            val parsed = JSONObject(response)
            saveIdentity(context, protocol, parsed)
        } catch (e: Exception) {
            Log.w(TAG, "registration through SHARD failed: ${e.message}")
            null
        }
    }

    /**
     * Write the identity in the TOML shape [config] expects.
     *
     * The core's [PersistedIdentity] is a flat table, not the nested `[peer]` /
     * `[account]` layout this used to emit. Drifting from it would have made the
     * file parse cleanly into an identity with empty credentials — the core
     * would load it, find nothing to handshake with, and register again,
     * silently undoing everything this class just did.
     */
    private fun saveIdentity(context: Context, protocol: String, response: JSONObject): File? {
        return try {
            val config = response.optJSONObject("config")
                ?: response.optJSONObject("peer_config")
                ?: return null
            // The fields PersistedIdentity serializes. Empty strings are the
            // core's own defaults for the ones this transport does not use.
            val toml = buildString {
                appendLine("device_id = \"${response.optString("id")}\"")
                appendLine("access_token = \"${response.optString("token")}\"")
                appendLine("cert_pem = \"\"")
                appendLine("key_pem = \"\"")
                appendLine("cert_issued_at = 0")
                appendLine("ipv4 = \"${config.optString("interface")}\"")
                appendLine("ipv6 = \"${config.optString("interface_v6")}\"")
                appendLine("wg_private_key = \"${response.optString("private_key")}\"")
                appendLine("wg_peer_public_key = \"${config.optString("public_key")}\"")
                appendLine("client_id = \"${response.optString("client_id")}\"")
                appendLine("organization = \"\"")
                appendLine("gateway_proxy = \"\"")
                appendLine("assigned_endpoint = \"${config.optString("endpoint")}\"")
            }
            val base = File(context.filesDir, "aether.toml")
            val target = when (protocol.lowercase()) {
                "masque" -> siblingFile(base, "masque")
                "gool", "warp-in-warp", "wow" -> siblingFile(base, "gool")
                else -> base
            }
            target.writeText(toml)
            Log.i(TAG, "saved a WARP identity to ${target.name} via SHARD")
            target
        } catch (e: Exception) {
            Log.w(TAG, "could not save the identity: ${e.message}")
            null
        }
    }

    private fun nowIso(): String =
        java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", java.util.Locale.US)
            .format(java.util.Date())

    private const val API_REGISTER_URL = "https://api.cloudflareclient.com/v0a4471/reg"
    private const val USER_AGENT = "okhttp/3.12.1"
    private const val CLIENT_VERSION = "a-6.41-2158"
    private const val DEFAULT_ENDPOINT = "162.159.192.1:2408"

    /**
     * The body [accountApiReachable] POSTs to see whether the carrier will let
     * a real registration through.
     *
     * Deliberately invalid: a 400 is still a "yes, the route is open", and a
     * valid body would burn a device slot on every probe.
     */
    private const val PROBE_BODY = "{}"

    /**
     * How long [ensureShardListener] waits for xray to race the pool and bind.
     *
     * [ShardManager.MAX_RACE_SLICES] × [ShardManager.RACE_BUDGET_MS] is the
     * worst case for a dead network; the listener usually appears in 1–3 s.
     */
    private const val START_BUDGET_MS = 45_000L
}
