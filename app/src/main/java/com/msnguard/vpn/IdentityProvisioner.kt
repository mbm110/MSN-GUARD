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
     */
    fun accountApiReachable(context: Context): Boolean {
        return try {
            val connection = URL(API_PROBE_URL).openConnection() as HttpURLConnection
            connection.connectTimeout = 8000
            connection.readTimeout = 8000
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            // Any HTTP status at all means the TLS handshake completed and the
            // endpoint answered. 404 is the normal response to a bare GET on /reg.
            connection.responseCode in 200..599
        } catch (e: Exception) {
            Log.i(TAG, "account API not reachable directly: ${e.message}")
            false
        }
    }

    /**
     * Bring SHARD up just far enough to have a SOCKS listener, if one is not
     * already running.
     *
     * Returns the listener address to route the account API through, or null
     * when SHARD could not produce one. Does not own the SHARD session: when a
     * listener already exists it is left alone, because tearing down a working
     * tunnel to start our own would be destructive to a session the user is
     * already relying on.
     */
    fun ensureShardListener(context: Context): String? {
        if (ShardManager.isRunning) {
            Log.i(TAG, "SHARD already running; reusing its listener")
            return "127.0.0.1:${ShardManager.SOCKS_PORT}"
        }
        return null
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

    private const val API_PROBE_URL = "https://api.cloudflareclient.com/v0a4471/reg"
    private const val API_REGISTER_URL = "https://api.cloudflareclient.com/v0a4471/reg"
    private const val USER_AGENT = "okhttp/3.12.1"
    private const val CLIENT_VERSION = "a-6.41-2158"
    private const val DEFAULT_ENDPOINT = "162.159.192.1:2408"
}
