package com.msnguard.vpn

import android.content.Context
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean

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
            // GOOL/WoW dials two WARP identities, so both halves must exist.
            "gool", "warp-in-warp", "wow" -> {
                if (!siblingFile(base, "secondary").exists()) return false
                base
            }
            // MIM dials two MASQUE identities: the primary AND its -secondary
            // sibling. The check below only looked at aether-masque.toml, so a
            // phone that had the outer hop but not the inner one reported
            // "already provisioned", skipped SHARD, and the core failed at
            // load_or_provision_masque(secondary) — "no masque identity found".
            "mim", "masque-in-masque", "masque over masque" -> {
                if (!siblingFile(siblingFile(base, "masque"), "secondary").exists()) return false
                siblingFile(base, "masque")
            }
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
    /**
     * A [accountApiReachable] answer is a property of the *network*, not of the
     * protocol: the carrier either lets the account API through or it does not,
     * and re-asking changes nothing while costing the full probe timeout on
     * every rung of the Auto Scan ladder — 33s × 3 in the field log.
     *
     * Cached for [BLOCKED_CACHE_MS] after a negative answer. A positive answer is
     * never cached (cheap, and the only thing that can flip a carrier back to
     * open is a network change, which goes through [clearApiBlockedCache]).
     */
    @Volatile
    private var apiBlockedSince = 0L
    private const val BLOCKED_CACHE_MS = 5 * 60_000L

    fun clearApiBlockedCache() {
        apiBlockedSince = 0L
    }

    /** Whether a negative answer is still within [BLOCKED_CACHE_MS]. */
    fun apiAlreadyMeasuredBlocked(): Boolean {
        return apiBlockedSince != 0L &&
            System.currentTimeMillis() - apiBlockedSince < BLOCKED_CACHE_MS
    }

    /**
     * Whether the SHARD listener was live before this provisioning attempt
     * raised it. A session the user was already relying on must not be torn down
     * by [MsnGuardVpnService.stopProvisioningShard].
     */
    @Volatile
    var shardWasAlreadyRunning = false
        private set

    fun accountApiReachable(context: Context): Boolean {
        // Fast path: a network already measured as filtered stays filtered for
        // the lifetime of the cache. Nothing the caller does in between — trying
        // WireGuard, then MASQUE, then MIM — changes what the carrier will do
        // with this same URL, so probing again is 33s of pure waste.
        if (apiBlockedSince != 0L &&
            System.currentTimeMillis() - apiBlockedSince < BLOCKED_CACHE_MS
        ) {
            Log.i(TAG, "account API already measured blocked on this network — skipping the probe")
            return false
        }
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
            apiBlockedSince = System.currentTimeMillis()
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
    /**
     * Whether the device's own link reaches the account API, and a SHARD
     * listener to register through when it does not, in one round trip.
     *
     * The two are decided *in parallel* on a network worth probing at all.
     * Doing them in sequence is what made provisioning slow: the probe takes up
     * to its full 8s+8s timeout to fail on a filtered carrier, and only then
     * does SHARD begin its 2s node race — a serial 33s the user watches every
     * rung of the Auto Scan ladder pay. Racing them means the listener is
     * already bound by the time the verdict arrives, so a blocked carrier pays
     * max(probe, shard) instead of probe + shard.
     *
     * @param probe whether to test the direct route at all. False when the
     *   network is already known to be filtered ([accountApiReachable] cached a
     *   negative answer): the probe would burn its timeout to re-confirm a
     *   result we already have, and SHARD is the only path anyway.
     * @return the listener address when SHARD produced one and the direct route
     *   is not usable, null when the direct route works or nothing was raised
     */
    fun probeAndRaiseShard(context: Context, probe: Boolean): ProbeOutcome {
        if (ShardManager.isRunning) {
            // A listener is already live and belongs to the user's own session.
            // Reuse it and skip the probe: if their tunnel is up, the account
            // API can ride it too.
            shardWasAlreadyRunning = true
            return ProbeOutcome(direct = true, listener = "127.0.0.1:${ShardManager.liveSocksPort}")
        }
        shardWasAlreadyRunning = false

        // The probe is the slow half, so start the race first and let it run
        // while the probe is still in flight.
        ConnectionLog.record("Identity: starting SHARD to provision through it")
        val shardStarted = AtomicBoolean(false)
        Thread({
            shardStarted.set(try {
                ShardManager.start(context)
            } catch (e: Exception) {
                Log.w(TAG, "SHARD would not start for provisioning: ${e.message}")
                ConnectionLog.record("Identity: SHARD start failed — ${e.message}")
                false
            })
            if (!shardStarted.get()) {
                ConnectionLog.record(
                    "Identity: SHARD start failed — " +
                        "${ShardManager.lastError.ifBlank { "no node answered" }}"
                )
            }
        }, "identity-shard-start").start()

        val direct = if (probe) accountApiReachable(context) else false
        if (direct) {
            // The carrier is open: the core registers on its own link. Take the
            // SHARD session back down — leaving it up would hold port 1824
            // against the user's own connect.
            waitForShard(shardStarted)
            if (shardStarted.get()) releaseShardListener(startedOurselves = true)
            return ProbeOutcome(direct = true, listener = null)
        }

        val listener = waitForShard(shardStarted)
        return ProbeOutcome(direct = false, listener = listener)
    }

    data class ProbeOutcome(val direct: Boolean, val listener: String?)

    private fun waitForShard(started: AtomicBoolean): String? {
        val deadline = System.currentTimeMillis() + START_BUDGET_MS
        val startOfErrors = ShardManager.lastError.length
        while (System.currentTimeMillis() < deadline) {
            if (started.get() || ShardManager.isRunning) {
                return "127.0.0.1:${ShardManager.liveSocksPort}"
            }
            if (ShardManager.lastError.length > startOfErrors) break
            try {
                Thread.sleep(200)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return null
            }
        }
        return null
    }

    fun ensureShardListener(context: Context): String? {
        if (ShardManager.isRunning) {
            Log.i(TAG, "SHARD already running; reusing its listener")
            return "127.0.0.1:${ShardManager.liveSocksPort}"
        }
        ConnectionLog.record("Identity: starting SHARD to provision through it")
        // On a worker thread: start() races the node pool and blocks until a
        // listener accepts, which can take the full race budget.
        // Written by the starter thread, read by this one.
        val started = AtomicBoolean(false)
        Thread({
            started.set(try {
                ShardManager.start(context)
            } catch (e: Exception) {
                Log.w(TAG, "SHARD would not start for provisioning: ${e.message}")
                ConnectionLog.record("Identity: SHARD start failed — ${e.message}")
                false
            })
            if (!started.get()) {
                ConnectionLog.record(
                    "Identity: SHARD start failed — " +
                        "${ShardManager.lastError.ifBlank { "no node answered" }}"
                )
            }
        }, "identity-shard-start").start()
        // Wait for that thread's result: the caller is already on a worker
        // thread (startTunnel), so blocking here costs nothing.
        val deadline = System.currentTimeMillis() + START_BUDGET_MS
        // A stale error from a previous session would break the wait before the
        // starter thread has even attempted, so snapshot the error boundary.
        val startOfErrors = ShardManager.lastError.length
        while (System.currentTimeMillis() < deadline) {
            if (started.get() || ShardManager.isRunning) {
                return "127.0.0.1:${ShardManager.liveSocksPort}"
            }
            if (ShardManager.lastError.length > startOfErrors) break
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
                val errBody = runCatching { connection.errorStream?.bufferedReader()?.readText()?.take(400) }.getOrNull()
                Log.w(TAG, "registration through SHARD returned HTTP $code${if (!errBody.isNullOrBlank()) " — ${errBody.take(200)}" else ""}")
                ConnectionLog.record("Identity Vault: $protocol via Shard — HTTP $code${if (!errBody.isNullOrBlank()) " — ${errBody.take(120)}" else ""}")
                return null
            }
            val response = connection.inputStream.bufferedReader().readText()
            val snippet = response.take(300)
            ConnectionLog.record("Identity Vault: $protocol via Shard — HTTP ${code} — ${snippet.take(120)}")
            val parsed = JSONObject(response)
            val saved = saveIdentity(context, protocol, parsed)
            if (saved == null) {
                Log.w(TAG, "registration through SHARD: saveIdentity returned null for $protocol — keys: ${parsed.keys().asSequence().joinToString()} — body ${response.take(300)}")
                ConnectionLog.record("Identity Vault: $protocol via Shard — parse/save null — keys ${parsed.keys().asSequence().joinToString().take(80)}")
            }
            saved
        } catch (e: Exception) {
            Log.w(TAG, "registration through SHARD failed: ${e.message}")
            ConnectionLog.record("Identity Vault: $protocol via Shard — exception ${e.message?.take(140)}")
            null
        }
    }

    /**
     * Warp Setting — Identity Vault: direct provision (Quantum ECH).
     *
     * POSTs the same registration body as [provisionThroughShard] directly to
     * [API_REGISTER_URL] without a proxy. On a 2xx response the body is handed
     * to [saveIdentity] so the core finds the file on the next connect.
     *
     * Must be called on a worker thread — it blocks on the network.
     * Logs to both [Log] and [ConnectionLog] so the vault terminal can surface
     * the result.
     *
     * @return true when an identity was saved.
     */
    fun provisionDirect(context: Context, protocol: String): Boolean {
        Log.i(TAG, "Identity Vault: provisioning $protocol directly")
        ConnectionLog.record("Identity Vault: provisioning $protocol directly")
        val body = JSONObject().apply {
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
            val connection = URL(API_REGISTER_URL).openConnection() as HttpURLConnection
            connection.connectTimeout = 20_000
            connection.readTimeout = 20_000
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("User-Agent", USER_AGENT)
            connection.setRequestProperty("CF-Client-Version", CLIENT_VERSION)
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toString().toByteArray()) }
            val code = connection.responseCode
            if (code !in 200..299) {
                Log.w(TAG, "Identity Vault: direct registration for $protocol returned HTTP $code")
                ConnectionLog.record("Identity Vault: direct registration for $protocol returned HTTP $code")
                return false
            }
            val response = connection.inputStream.bufferedReader().readText()
            val parsed = JSONObject(response)
            val file = saveIdentity(context, protocol, parsed)
            val ok = file != null
            if (ok) {
                Log.i(TAG, "Identity Vault: $protocol provisioned directly -> ${file!!.name}")
                ConnectionLog.record("Identity Vault: $protocol provisioned directly")
            } else {
                Log.w(TAG, "Identity Vault: direct registration for $protocol saved no identity")
                ConnectionLog.record("Identity Vault: direct registration for $protocol saved no identity")
            }
            ok
        } catch (e: Exception) {
            Log.w(TAG, "Identity Vault: direct provision for $protocol failed: ${e.message}")
            ConnectionLog.record("Identity Vault: direct provision for $protocol failed — ${e.message}")
            false
        }
    }

    /**
     * Warp Setting — Identity Vault: SHARD-backed provision.
     *
     * Wrapper around [ensureShardListener] + [provisionThroughShard] +
     * [releaseShardListener]. Starts a SHARD listener when none is live,
     * registers through it, then tears the session down only when this call
     * started it — an existing user session is never released.
     *
     * Must be called on a worker thread — [ensureShardListener] blocks up to
     * [START_BUDGET_MS] while xray races.
     *
     * @return true when an identity was saved.
     */
    fun provisionViaShard(context: Context, protocol: String): Boolean {
        Log.i(TAG, "Identity Vault: provisioning $protocol via SHARD")
        ConnectionLog.record("Identity Vault: provisioning $protocol via SHARD")
        val wasRunning = ShardManager.isRunning
        val listener = ensureShardListener(context)
        if (listener == null) {
            Log.w(TAG, "Identity Vault: SHARD listener not available for $protocol")
            ConnectionLog.record("Identity Vault: SHARD listener not available for $protocol")
            return false
        }
        val port = listener.substringAfterLast(":").toIntOrNull() ?: ShardManager.liveSocksPort
        var success = false
        try {
            val file = provisionThroughShard(context, protocol, port)
            success = file != null
            if (success) {
                Log.i(TAG, "Identity Vault: $protocol provisioned via SHARD -> ${file!!.name}")
                ConnectionLog.record("Identity Vault: $protocol provisioned via SHARD")
            } else {
                Log.w(TAG, "Identity Vault: $protocol via SHARD returned no identity")
                ConnectionLog.record("Identity Vault: $protocol via SHARD failed")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Identity Vault: provision via SHARD for $protocol failed: ${e.message}")
            ConnectionLog.record("Identity Vault: provision via SHARD for $protocol failed — ${e.message}")
            success = false
        } finally {
            val startedOurselves = !wasRunning
            try {
                releaseShardListener(startedOurselves)
            } catch (e: Exception) {
                Log.w(TAG, "Identity Vault: release SHARD after $protocol failed: ${e.message}")
            }
        }
        return success
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
