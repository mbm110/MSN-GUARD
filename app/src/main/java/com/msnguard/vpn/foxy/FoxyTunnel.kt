package com.msnguard.vpn.foxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.msnguard.vpn.ConnectionLog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Foxy transport manager — the app-layer engine behind MSN's FOXY method.
 *
 * Data plane (all app-side, no Rust core involvement):
 *   VpnService TUN → TunEngine (MSN's choice: Hev/Zeptun/Badvpn, untouched)
 *     → FoxySocksServer (127.0.0.1:SOCKS_PORT)
 *     → H2UpstreamSession (netty, ALPN h2, TLS to the Fastly edge)
 *     → HTTP CONNECT <target> with proxy-authorization Bearer <guardian JWT>
 *
 * Control plane: FxA login (email + password + emailed verification code,
 * HAWK-signed), Guardian proxy pass (JWT, auto-activation), server list from
 * Mozilla RemoteSettings, edge address resolved over DoH.
 *
 * Isolation contract: this object never touches CoreConfig, WarpIdentityFetcher,
 * ShardManager, or the aether engine. Revert = delete this package + the two
 * service/UI hooks.
 */
object FoxyTunnel {

    // 1819 warp core, 1820 chain, 1824 shard, 1826 warp exit, 1827 smart-dns,
    // 1839 identity bind. 1830 is free and reserved for us.
    const val SOCKS_PORT = 1830

    /** WireGuard-style ladder baseline MTU for the FOXY TUN interface. */
    const val TUN_MTU = 1400

    private const val TAG = "FoxyTunnel"

    /** Redial loop cadence — the reference FoxyVpnService polls every 2 s. */
    private const val WATCHDOG_INTERVAL_MS = 2_000L

    /** The reference caps one upstream dial at CONNECT_TIMEOUT_MS = 20 s. */
    private const val REDIAL_CONNECT_TIMEOUT_MS = 20_000L

    /** The reference backs failed redials off (2 s base, capped). */
    private const val REDIAL_BACKOFF_BASE_MS = 2_000L
    private const val REDIAL_BACKOFF_CAP_MS = 12_000L

    @Volatile private var socks: LocalSocks5Server? = null
    @Volatile private var session: UpstreamSession? = null
    @Volatile private var proxyPass: ProxyPass? = null

    /** Candidate list the redial loops walk; refetched only on the next start. */
    @Volatile private var dialCandidates: List<ProxyCandidate>? = null

    /** Context for redial-time pass minting. Cleared on stop. */
    @Volatile private var appContext: Context? = null

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var watchdog: Job? = null

    /** One redial at a time; the unhealthy callback and the watchdog share it. */
    private val redialing = AtomicBoolean(false)

    val isRunning: Boolean get() = socks != null

    /** Bytes moved through the tunnel since start (for the service's stats poll). */
    @Volatile var txBytes: Long = 0L
    @Volatile var rxBytes: Long = 0L

    fun tokenStore(context: Context) = FxoTokenStore(context)
    fun authRepo(context: Context) = FxaAuthRepository(tokenStore(context))

    /**
     * Sign-in state machine for the Foxy panel:
     *  - null        → not signed in, no pending session
     *  - "pending"   → login accepted, waiting for the emailed verification code
     *  - "active"    → tokens stored (session valid)
     */
    fun signInStatus(context: Context): String? {
        val store = tokenStore(context)
        if (store.pendingSessionToken != null) return "pending"
        if (store.hasStoredSession()) return "active"
        return null
    }

    /**
     * Start a login attempt. Returns "needs-code" (202 — email sent), "signed-in"
     * (FxA did not require a code and tokens are already stored), or THROWS with
     * the real FxA failure. A swallowed Result here previously mapped every
     * wrong-password / unreachable-server error to "signed in" — never do that.
     */
    suspend fun login(context: Context, email: String, password: String): String =
        withContext(Dispatchers.IO) {
            val repo = authRepo(context)
            val needed = repo.startLogin(email.trim(), password).getOrThrow()
            if (needed) "needs-code" else "signed-in"
        }

    /** Verify the emailed code and finish the login. */
    suspend fun verifyCode(context: Context, code: String): Unit =
        withContext(Dispatchers.IO) {
            val repo = authRepo(context)
            runCatching { repo.submitTwoFactorCode(code.trim()) }.getOrThrow()
        }

    /** Fresh tokens for connect-time use (silent refresh; may throw). */
    suspend fun ensureAccessToken(context: Context): RuntimeAuth =
        withContext(Dispatchers.IO) {
            val repo = authRepo(context)
            runCatching { repo.ensureFreshAccessToken() }.getOrThrow()
        }

    fun signOut(context: Context) {
        runCatching { tokenStore(context).clear() }
        ConnectionLog.record("Foxy: signed out — tokens cleared")
    }

    /**
     * Bring the data plane up. Blocking listeners already spin inside
     * [FoxyLocalSocksServer.start]; throws with the last error on failure.
     */
    suspend fun start(context: Context) = withContext(Dispatchers.IO) {
        if (isRunning) return@withContext
        FoxyTunnel.rxBytes = 0L
        FoxyTunnel.txBytes = 0L
        // While Foxy owns the device, mirror its WARN/ERROR/INFO into the
        // user-visible connection log — the failure reasons otherwise die in
        // logcat and the log goes dark between "connected" and teardown.
        FoxyLog.mirror = { tag, _, msg ->
            ConnectionLog.record("Foxy: [" + tag + "] " + msg.take(160))
        }
        appContext = context.applicationContext
        // Reference parity: the bundled GlobalSign roots must be loaded BEFORE
        // the first TLS handshake touches UpstreamTrust (it builds its
        // trustManagerFactory on first use and caches it). Without this the
        // pool was "124 system root(s) + 0 bundled root(s)".
        UpstreamTrust.init(context)
        ConnectionLog.record("Foxy: starting — refreshing FxA session…")
        val pass = mintPass(context)
        proxyPass = pass
        ConnectionLog.record("Foxy: pass acquired (lifetime noted)")

        val countries = ServerListClient(context)
            .fetchCountries()
        // Location choice from the Foxy page's Server picker (null = Automatic,
        // which keeps the historic first-country behaviour). A saved code that
        // the refreshed server list no longer carries must NOT silently fall
        // back to another country — the user asked for that exit, so fail loudly.
        val chosen = FoxySettings.selectedCountryCode(context)
            ?.takeIf { code -> countries.any { it.code.equals(code, ignoreCase = true) } }
        val candidates = ServerListClient.candidatesForCountry(
            countries,
            chosen ?: countries.firstOrNull()?.code ?: "",
        )
        if (candidates.isEmpty()) {
            if (chosen != null) {
                error("Foxy: no candidate in the selected country ($chosen) — pick a different server on the Foxy page")
            }
            error("Foxy: no reachable server found — try again later")
        }
        ConnectionLog.record(
            "Foxy: ${candidates.size} server candidate(s) in " +
                (chosen ?: countries.firstOrNull()?.code ?: "?"),
        )
        // The redial loops walk this same list later.
        dialCandidates = candidates

        try {
            // The reference's dialUpstream: walk the list until one candidate
            // actually connects (the first candidate is often one this ISP
            // cannot reach at all), and carry the last failure upward when
            // none does.
            val s = dialUpstream(context, pass)
            session = s

            val srv = LocalSocks5Server(
                bindAddress = "127.0.0.1",
                port = SOCKS_PORT,
                rejectFakeDnsAddresses = true,
                dohUrl = null,
                sessionProvider = { session },
            ) {
                onUpstreamUnhealthy()
            }
            srv.start()
            socks = srv
            startWatchdog()
            ConnectionLog.record("Foxy: tunnel up — SOCKS on 127.0.0.1:$SOCKS_PORT")
        } catch (e: Exception) {
            stop()
            throw e
        }
    }

    fun stop() {
        // Cancel the watchdog and any in-flight redial FIRST: they must not
        // hand out a session after the SOCKS listener is gone (their
        // `socks == null` tombstone checks close anything just produced).
        runCatching { scope.coroutineContext[Job]?.cancelChildren() }
        watchdog = null
        dialCandidates = null
        appContext = null
        val wasRunning = socks != null || session != null
        runCatching { socks?.stop().also { socks = null } }
        runCatching { session?.close().also { session = null } }
        FoxyLog.mirror = null
        // Field report: a user disconnects Foxy, tries Tor later and still sees
        // "Foxy: stopped" — a teardown log worded like an alarm, which looked
        // like Foxy interfering with the new connection. It never was: this
        // stop() runs on EVERY disconnect path by design (each transport's
        // shutdown calls it to guarantee no Foxy SOCKS or H2 session survives).
        // Keep the guarantee, drop the noise — only tell the log when Foxy was
        // actually serving a tunnel beforehand.
        if (wasRunning) ConnectionLog.record("Foxy: stopped")
    }

    /** Log-location helper for the in-panel vault path (unused external state). */
    fun stateDir(context: Context): File = context.filesDir

    // ---------------------------------------------------------------------
    // Redial machinery — the reference FoxyVpnService answers a dead or
    // unauthenticated upstream session with a real reconnect; logging the
    // callback and doing nothing quietly left a zombie tunnel behind.
    // ---------------------------------------------------------------------

    /**
     * Fresh connection pass for dial and redial — the same flow the
     * reference's mintProxyPass runs: renew the FxA session when stale, and
     * activate the entitlement once when the pass comes back invalid.
     *
     * alpha39 device log: "Foxy start failed: connection failure" ~1 s after
     * "refreshing FxA session…" with NO step visible between — the control
     * plane's failure reason died inside the thrown exception. Every step now
     * records its own outcome (message + full cause chain), because the whole
     * request stack (OkHttp → socket factory → TLS) wraps the real reason
     * (refused/reset/DNS/alert) in layers that e.message alone loses.
     */
    private suspend fun mintPass(context: Context): ProxyPass {
        val auth = try {
            ensureAccessToken(context)
        } catch (idc: CancellationException) {
            throw idc
        } catch (e: Exception) {
            ConnectionLog.record("Foxy: FxA session refresh failed — " + causeChain(e))
            throw e
        }
        ConnectionLog.record("Foxy: fetching connection pass…")
        val guardian = GuardianClient()
        return try {
            guardian.fetchProxyPass(GUARDIAN_ENDPOINT_DEFAULT, auth.accessToken)
        } catch (idc: CancellationException) {
            throw idc
        } catch (first: Exception) {
            ConnectionLog.record("Foxy: pass fetch failed — " + causeChain(first))
            if (first is TokenInvalidError) {
                try {
                    ConnectionLog.record("Foxy: activating connection pass once…")
                    guardian.activateGuardian(GUARDIAN_ENDPOINT_DEFAULT, auth.accessToken)
                    guardian.fetchProxyPass(GUARDIAN_ENDPOINT_DEFAULT, auth.accessToken)
                } catch (idc: CancellationException) {
                    throw idc
                } catch (e: Exception) {
                    ConnectionLog.record("Foxy: pass retry after activation failed — " + causeChain(e))
                    throw e
                }
            } else {
                throw first
            }
        }
    }

    /** The nested causes are where the real reason hides (OkHttp wraps a lot). */
    private fun causeChain(e: Throwable, depth: Int = 0): String {
        val line = (e::class.simpleName ?: "Exception") + ": " + (e.message ?: "-")
        if (depth >= 3) return line
        val cause = e.cause ?: return line
        return "$line <- " + causeChain(cause, depth + 1)
    }

    /**
     * Dial the upstream exactly like the reference's dialUpstream: walk the
     * candidate list, resolve each edge address, connect over H2 with the
     * freshly minted pass. Throws the LAST failure when every candidate failed.
     */
    private suspend fun dialUpstream(context: Context, pass: ProxyPass): UpstreamSession {
        val list = dialCandidates ?: error("Foxy: no dial candidates")
        var lastErr: Exception? = null
        for (cand in list) {
            try {
                val edge = EdgeAddressResolver.resolve(cand.host, listOf("1.1.1.1", "8.8.8.8"))
                ConnectionLog.record("Foxy: dialing ${cand.host}:${cand.port}")
                val s = H2UpstreamSession(
                    upstreamHost = cand.host,
                    upstreamPort = cand.port,
                    bearerToken = pass.token,
                    edgeAddress = edge,
                    tlsSplitMode = FoxySettings.tlsSplitMode(context),
                )
                s.connect()
                return s
            } catch (idc: CancellationException) {
                throw idc
            } catch (e: Exception) {
                lastErr = e
                ConnectionLog.record("Foxy: dial to ${cand.host} failed — ${e.message ?: "unknown"}")
            }
        }
        throw lastErr ?: IllegalStateException("Foxy: could not reach any server")
    }

    /**
     * The SOCKS server's health tracker decided the session is the likelier
     * cause of failures than any one destination (or the edge rejected the
     * pass). The reference answers that with a real redial.
     */
    private fun onUpstreamUnhealthy() {
        if (socks == null) return
        ConnectionLog.record("Foxy: upstream session unhealthy — redialing")
        scope.launch { redial("unhealthy flows") }
    }

    /**
     * One reconnect attempt: fresh pass, dial a new session, swap it in.
     * Returns true when a live session is in place (including "a redial was
     * already running"). [LocalSocks5Server] reads [session] through its
     * sessionProvider, so new flows pick the fresh session up instantly.
     */
    private suspend fun redial(why: String): Boolean {
        if (!redialing.compareAndSet(false, true)) return true
        try {
            val context = appContext ?: return false
            if (socks == null) return false
            ConnectionLog.record("Foxy: redial ($why) — fetching a fresh pass…")
            val pass = mintPass(context)
            val fresh = withTimeoutOrNull(REDIAL_CONNECT_TIMEOUT_MS) { dialUpstream(context, pass) }
            if (fresh == null) {
                ConnectionLog.record("Foxy: redial ($why) timed out or failed — the watchdog retries")
                return false
            }
            // Torn down while the dial was in flight — do not leak the fresh session.
            if (socks == null) {
                runCatching { fresh.close() }
                return false
            }
            runCatching { session?.close() }
            session = fresh
            ConnectionLog.record("Foxy: upstream redialled")
            return true
        } catch (idc: CancellationException) {
            throw idc
        } catch (e: Exception) {
            ConnectionLog.record("Foxy: redial ($why) failed — ${e.message ?: "error"}")
            return false
        } finally {
            redialing.set(false)
        }
    }

    /**
     * Mirror of the reference FoxyVpnService's upstream watchdog (2 s interval,
     * 20 s dial timeout, capped backoff, hold-while-offline): while the SOCKS
     * listener is up, keep an upstream session live — swap a fresh one in
     * whenever the edge session dies, so the TUN path never loses the
     * transport underneath the user.
     */
    private fun startWatchdog() {
        watchdog?.cancel()
        watchdog = scope.launch {
            var failures = 0
            while (isActive) {
                delay(WATCHDOG_INTERVAL_MS)
                if (socks == null) return@launch
                val context = appContext ?: return@launch
                val current = session
                if (current != null && current.isConnected) {
                    if (failures != 0) ConnectionLog.record("Foxy: upstream session healthy again")
                    failures = 0
                    continue
                }
                // Same as the reference: wait silently for connectivity
                // instead of burning dials on a dead link.
                if (!hasUsableNetwork(context)) continue
                if (failures == 0) ConnectionLog.record("Foxy: upstream session down — redialing…")
                if (redial("watchdog")) {
                    failures = 0
                } else {
                    failures++
                    val backoff = (REDIAL_BACKOFF_BASE_MS shl failures.coerceAtMost(5))
                        .coerceAtLeast(REDIAL_BACKOFF_BASE_MS)
                        .coerceAtMost(REDIAL_BACKOFF_CAP_MS)
                    delay(backoff)
                }
            }
        }
    }

    /** The reference's hasUsableNetwork — Android already holds this permission. */
    private fun hasUsableNetwork(context: Context): Boolean = runCatching {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return@runCatching false
        val net = cm.activeNetwork ?: return@runCatching false
        val caps = cm.getNetworkCapabilities(net) ?: return@runCatching false
        caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }.getOrDefault(false)
}
