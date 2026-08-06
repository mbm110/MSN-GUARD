package studio.cluvex.aethery

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Intent
import android.content.pm.ServiceInfo
import android.service.quicksettings.TileService
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import org.json.JSONObject
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import ca.psiphon.psiphontunnel.PsiphonTunnel

class AetherVpnService : VpnService(), NativeCore.CoreCallback, PsiphonTunnel.HostService {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val connected = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)
    // Native transport sockets need VpnService.protect only while a TUN exists.
    // Proxy mode has no VPN interface, so protecting there would always fail.
    private val vpnModeActive = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var lastTrafficSampleMs = 0L
    private var currentTx = 0L
    private var currentRx = 0L
    private var prevTx = 0L
    private var prevRx = 0L
    private var prevSpeedSampleMs = 0L
    private var currentSpeedTx = 0L
    private var currentSpeedRx = 0L
    private var accountedTx = 0L
    private var accountedRx = 0L
    private var storedConfig: String? = null
    private var storedVpnMode = true
    private var currentProtocol = "Tunnel"
    private var currentVpnIp = ""
    private var currentPing = ""

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    @Throws(PsiphonTunnel.Exception::class)
    override fun bindToDevice(fd: Long) {
        if (!protect(fd.toInt())) {
            throw PsiphonTunnel.Exception("protect(fd=$fd) failed")
        }
    }

    override fun onConnecting() {
        ConnectionLog.record("Psiphon connecting")
    }

    override fun onConnected() {
        ConnectionLog.record("Psiphon connected")
    }

    override fun onExiting() {
        ConnectionLog.record("Psiphon exiting")
        psiphonTunnel = null
    }

    override fun onClientAddress(address: String?) {
        if (!address.isNullOrBlank()) {
            ConnectionLog.record("Psiphon exit IP: $address")
            getSharedPreferences("settings", MODE_PRIVATE).edit()
                .putString("last_ip", address).apply()
        }
    }

    override fun onHomepage(homepage: String?) {
        ConnectionLog.record("Psiphon homepage: ${homepage ?: "—"}")
    }

    override fun onClientRegion(region: String?) {
        if (!region.isNullOrBlank()) ConnectionLog.record("Psiphon region: $region")
    }

    override fun onBytesTransferred(sent: Long, received: Long) {
        // Traffic stats handled by NativeCore callback
    }

    override fun onDiagnosticMessage(message: String) {
        ConnectionLog.record("Psiphon: $message")
    }

    private fun buildPsiphonConfig(): String {
        return org.json.JSONObject().apply {
            put("PropagationChannelId", "FFFFFFFFFFFFFFFF")
            put("SponsorId", "1111111111111111")
            put("EgressRegion", "")
            put("EstablishTunnelTimeoutSeconds", 0)
            put("DataDirectory", filesDir.absolutePath)
            put("ClientVersion", "1")
            put("TunnelProtocol", "")
            put("RemoteServerListURL", "")
            put("LocalSocksProxyPort", 0)
            put("RemoteServerListSignaturePublicKey", "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=")
            put("ServerEntrySignaturePublicKey", "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=")
            put("ExchangeObfuscationKey", "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU=")
        }.toString()
    }

    private fun startPsiphonTunnel(): String? {
        try {
            val tunnel = PsiphonTunnel.newPsiphonTunnel(this)
            tunnel.setVpnMode(false) // SOCKS mode — we manage the TUN.
            psiphonTunnel = tunnel
            psiphonConfigJson = buildPsiphonConfig()

            // Load hex-encoded server entries from assets
            val serverEntries = try {
                assets.open("server_entries.txt").bufferedReader().readText().trim()
            } catch (e: Exception) {
                ConnectionLog.record("No server_entries.txt in assets: ${e.message}")
                ""
            }
            tunnel.startTunneling(serverEntries)

            // Poll for SOCKS port — ready in <1s
            var port = 0
            for (i in 1..40) { // 40 × 250ms = 10s max
                port = tunnel.localSocksProxyPort
                if (port > 0) break
                Thread.sleep(250)
            }
            if (port > 0) {
                ConnectionLog.record("Psiphon SOCKS proxy on 127.0.0.1:$port")
                return "127.0.0.1:$port"
            }
            ConnectionLog.record("Psiphon SOCKS proxy did not start within 10s")
            return null
        } catch (e: Exception) {
            ConnectionLog.record("Psiphon start failed: ${e.message}")
            return null
        }
    }

    private fun stopPsiphonTunnel() {
        try { psiphonTunnel?.stop() } catch (_: Exception) {}
        psiphonTunnel = null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> intent.getStringExtra(EXTRA_CONFIG)?.let { config ->
                startTunnel(config, intent.getBooleanExtra(EXTRA_VPN_MODE, true))
            }
            ACTION_DISCONNECT -> stopTunnel()
            ACTION_RECONNECT -> {
                val config = storedConfig
                if (config != null && connected.get()) {
                    ConnectionLog.record("Quick reconnect requested")
                    stopTunnel(notify = false)
                    worker.execute {
                        try { Thread.sleep(500) } catch (_: InterruptedException) {}
                        startTunnel(config, storedVpnMode)
                    }
                }
            }
            ACTION_NOTIFICATION_HEALTH -> {
                intent.getStringExtra(EXTRA_NOTIFICATION_IP)?.let { currentVpnIp = it }
                intent.getStringExtra(EXTRA_NOTIFICATION_PING)?.let { currentPing = it }
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification(currentTx, currentRx))
            }
        }
        return Service.START_REDELIVER_INTENT
    }

    override fun onDestroy() {
        stopTunnel(notify = false)
        worker.shutdownNow()
        super.onDestroy()
    }

    fun protectSocket(fd: Int): Boolean = !vpnModeActive.get() || protect(fd)

    override fun onEvent(json: String) {
        try {
            val event = JSONObject(json)
            when (event.getString("type")) {
                "status" -> {
                    val status = event.getString("status")
                    val detail = if (event.isNull("detail")) null else event.getString("detail")
                    sendStatus(status, detail)
                }
                "traffic" -> {
                    val tx = event.getLong("tx")
                    val rx = event.getLong("rx")
                    currentTx = tx
                    currentRx = rx
                    updateTrafficNotification(tx, rx)
                }
                "log" -> {
                    val message = event.getString("message")
                    ConnectionLog.record(message)
                }
            }
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Failed to parse event: $json", e)
        }
    }

    private fun startTunnel(config: String, vpnMode: Boolean) {
        if (!connected.compareAndSet(false, true)) return
        storedConfig = config
        storedVpnMode = vpnMode
        currentProtocol = config.substringAfter("\"protocol\":\"").substringBefore('\"').uppercase()
        currentVpnIp = ""
        currentPing = ""
        stopRequested.set(false)
        vpnModeActive.set(vpnMode)
        startAsForeground()
        worker.execute {
            try {
                ConnectionLog.record("Preparing $currentProtocol identity")
                NativeCore.attach(this)
                val isPsiphon = currentProtocol.contains("PSIPHON")
                val result = if (isPsiphon) {
                    // PSIPHON: SOCKS-only mode — start Psiphon first, get port, then start Rust core
                    val socksProxy = startPsiphonTunnel()
                    if (socksProxy == null) {
                        error("Psiphon failed to start SOCKS proxy")
                    }
                    // Build a config that tells Rust to use upstream SOCKS proxy
                    val psiphonConfig = buildPsiphonBridgeConfig(config, socksProxy)
                    val addresses = NativeCore.prepare(psiphonConfig)
                    ConnectionLog.record("Creating Android VPN interface for Psiphon")
                    tun = Builder()
                        .setSession("MSN-VPN")
                        .setMtu(1280)
                        .addAddress(addresses.ipv4, 32)
                        .addAddress(addresses.ipv6, 128)
                        .addRoute("0.0.0.0", 0)
                        .addRoute("::", 0)
                        .applyDns(psiphonConfig)
                        .applyLanAccess()
                        .applySplitTunneling()
                        .establish() ?: error("Android could not establish the VPN interface")
                    ConnectionLog.record("Starting Rust core → Psiphon SOCKS $socksProxy")
                    sendStatus(STATUS_CONNECTED)  // Mark connected immediately
                    NativeCore.start(psiphonConfig, tun!!.fd)
                } else if (vpnMode) {
                    val addresses = NativeCore.prepare(config)
                    ConnectionLog.record("Creating Android VPN interface")
                    tun = Builder()
                        .setSession("MSN-VPN")
                        .setMtu(1280)
                        .addAddress(addresses.ipv4, 32)
                        .addAddress(addresses.ipv6, 128)
                        .addRoute("0.0.0.0", 0)
                        .addRoute("::", 0)
                        .applyDns(config)
                        .applyLanAccess()
                        .applySplitTunneling()
                        .establish() ?: error("Android could not establish the VPN interface")
                    ConnectionLog.record("Scanning gateways for VPN")
                    NativeCore.start(config, tun!!.fd)
                } else {
                    ConnectionLog.record("Starting local SOCKS5 proxy")
                    NativeCore.startProxy(config)
                }
                
                if (result != 0 && !stopRequested.get()) {
                    val detail = NativeCore.lastError().ifBlank { "Tunnel exited with code $result" }
                    ConnectionLog.record("Native tunnel exited: $detail")
                    sendStatus(STATUS_FAILED, detail)
                } else if (stopRequested.get()) {
                    sendStatus(STATUS_DISCONNECTED)
                } else {
                    ConnectionLog.record("Native tunnel stopped unexpectedly")
                    sendStatus(STATUS_FAILED, "Tunnel stopped unexpectedly")
                }
            } catch (error: Exception) {
                val detail = NativeCore.lastError().ifBlank { error.message ?: "Tunnel setup failed" }
                Log.e(LOG_TAG, "Tunnel failed: $detail", error)
                sendStatus(STATUS_FAILED, detail)
            } finally {
                NativeCore.detach()
                vpnModeActive.set(false)
                val killSwitch = getSharedPreferences("settings", MODE_PRIVATE).getBoolean("kill_switch", false)
                tun?.close()
                tun = null
                connected.set(false)
                if (killSwitch && !stopRequested.get()) {
                    ConnectionLog.record("Kill switch active; blocking all traffic")
                    sendStatus(STATUS_FAILED, "Kill switch active — tunnel dropped")
                    rebuildKillSwitchVpn()
                } else {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    private fun buildPsiphonBridgeConfig(baseConfig: String, socksProxy: String): String {
        // Inject upstream_proxy into config JSON for Rust core
        return try {
            val json = org.json.JSONObject(baseConfig)
            json.put("upstream_proxy", socksProxy)
            json.put("protocol", "psiphon")
            json.toString()
        } catch (e: Exception) {
            // Fallback: manual JSON replacement
            baseConfig.replace(
                ""protocol":"psiphon"",
                ""protocol":"psiphon","upstream_proxy":"$socksProxy""
            )
        }
    }

    private fun stopTunnel(notify: Boolean = true) {
        stopPsiphonTunnel()
        stopRequested.set(true)
        NativeCore.stop()
        if (notify && !connected.get()) sendStatus(STATUS_DISCONNECTED)
    }

    private fun rebuildKillSwitchVpn() {
        try {
            tun?.close()
            tun = Builder()
                .setSession("MSN-VPN — Kill Switch")
                .setMtu(1280)
                .addAddress("100.64.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .establish()
            ConnectionLog.record("Kill switch VPN active; all traffic blocked")
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Kill switch rebuild failed: ${e.message}")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun sendStatus(status: String, detail: String? = null) {
        Log.i(LOG_TAG, "status=$status${detail?.let { " detail=$it" } ?: ""}")
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_STATUS, status)
            .apply { detail?.let { putExtra(EXTRA_DETAIL, it) } })
        TileService.requestListeningState(
            this,
            ComponentName(this, AetherTileService::class.java),
        )
    }

    private fun updateTrafficNotification(tx: Long, rx: Long) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastTrafficSampleMs < 900) return

        val elapsed = now - prevSpeedSampleMs
        if (elapsed > 0 && prevSpeedSampleMs > 0) {
            currentSpeedTx = ((tx - prevTx) * 1000) / elapsed
            currentSpeedRx = ((rx - prevRx) * 1000) / elapsed
        }
        prevTx = tx
        prevRx = rx
        prevSpeedSampleMs = now

        val (monthTx, monthRx) = recordMonthlyTraffic(
            (tx - accountedTx).coerceAtLeast(0),
            (rx - accountedRx).coerceAtLeast(0),
        )
        accountedTx = tx
        accountedRx = rx
        sendTraffic(tx, rx, monthTx, monthRx)

        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(tx, rx))
        lastTrafficSampleMs = now
    }

    private fun recordMonthlyTraffic(tx: Long, rx: Long): Pair<Long, Long> {
        val month = java.text.SimpleDateFormat("yyyy-MM", java.util.Locale.US).format(java.util.Date())
        val prefs = getSharedPreferences(TRAFFIC_PREFS, MODE_PRIVATE)
        val sameMonth = prefs.getString(TRAFFIC_MONTH, null) == month
        val monthTx = (if (sameMonth) prefs.getLong(TRAFFIC_TX, 0) else 0) + tx
        val monthRx = (if (sameMonth) prefs.getLong(TRAFFIC_RX, 0) else 0) + rx
        prefs.edit()
            .putString(TRAFFIC_MONTH, month)
            .putLong(TRAFFIC_TX, monthTx)
            .putLong(TRAFFIC_RX, monthRx)
            .apply()
        return monthTx to monthRx
    }

    private fun sendTraffic(tx: Long, rx: Long, monthTx: Long, monthRx: Long) {
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_TRAFFIC_TX, tx)
            .putExtra(EXTRA_TRAFFIC_RX, rx)
            .putExtra(EXTRA_TRAFFIC_SPEED_TX, currentSpeedTx)
            .putExtra(EXTRA_TRAFFIC_SPEED_RX, currentSpeedRx)
            .putExtra(EXTRA_TRAFFIC_MONTH_TX, monthTx)
            .putExtra(EXTRA_TRAFFIC_MONTH_RX, monthRx))
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1_024 -> "$bytes B"
        bytes < 1_048_576 -> "${bytes / 1_024} KB"
        bytes < 1_073_741_824 -> "${bytes / 1_048_576} MB"
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / 1_073_741_824.toDouble())
    }

    private fun formatSpeed(bytesPerSec: Long): String = when {
        bytesPerSec < 1_024 -> "$bytesPerSec B/s"
        bytesPerSec < 1_048_576 -> "${bytesPerSec / 1_024} KB/s"
        else -> String.format(java.util.Locale.US, "%.1f MB/s", bytesPerSec / 1_048_576.0)
    }

    private fun startAsForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ))
        val notification = notification(0, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notification(tx: Long, rx: Long): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(
                Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP,
            ),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnectIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, AetherVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val reconnectIntent = PendingIntent.getService(
            this,
            2,
            Intent(this, AetherVpnService::class.java).setAction(ACTION_RECONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val health = listOfNotNull(
            currentVpnIp.takeIf(String::isNotBlank)?.let { "VPN $it" },
            currentPing.takeIf(String::isNotBlank),
        ).joinToString(" · ")
        val traffic = if (tx > 0 || rx > 0) {
            val speedText = if (currentSpeedTx > 0 || currentSpeedRx > 0) {
                "  \u2191${formatSpeed(currentSpeedTx)} \u2193${formatSpeed(currentSpeedRx)}"
            } else ""
            "${getString(R.string.vpn_download)}: ${formatBytes(rx)}  ${getString(R.string.vpn_upload)}: ${formatBytes(tx)}$speedText"
        } else {
            getString(R.string.vpn_notification)
        }
        val contentText = listOf(health, traffic).filter(String::isNotBlank).joinToString(" · ")

        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.aethery_notification)
            .setContentTitle("${getString(R.string.app_name)} · $currentProtocol")
            .setContentText(contentText)
            .setContentIntent(openAppIntent)
            .setOnlyAlertOnce(true)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                getString(R.string.vpn_disconnect),
                disconnectIntent,
            )
            .addAction(
                android.R.drawable.ic_menu_revert,
                "Quick Reconnect",
                reconnectIntent,
            )
            .build()
    }

    private fun Builder.applySplitTunneling(): Builder {
        val settings = SplitTunnelSettings(this@AetherVpnService)
        val mode = settings.mode()
        val packages = settings.packages()

        if (mode == SplitTunnelSettings.Mode.ALL) return this
        if (mode == SplitTunnelSettings.Mode.INCLUDE) {
            // Keep Aethery's UI requests (including the public-IP card) in the VPN.
            // The native transport protects its own sockets before connecting.
            addAllowedApplication(packageName)
        }
        if (packages.isEmpty()) {
            check(mode != SplitTunnelSettings.Mode.INCLUDE) {
                "No apps selected for tunnel. Connection aborted for safety."
            }
            return this
        }

        var addedCount = 0
        packages.forEach { pkg ->
            try {
                when (mode) {
                    SplitTunnelSettings.Mode.INCLUDE -> {
                        addAllowedApplication(pkg)
                        addedCount++
                    }
                    SplitTunnelSettings.Mode.EXCLUDE -> {
                        if (pkg != packageName) {
                            addDisallowedApplication(pkg)
                            addedCount++
                        }
                    }
                }
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                Log.w(LOG_TAG, "Split tunnel skipped missing app: $pkg")
            } catch (e: Exception) {
                Log.e(LOG_TAG, "Failed to add $pkg to split tunnel: ${e.message}")
            }
        }

        if (mode == SplitTunnelSettings.Mode.INCLUDE && addedCount == 0) {
            error("Selected apps are no longer installed. Connection aborted.")
        }

        ConnectionLog.record("Split tunnel ${mode.label.lowercase()}: $addedCount app(s)")
        return this
    }

    private fun Builder.applyLanAccess(): Builder {
        if (!getSharedPreferences("settings", MODE_PRIVATE).getBoolean("lan_sharing", false)) return this
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            ConnectionLog.record("LAN access uses system local routes on Android 12 and older")
            return this
        }
        listOf(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
        ).forEach { cidr ->
            val (address, prefix) = cidr.split('/')
            excludeRoute(IpPrefix(InetAddress.getByName(address), prefix.toInt()))
        }
        ConnectionLog.record("LAN routes bypass the VPN")
        return this
    }

    private fun Builder.applyDns(config: String): Builder {
        val configured = JSONObject(config).optString("dns_servers")
        val servers = configured.split(',', ';', ' ', '\n')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .mapNotNull { entry ->
                val address = when {
                    entry.startsWith('[') -> entry.substringAfter('[').substringBefore(']')
                    entry.count { it == ':' } == 1 -> entry.substringBefore(':')
                    else -> entry
                }
                runCatching { InetAddress.getByName(address) }.getOrNull()
            }
            .distinct()
        (servers.ifEmpty { listOf(InetAddress.getByName("1.1.1.1")) }).forEach { addDnsServer(it) }
        return this
    }

    // ── PsiphonTunnel.HostService implementation ──

    private var psiphonTunnel: PsiphonTunnel? = null
    private var psiphonConfigJson: String = ""

    override fun getContext(): android.content.Context = this

    override fun getPsiphonConfig(): String = psiphonConfigJson

    @Throws(PsiphonTunnel.Exception::class)
    override fun newPsiphonTunnel(): PsiphonTunnel {
        return PsiphonTunnel.newPsiphonTunnel(this)
    }

    companion object {
        const val ACTION_CONNECT = "studio.cluvex.aethery.CONNECT"
        const val ACTION_DISCONNECT = "studio.cluvex.aethery.DISCONNECT"
        const val ACTION_RECONNECT = "studio.cluvex.aethery.RECONNECT"
        const val ACTION_NOTIFICATION_HEALTH = "studio.cluvex.aethery.NOTIFICATION_HEALTH"
        const val ACTION_STATUS = "studio.cluvex.aethery.STATUS"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_VPN_MODE = "vpn_mode"
        const val EXTRA_STATUS = "status"
        const val EXTRA_DETAIL = "detail"
        const val EXTRA_TRAFFIC_TX = "traffic_tx"
        const val EXTRA_TRAFFIC_RX = "traffic_rx"
        const val EXTRA_TRAFFIC_SPEED_TX = "traffic_speed_tx"
        const val EXTRA_TRAFFIC_SPEED_RX = "traffic_speed_rx"
        const val EXTRA_TRAFFIC_MONTH_TX = "traffic_month_tx"
        const val EXTRA_TRAFFIC_MONTH_RX = "traffic_month_rx"
        const val EXTRA_NOTIFICATION_IP = "notification_ip"
        const val EXTRA_NOTIFICATION_PING = "notification_ping"
        const val STATUS_CONNECTING = "connecting"
        const val STATUS_STARTING = "starting"
        const val STATUS_SCANNING = "scanning"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_FAILED = "failed"
        const val STATUS_DISCONNECTED = "disconnected"
        private const val CHANNEL_ID = "aethery_vpn"
        private const val NOTIFICATION_ID = 1
        private const val TRAFFIC_PREFS = "traffic_monitor"
        private const val TRAFFIC_MONTH = "month"
        private const val TRAFFIC_TX = "tx"
        private const val TRAFFIC_RX = "rx"
        private const val LOG_TAG = "AetheryVpn"
    }
}

object ConnectionLog {
    private const val MAX_ENTRIES = 100
    private val entries = ArrayDeque<String>()

    @Synchronized
    fun record(message: String) {
        if (entries.size == MAX_ENTRIES) entries.removeFirst()
        entries.addLast("${java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())}  $message")
    }

    @Synchronized
    fun snapshot(): List<String> = entries.toList()
}
