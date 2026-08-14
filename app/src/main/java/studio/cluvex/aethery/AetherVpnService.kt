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
import android.net.ProxyInfo
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

class AetherVpnService : VpnService(), NativeCore.CoreCallback {
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

    fun protectSocket(fd: Int): Boolean {
        if (!vpnModeActive.get()) return true
        val ok = protect(fd)
        if (!ok) {
            Log.w(LOG_TAG, "VpnService.protect($fd) failed")
            ConnectionLog.record("Socket protect failed for fd=$fd")
        }
        return ok
    }

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
                ConnectionLog.bind(java.io.File(filesDir, "connection.log"))
                ConnectionLog.record("Preparing $currentProtocol identity")
                NativeCore.attach(this)
                val result = if (vpnMode) {
                    val addresses = NativeCore.prepare(config)
                    ConnectionLog.record("Creating Android VPN interface")
                    if (addresses.organization.isNotBlank()) {
                        ConnectionLog.record("Zero Trust organization ${addresses.organization}")
                    }
                    tun = Builder()
                        .setSession("Aethery")
                        .setMtu(1280)
                        .applyTunnelAddresses(addresses)
                        .applyDns(config, addresses)
                        .applyGatewayProxy(config, addresses)
                        .applyLanAccess(addresses)
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
                    ConnectionLog.record("Disconnect requested")
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
                connected.set(false)
                if (killSwitch && !stopRequested.get()) {
                    ConnectionLog.record("Kill switch active; blocking all traffic")
                    sendStatus(STATUS_FAILED, "Kill switch active — tunnel dropped")
                    rebuildKillSwitchVpn()
                } else {
                    tun?.close()
                    tun = null
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    private fun stopTunnel(notify: Boolean = true) {
        stopRequested.set(true)
        NativeCore.stop()
        if (notify && !connected.get()) sendStatus(STATUS_DISCONNECTED)
    }

    private fun rebuildKillSwitchVpn() {
        val oldTun = tun
        try {
            val blockingTun = Builder()
                .setSession("Aethery — Kill Switch")
                .setMtu(1280)
                .addAddress("100.64.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .setBlocking(true)
                .establish()
            tun = blockingTun
            oldTun?.close()
            ConnectionLog.record("Kill switch VPN active; all traffic blocked")
        } catch (e: Exception) {
            Log.e(LOG_TAG, "Kill switch rebuild failed: ${e.message}")
            oldTun?.close()
            tun = null
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
        val launchIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
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
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Aethery \u2014 $currentProtocol")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(launchIntent)
            .setOngoing(true)
            .setShowWhen(false)
            .setOnlyAlertOnce(true)

        val healthParts = mutableListOf<String>()
        if (currentVpnIp.isNotBlank()) healthParts.add(currentVpnIp)
        if (currentPing.isNotBlank()) healthParts.add(currentPing)
        val healthLine = if (healthParts.isNotEmpty()) healthParts.joinToString(" \u00b7 ") else null

        val speedLine = if (currentSpeedTx > 0 || currentSpeedRx > 0) {
            "\u2191 ${formatSpeed(currentSpeedTx)}  \u2193 ${formatSpeed(currentSpeedRx)}"
        } else null
        val totalLine = "\u2191 ${formatBytes(tx)}  \u2193 ${formatBytes(rx)}"

        val subText = listOfNotNull(healthLine, speedLine).joinToString("  \u00b7  ")
        if (subText.isNotBlank()) {
            builder.setContentText(subText)
            builder.setSubText(totalLine)
        } else {
            builder.setContentText(totalLine)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.addAction(Notification.Action.Builder(
                null,
                "Reconnect",
                reconnectIntent,
            ).build())
            builder.addAction(Notification.Action.Builder(
                null,
                "Disconnect",
                disconnectIntent,
            ).build())
        } else {
            @Suppress("DEPRECATION")
            builder.addAction(0, "Reconnect", reconnectIntent)
            @Suppress("DEPRECATION")
            builder.addAction(0, "Disconnect", disconnectIntent)
        }
        return builder.build()
    }

    private fun Builder.applySplitTunneling(): Builder {
        val settings = SplitTunnelSettings(this@AetherVpnService)
        val mode = settings.mode()
        val packages = settings.packages()

        if (mode == SplitTunnelSettings.Mode.ALL) return this
        if (mode == SplitTunnelSettings.Mode.INCLUDE) {
            addAllowedApplication(packageName)
        }
        if (packages.isEmpty()) {
            check(mode != SplitTunnelSettings.Mode.INCLUDE) {
                "No apps selected for tunnel. Connection aborted for safety."
            }
            return this
        }

        var addedCount = 0
        for (pkg in packages) {
            try {
                when (mode) {
                    SplitTunnelSettings.Mode.ALL -> Unit
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

    private fun Builder.applyTunnelAddresses(addresses: NativeCore.TunnelAddresses): Builder {
        val v4 = parseTunnelAddress(addresses.ipv4, 32)
            ?: error("Zero Trust identity has no usable IPv4 address")
        addAddress(v4.first, v4.second)
        addRoute("0.0.0.0", 0)
        val v6 = parseTunnelAddress(addresses.ipv6, 128)
        if (v6 != null) {
            addAddress(v6.first, v6.second)
            addRoute("::", 0)
        }
        return this
    }

    private fun lanBypassEnabled(): Boolean {
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        if (!prefs.contains("lan_bypass") && prefs.getBoolean("lan_sharing", false)) {
            prefs.edit().putBoolean("lan_bypass", true).apply()
            return true
        }
        return prefs.getBoolean("lan_bypass", false)
    }

    private fun Builder.applyLanAccess(addresses: NativeCore.TunnelAddresses): Builder {
        if (!lanBypassEnabled()) return this
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            ConnectionLog.record("LAN access uses system local routes on Android 12 and older")
            return this
        }
        val ranges = mutableListOf(
            "10.0.0.0/8",
            "192.168.0.0/16",
            "fc00::/7",
            "fe80::/10",
        )
        // WARP/Zero Trust device and gateway addresses live in 172.16.0.0/12.
        // Excluding that range would leak org DNS/gateway onto the LAN.
        if (!isWarpCgnat(addresses)) {
            ranges.add(1, "172.16.0.0/12")
        }
        ranges.forEach { cidr ->
            val (address, prefix) = cidr.split('/')
            excludeRoute(IpPrefix(InetAddress.getByName(address), prefix.toInt()))
        }
        ConnectionLog.record("LAN routes bypass the VPN")
        return this
    }

    private fun Builder.applyDns(config: String, addresses: NativeCore.TunnelAddresses): Builder {
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
        val fallbacks = mutableListOf("1.1.1.1", "1.0.0.1")
        if (addresses.ipv6.isNotBlank()) {
            fallbacks.add("2606:4700:4700::1111")
        }
        val fallbackAddrs = fallbacks.mapNotNull { runCatching { InetAddress.getByName(it) }.getOrNull() }
        (servers.ifEmpty { fallbackAddrs }).forEach { addDnsServer(it) }
        return this
    }

    private fun Builder.applyGatewayProxy(
        config: String,
        addresses: NativeCore.TunnelAddresses,
    ): Builder {
        if (!JSONObject(config).optBoolean("gateway", false)) return this
        val parsed = parseSocketAddress(addresses.gatewayProxy) ?: return this
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            setHttpProxy(ProxyInfo.buildDirectProxy(parsed.first, parsed.second))
            ConnectionLog.record("Zero Trust gateway ${parsed.first}:${parsed.second}")
        } else {
            ConnectionLog.record("Gateway filtering in VPN mode needs Android 10 or newer")
        }
        return this
    }

    private fun parseTunnelAddress(raw: String, defaultPrefix: Int): Pair<InetAddress, Int>? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        val host = trimmed.substringBefore('/')
        val prefix = trimmed.substringAfter('/', missingDelimiterValue = "")
            .toIntOrNull() ?: defaultPrefix
        val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return null
        val maxPrefix = if (address.address.size == 4) 32 else 128
        return address to prefix.coerceIn(0, maxPrefix)
    }

    private fun parseSocketAddress(raw: String): Pair<String, Int>? {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return null
        return if (trimmed.startsWith('[')) {
            val host = trimmed.substringAfter('[').substringBefore(']')
            val port = trimmed.substringAfter("]:", "").toIntOrNull() ?: return null
            host to port
        } else {
            val separator = trimmed.lastIndexOf(':')
            if (separator <= 0) return null
            val host = trimmed.substring(0, separator)
            val port = trimmed.substring(separator + 1).toIntOrNull() ?: return null
            host to port
        }
    }

    private fun isWarpCgnat(addresses: NativeCore.TunnelAddresses): Boolean {
        val host = addresses.ipv4.substringBefore('/').trim()
        val octets = host.split('.')
        if (octets.size == 4) {
            val first = octets[0].toIntOrNull()
            val second = octets[1].toIntOrNull()
            if (first == 172 && second != null && second in 16..31) return true
        }
        return addresses.gatewayProxy.contains("172.16.") ||
            addresses.gatewayProxy.contains("172.17.") ||
            addresses.gatewayProxy.contains("172.18.")
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
    private const val MAX_FILE_BYTES = 256 * 1024L
    private val entries = ArrayDeque<String>()
    private var sink: java.io.File? = null

    @Synchronized
    fun bind(file: java.io.File) {
        sink = file
        if (file.exists() && file.length() > MAX_FILE_BYTES) {
            file.delete()
        }
    }

    @Synchronized
    fun record(message: String) {
        val line = "${java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())}  $message"
        if (entries.size == MAX_ENTRIES) entries.removeFirst()
        entries.addLast(line)
        runCatching { sink?.appendText(line + "\n") }
    }

    @Synchronized
    fun snapshot(): List<String> = entries.toList()
}
