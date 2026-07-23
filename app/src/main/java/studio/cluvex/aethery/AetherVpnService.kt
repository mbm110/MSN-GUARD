package studio.cluvex.aethery

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AetherVpnService : VpnService(), NativeCore.CoreCallback {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val connected = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var lastTrafficSampleMs = 0L

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> intent.getStringExtra(EXTRA_CONFIG)?.let { config ->
                startTunnel(config, intent.getBooleanExtra(EXTRA_VPN_MODE, true))
            }
            ACTION_DISCONNECT -> stopTunnel()
        }
        return Service.START_NOT_STICKY
    }

    override fun onDestroy() {
        stopTunnel(notify = false)
        worker.shutdownNow()
        super.onDestroy()
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

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
        stopRequested.set(false)
        startAsForeground()
        worker.execute {
            try {
                val protocol = config.substringAfter("\"protocol\":\"").substringBefore('\"').uppercase()
                ConnectionLog.record("Preparing $protocol identity")
                NativeCore.attach(this)
                val result = if (vpnMode) {
                    val addresses = NativeCore.prepare(config)
                    ConnectionLog.record("Creating Android VPN interface")
                    tun = Builder()
                        .setSession("Aethery")
                        .setMtu(1280)
                        .addAddress(addresses.ipv4, 32)
                        .addAddress(addresses.ipv6, 128)
                        .addRoute("0.0.0.0", 0)
                        .addRoute("::", 0)
                        .addDnsServer("1.1.1.1")
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
                    sendStatus(STATUS_FAILED, detail)
                }
            } catch (error: Exception) {
                val detail = NativeCore.lastError().ifBlank { error.message ?: "Tunnel setup failed" }
                Log.e(LOG_TAG, "Tunnel failed: $detail", error)
                sendStatus(STATUS_FAILED, detail)
            } finally {
                NativeCore.detach()
                tun?.close()
                tun = null
                connected.set(false)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun stopTunnel(notify: Boolean = true) {
        stopRequested.set(true)
        NativeCore.stop()
        if (notify) sendStatus(STATUS_DISCONNECTED)
    }

    private fun sendStatus(status: String, detail: String? = null) {
        Log.i(LOG_TAG, "status=$status${detail?.let { " detail=$it" } ?: ""}")
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_STATUS, status)
            .apply { detail?.let { putExtra(EXTRA_DETAIL, it) } })
    }

    private fun updateTrafficNotification(tx: Long, rx: Long) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastTrafficSampleMs < 900) return // Throttle UI updates
        
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification("↓ ${formatBytes(rx)}  ↑ ${formatBytes(tx)}"))
        lastTrafficSampleMs = now
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1_024 -> "$bytes B"
        bytes < 1_048_576 -> "${bytes / 1_024} KB"
        bytes < 1_073_741_824 -> "${bytes / 1_048_576} MB"
        else -> String.format(java.util.Locale.US, "%.2f GB", bytes / 1_073_741_824.toDouble())
    }

    private fun startAsForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID,
            getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ))
        val notification = notification(getString(R.string.vpn_notification))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun notification(content: String): Notification {
        val stopIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, AetherVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(content)
            .setOnlyAlertOnce(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopIntent)
            .build()
    }

    private fun Builder.applySplitTunneling(): Builder {
        val settings = SplitTunnelSettings(this@AetherVpnService)
        val mode = settings.mode()
        val packages = settings.packages()

        // Always exclude Aethery in Exclude or All mode to prevent routing loops.
        if (mode == SplitTunnelSettings.Mode.EXCLUDE || mode == SplitTunnelSettings.Mode.ALL) {
            try {
                addDisallowedApplication(packageName)
            } catch (_: Exception) {
                // Should not happen for own package
            }
        }

        if (mode == SplitTunnelSettings.Mode.ALL) return this
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

    companion object {
        const val ACTION_CONNECT = "studio.cluvex.aethery.CONNECT"
        const val ACTION_DISCONNECT = "studio.cluvex.aethery.DISCONNECT"
        const val ACTION_STATUS = "studio.cluvex.aethery.STATUS"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_VPN_MODE = "vpn_mode"
        const val EXTRA_STATUS = "status"
        const val EXTRA_DETAIL = "detail"
        const val STATUS_CONNECTING = "connecting"
        const val STATUS_STARTING = "starting"
        const val STATUS_SCANNING = "scanning"
        const val STATUS_CONNECTED = "connected"
        const val STATUS_FAILED = "failed"
        const val STATUS_DISCONNECTED = "disconnected"
        private const val CHANNEL_ID = "aethery_vpn"
        private const val NOTIFICATION_ID = 1
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
