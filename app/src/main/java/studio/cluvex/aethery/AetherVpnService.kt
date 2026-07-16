package studio.cluvex.aethery

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class AetherVpnService : VpnService() {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val readinessWorker = Executors.newSingleThreadScheduledExecutor()
    private val connected = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var readinessCheck: ScheduledFuture<*>? = null
    private var trafficCheck: ScheduledFuture<*>? = null
    private var lastRxBytes = 0L
    private var lastTxBytes = 0L
    private var lastTrafficSampleMs = 0L

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> intent.getStringExtra(EXTRA_CONFIG)?.let(::startTunnel)
            ACTION_DISCONNECT -> stopTunnel()
        }
        return Service.START_NOT_STICKY
    }

    override fun onDestroy() {
        stopTunnel(notify = false)
        worker.shutdownNow()
        readinessWorker.shutdownNow()
        super.onDestroy()
    }

    fun protectSocket(fd: Int): Boolean = protect(fd)

    private fun startTunnel(config: String) {
        if (!connected.compareAndSet(false, true)) return
        stopRequested.set(false)
        startAsForeground()
        watchTraffic()
        sendStatus(STATUS_STARTING)
        worker.execute {
            try {
                ConnectionLog.record("Preparing ${config.substringAfter("\"protocol\":\"").substringBefore('\"').uppercase()} identity")
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

                NativeCore.attach(this)
                ConnectionLog.record("Scanning MASQUE gateways")
                sendStatus(STATUS_SCANNING)
                watchReadiness()
                val result = NativeCore.start(config, tun!!.fd)
                check(result == 0) { NativeCore.lastError() }
                check(stopRequested.get()) {
                    NativeCore.lastError().ifBlank { "MASQUE tunnel closed before setup completed" }
                }
                sendStatus(STATUS_DISCONNECTED)
            } catch (error: Exception) {
                val detail = NativeCore.lastError().ifBlank { error.message ?: "Tunnel setup failed" }
                Log.e(LOG_TAG, "Tunnel failed: $detail", error)
                sendStatus(STATUS_FAILED, detail)
            } finally {
                readinessCheck?.cancel(true)
                readinessCheck = null
                trafficCheck?.cancel(true)
                trafficCheck = null
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
        readinessCheck?.cancel(true)
        readinessCheck = null
        trafficCheck?.cancel(true)
        trafficCheck = null
        NativeCore.stop()
        tun?.close()
        tun = null
        if (notify) sendStatus(STATUS_DISCONNECTED)
    }

    private fun sendStatus(status: String, detail: String? = null) {
        Log.i(LOG_TAG, "status=$status${detail?.let { " detail=$it" } ?: ""}")
        ConnectionLog.record("${status.replaceFirstChar(Char::uppercase)}${detail?.let { ": $it" } ?: ""}")
        sendBroadcast(Intent(ACTION_STATUS)
            .setPackage(packageName)
            .putExtra(EXTRA_STATUS, status)
            .apply { detail?.let { putExtra(EXTRA_DETAIL, it) } })
    }

    private fun watchReadiness() {
        readinessCheck?.cancel(true)
        readinessCheck = readinessWorker.scheduleAtFixedRate({
            if (NativeCore.isReady()) {
                ConnectionLog.record("CONNECT-IP accepted by gateway")
                sendStatus(STATUS_CONNECTED)
                readinessCheck?.cancel(false)
            }
        }, 250, 250, TimeUnit.MILLISECONDS)
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

    private fun watchTraffic() {
        lastRxBytes = trafficBytes(TrafficStats.getUidRxBytes(applicationInfo.uid))
        lastTxBytes = trafficBytes(TrafficStats.getUidTxBytes(applicationInfo.uid))
        lastTrafficSampleMs = SystemClock.elapsedRealtime()
        trafficCheck?.cancel(true)
        trafficCheck = readinessWorker.scheduleAtFixedRate({
            val now = SystemClock.elapsedRealtime()
            val elapsedMs = (now - lastTrafficSampleMs).coerceAtLeast(1L)
            val rx = trafficBytes(TrafficStats.getUidRxBytes(applicationInfo.uid))
            val tx = trafficBytes(TrafficStats.getUidTxBytes(applicationInfo.uid))
            val down = ((rx - lastRxBytes).coerceAtLeast(0L) * 1_000 / elapsedMs)
            val up = ((tx - lastTxBytes).coerceAtLeast(0L) * 1_000 / elapsedMs)
            lastRxBytes = rx
            lastTxBytes = tx
            lastTrafficSampleMs = now
            getSystemService(NotificationManager::class.java)
                .notify(NOTIFICATION_ID, notification("↓ ${formatRate(down)}  ↑ ${formatRate(up)}"))
        }, 1, 1, TimeUnit.SECONDS)
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

    private fun trafficBytes(bytes: Long): Long =
        if (bytes == TrafficStats.UNSUPPORTED.toLong()) 0L else bytes

    private fun formatRate(bytesPerSecond: Long): String = when {
        bytesPerSecond < 1_024 -> "$bytesPerSecond B/s"
        bytesPerSecond < 1_048_576 -> "${bytesPerSecond / 1_024} KB/s"
        else -> "${bytesPerSecond / 1_048_576} MB/s"
    }

    private fun Builder.applySplitTunneling(): Builder {
        val settings = SplitTunnelSettings(this@AetherVpnService)
        val packages = settings.packages()
        if (settings.mode() == SplitTunnelSettings.Mode.ALL) return this
        if (packages.isEmpty()) {
            check(settings.mode() != SplitTunnelSettings.Mode.INCLUDE) {
                "Select at least one app for split tunneling"
            }
            return this
        }
        packages.forEach { packageName ->
            try {
                when (settings.mode()) {
                    SplitTunnelSettings.Mode.INCLUDE -> addAllowedApplication(packageName)
                    SplitTunnelSettings.Mode.EXCLUDE -> addDisallowedApplication(packageName)
                    SplitTunnelSettings.Mode.ALL -> Unit
                }
            } catch (_: android.content.pm.PackageManager.NameNotFoundException) {
                ConnectionLog.record("Split tunnel skipped removed app: $packageName")
            }
        }
        ConnectionLog.record("Split tunnel ${settings.mode().label.lowercase()}: ${packages.size} app(s)")
        return this
    }

    companion object {
        const val ACTION_CONNECT = "studio.cluvex.aethery.CONNECT"
        const val ACTION_DISCONNECT = "studio.cluvex.aethery.DISCONNECT"
        const val ACTION_STATUS = "studio.cluvex.aethery.STATUS"
        const val EXTRA_CONFIG = "config"
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
