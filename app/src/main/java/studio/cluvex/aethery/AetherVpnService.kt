package studio.cluvex.aethery

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
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
        sendStatus(STATUS_CONNECTING)
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
                    .establish() ?: error("Android could not establish the VPN interface")

                NativeCore.attach(this)
                ConnectionLog.record("Scanning MASQUE gateways")
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
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(getString(R.string.vpn_notification))
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        const val ACTION_CONNECT = "studio.cluvex.aethery.CONNECT"
        const val ACTION_DISCONNECT = "studio.cluvex.aethery.DISCONNECT"
        const val ACTION_STATUS = "studio.cluvex.aethery.STATUS"
        const val EXTRA_CONFIG = "config"
        const val EXTRA_STATUS = "status"
        const val EXTRA_DETAIL = "detail"
        const val STATUS_CONNECTING = "connecting"
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
