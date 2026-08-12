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
import java.util.ArrayDeque
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import ca.psiphon.PsiphonTunnel

class AetherVpnService : VpnService(), NativeCore.CoreCallback, PsiphonTunnel.HostService {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val connected = AtomicBoolean(false)
    private val stopRequested = AtomicBoolean(false)
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
    private var psiphonTunnel: PsiphonTunnel? = null
    private var psiphonConfigJson: String = ""
    private var psiphonVpnMode = false
    private var psiphonVpnActivated = false
    private var activeSocksPort = 0

    companion object {
        const val LOG_TAG = "AetherVpnService"
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
        const val STATUS_DISCONNECTED = "disconnected"
        const val STATUS_FAILED = "failed"
        const val CHANNEL_ID = "vpn_channel"
        const val NOTIFICATION_ID = 1
        const val TRAFFIC_PREFS = "traffic_stats"
        const val TRAFFIC_MONTH = "month"
        const val TRAFFIC_TX = "tx"
        const val TRAFFIC_RX = "rx"
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    override fun bindToDevice(fd: Long) {
        if (!protect(fd.toInt())) {
            throw PsiphonTunnel.Exception("protect(fd=$fd) failed")
        }
    }

    override fun onListeningSocksProxyPort(port: Int) {
        activeSocksPort = port
        ConnectionLog.record("Psiphon SOCKS proxy listening on port $port")
    }

    override fun onConnecting() {
        ConnectionLog.record("Psiphon connecting")
    }

    override fun onConnected() {
        ConnectionLog.record("Psiphon connected — upstream tunnel ready")

        val port = activeSocksPort
        if (port <= 0) {
            sendStatus(STATUS_FAILED, "Psiphon SOCKS port unavailable")
            return
        }
        val socksProxy = "127.0.0.1:$port"

        if (!psiphonVpnMode) {
            // PROXY MODE: just expose the SOCKS port — no TUN needed.
            ConnectionLog.record("Psiphon SOCKS proxy ready at $socksProxy")
            sendStatus(STATUS_CONNECTED)
            return
        }

        // VPN MODE: TUN is already up (created in startTunnel() before Psiphon
        // started). tun2socks keeps running across Psiphon rotations — the SOCKS
        // port is fixed, so a rotation only breaks in-flight upstream sockets and
        // lwIP resets those individual flows while the TUN device stays up.
        if (psiphonVpnActivated && Tun2SocksManager.isRunning) {
            ConnectionLog.record("Psiphon reconnected — tun2socks still routing, nothing to do")
            sendStatus(STATUS_CONNECTED)
            return
        }

        val tunFd = tun
        if (tunFd == null) {
            sendStatus(STATUS_FAILED, "VPN interface missing")
            return
        }

        if (!Tun2SocksManager.start(tunFd, port)) {
            sendStatus(STATUS_FAILED, "Could not start whole-device routing")
            return
        }
        psiphonVpnActivated = true
        ConnectionLog.record("Whole-device routing active via tun2socks → $socksProxy")
        connected.set(true)
        // Replace the placeholder "Connecting..." notification immediately. It used
        // to be overwritten by the first traffic sample from the Rust core; with
        // tun2socks the first sample can be seconds away, so the notification
        // would sit on "Connecting..." while the device was fully tunnelled.
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification(currentTx, currentRx))
        sendStatus(STATUS_CONNECTED)
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
        // In VPN mode there is no Rust core in the data path anymore, so Psiphon's
        // own byte counters are the source of traffic stats. These arrive as
        // deltas, not totals.
        if (!psiphonVpnMode) return
        currentTx += sent
        currentRx += received
        updateTrafficNotification(currentTx, currentRx)
    }

    override fun onDiagnosticMessage(message: String) {
        ConnectionLog.record("Psiphon: $message")
    }

    override fun getContext(): android.content.Context = this

    override fun getPsiphonConfig(): String = psiphonConfigJson

    private fun buildPsiphonConfig(vpnMode: Boolean = true): String {
        val prefs = getSharedPreferences("settings", MODE_PRIVATE)
        // VPN mode: always use fixed port 1819 so TUN can be pre-created.
        // Proxy mode: use user-configured port (default 1819).
        val socksPort = prefs.getInt("default_socks_port", 1819)
        return org.json.JSONObject().apply {
            put("PropagationChannelId", "FFFFFFFFFFFFFFFF")
            put("SponsorId", "1111111111111111")
            put("EgressRegion", "")
            put("EstablishTunnelTimeoutSeconds", 0)
            put("DataDirectory", filesDir.absolutePath)
            put("ClientVersion", "1")
            put("TunnelProtocol", "")
            put("RemoteServerListURL", "")
            put("LocalSocksProxyPort", socksPort)
            put("RemoteServerListSignaturePublicKey", "MIICIDANBgkqhkiG9w0BAQEFAAOCAg0AMIICCAKCAgEAt7Ls+/39r+T6zNW7GiVpJfzq/xvL9SBH5rIFnk0RXYEYavax3WS6HOD35eTAqn8AniOwiH+DOkvgSKF2caqk/y1dfq47Pdymtwzp9ikpB1C5OfAysXzBiwVJlCdajBKvBZDerV1cMvRzCKvKwRmvDmHgphQQ7WfXIGbRbmmk6opMBh3roE42KcotLFtqp0RRwLtcBRNtCdsrVsjiI1Lqz/lH+T61sGjSjQ3CHMuZYSQJZo/KrvzgQXpkaCTdbObxHqb6/+i1qaVOfEsvjoiyzTxJADvSytVtcTjijhPEV6XskJVHE1Zgl+7rATr/pDQkw6DPCNBS1+Y6fy7GstZALQXwEDN/qhQI9kWkHijT8ns+i1vGg00Mk/6J75arLhqcodWsdeG/M/moWgqQAnlZAGVtJI1OgeF5fsPpXu4kctOfuZlGjVZXQNW34aOzm8r8S0eVZitPlbhcPiR4gT/aSMz/wd8lZlzZYsje/Jr8u/YtlwjjreZrGRmG8KMOzukV3lLmMppXFMvl4bxv6YFEmIuTsOhbLTwFgh7KYNjodLj/LsqRVfwz31PgWQFTEPICV7GCvgVlPRxnofqKSjgTWI4mxDhBpVcATvaoBl1L/6WLbFvBsoAUBItWwctO2xalKxF5szhGm8lccoc5MZr8kfE0uxMgsxz4er68iCID+rsCAQM=")
            put("ServerEntrySignaturePublicKey", "sHuUVTWaRyh5pZwy4UguSgkwmBe0EHtJJkoF5WrxmvA=")
            put("ExchangeObfuscationKey", "DpXzloJk1Hw6aSzmKKky0xcahsEHubch81Mi6K0XMlU=")
            // Required for onBytesTransferred() to ever fire. Psiphon suppresses
            // the BytesTransferred notice unless this is set, and in VPN mode
            // Psiphon's counters are the ONLY traffic source now that the Rust
            // core is out of the data path — without it the notification stays
            // stuck on "Connecting..." forever and data usage reads 0.
            put("EmitBytesTransferred", true)
            // Note: "DisableNetworkManager" was tried here and is a no-op — the
            // key does not exist in libgojni.so (verified with strings). Psiphon's
            // NetworkMonitor still restarts the tunnel when tun0 appears. That is
            // survivable now: tun2socks holds the TUN fd and the SOCKS port is
            // fixed, so a rotation only kills in-flight upstream sockets and lwIP
            // resets those flows individually instead of dropping the interface.
        }.toString()
    }

    private fun startPsiphonTunnel(vpnMode: Boolean = true) {
        try {
            val tunnel = PsiphonTunnel.newPsiphonTunnel(this)
            // Always SOCKS mode — in VPN mode we bridge TUN→SOCKS ourselves.
            tunnel.setVpnMode(false)
            psiphonTunnel = tunnel
            psiphonConfigJson = buildPsiphonConfig(vpnMode)

            // Load hex-encoded server entries from assets
            val serverEntries = try {
                assets.open("server_entries.txt").bufferedReader().readText().trim()
            } catch (e: Exception) {
                ConnectionLog.record("No server_entries.txt in assets: ${e.message}")
                ""
            }
            // Fire-and-forget: Psiphon connects asynchronously.
            // onListeningSocksProxyPort() saves the port.
            // onConnected() starts the Rust core to bridge TUN → SOCKS.
            tunnel.startTunneling(serverEntries)
            ConnectionLog.record("Psiphon tunnel starting...")
        } catch (e: Exception) {
            ConnectionLog.record("Psiphon start failed: ${e.message}")
            activeSocksPort = 0
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
                    stopTunnel(notify = false, teardownService = false)
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
        currentProtocol = config.substringAfter("\"protocol\":\"").substringBefore('"').uppercase()
        currentVpnIp = ""
        currentPing = ""
        stopRequested.set(false)
        vpnModeActive.set(vpnMode)
        startAsForeground()

        // PSIPHON: callback-driven lifecycle — MUST NOT enter try/finally.
        // The finally block calls stopSelf() which destroys the service and kills Psiphon.
        if (currentProtocol.contains("PSIPHON")) {
            psiphonVpnMode = vpnMode  // Save for onConnected() callback
            psiphonVpnActivated = false
            worker.execute {
                try {
                    ConnectionLog.record("Preparing PSIPHON identity (${if (vpnMode) "VPN" else "Proxy"} mode)")
                    if (vpnMode) {
                        // VPN MODE: Create TUN FIRST, then start Psiphon.
                        // This prevents Psiphon's NetworkMonitor from seeing a "change"
                        // when tun0 appears — the 13-second restart loop is eliminated.
                        val socksPort = getSharedPreferences("settings", MODE_PRIVATE)
                            .getInt("default_socks_port", 1819)

                        // Address plan comes from tun2socks: the interface gets
                        // .ipAddress while lwIP answers on .router, which is also
                        // the DNS resolver the system will use. These must not be
                        // swapped or lwIP drops every packet.
                        val address = Tun2SocksManager.selectPrivateAddress()

                        ConnectionLog.record("Creating TUN interface BEFORE Psiphon starts")
                        tun = Builder()
                            .setSession("MSN-VPN")
                            .setMtu(Tun2SocksManager.VPN_INTERFACE_MTU)
                            .addAddress(address.ipAddress, address.prefixLength)
                            .addRoute("0.0.0.0", 0)
                            .addRoute(address.subnet, address.prefixLength)
                            .addDnsServer(address.router)
                            .addDisallowedApplication(packageName)
                            .establish() ?: error("Android could not establish the VPN interface")
                        vpnModeActive.set(true)
                        ConnectionLog.record("TUN ready — now starting Psiphon on port $socksPort")
                        // Pre-save the SOCKS port so onConnected() can start tun2socks immediately.
                        activeSocksPort = socksPort
                        startPsiphonTunnel(vpnMode)
                        sendStatus(STATUS_CONNECTING, "Psiphon starting...")
                    } else {
                        // PROXY MODE: just start Psiphon, no TUN needed.
                        startPsiphonTunnel(vpnMode)
                        sendStatus(STATUS_CONNECTING, "Psiphon starting...")
                    }
                } catch (e: Exception) {
                    ConnectionLog.record("Psiphon start failed: ${e.message}")
                    sendStatus(STATUS_FAILED, e.message)
                    connected.set(false)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
            return
        }

        worker.execute {
            try {
                ConnectionLog.record("Preparing $currentProtocol identity")
                NativeCore.attach(this)
                val result = if (vpnMode) {
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
                        // applySplitTunneling() handles app exclusion per mode.
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


    private fun stopTunnel(notify: Boolean = true, teardownService: Boolean = true) {
        stopRequested.set(true)
        // Order matters: stop routing first so no more packets enter a tunnel
        // that is being torn down, then stop Psiphon itself.
        Tun2SocksManager.stop()
        stopPsiphonTunnel()
        NativeCore.stop()

        if (psiphonVpnMode) {
            // In VPN mode nothing else owns the service lifecycle now that the
            // Rust core is out of the data path, so tear down here.
            NativeCore.detach()
            vpnModeActive.set(false)
            psiphonVpnActivated = false
            tun?.close()
            tun = null
            connected.set(false)
            if (notify) sendStatus(STATUS_DISCONNECTED)
            // A reconnect re-enters startTunnel() on the worker thread, so the
            // service must survive; only a real disconnect stops it.
            if (teardownService) {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
            return
        }

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
            "VPN Service",
            NotificationManager.IMPORTANCE_LOW
        ))
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("MSN-GUARD")
            .setContentText("Connecting...")
            .setSmallIcon(android.R.drawable.ic_menu_rotate)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    private fun notification(tx: Long, rx: Long): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, AetherVpnService::class.java).apply {
            action = ACTION_DISCONNECT
            putExtra(EXTRA_CONFIG, storedConfig ?: "")
            putExtra(EXTRA_VPN_MODE, storedVpnMode)
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this, 1, disconnectIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val reconnectIntent = Intent(this, AetherVpnService::class.java).apply {
            action = ACTION_RECONNECT
        }
        val reconnectPendingIntent = PendingIntent.getService(
            this, 2, reconnectIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("MSN-GUARD")
            .setContentText("VPN: $currentProtocol • ${formatBytes(tx)}↑ ${formatBytes(rx)}↓ • ${formatSpeed(currentSpeedTx)}↑ ${formatSpeed(currentSpeedRx)}↓")
            .setSmallIcon(android.R.drawable.ic_menu_rotate)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", disconnectPendingIntent)
            .addAction(android.R.drawable.ic_menu_revert, "Reconnect", reconnectPendingIntent)
            .build()
    }

    private fun Builder.applySplitTunneling(): Builder {
        val settings = SplitTunnelSettings(this@AetherVpnService)
        val mode = settings.mode()
        val packages = settings.packages()

        if (mode == SplitTunnelSettings.Mode.ALL) {
            // GLOBAL: all apps through VPN, but MUST exclude ourselves to prevent routing loop.
            addDisallowedApplication(packageName)
            return this
        }
        if (mode == SplitTunnelSettings.Mode.INCLUDE) {
            // INCLUDE (whitelist): only listed apps go through VPN.
            // Do NOT add our own packageName — it's excluded by default.
            // Do NOT use addDisallowedApplication here (mixing with addAllowedApplication crashes).
        }
        if (packages.isEmpty()) {
            check(mode != SplitTunnelSettings.Mode.INCLUDE) {
                "No apps selected for tunnel. Connection aborted for safety."
            }
            // EXCLUDE with empty list: nothing to exclude beyond ourselves.
            addDisallowedApplication(packageName)
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

        // EXCLUDE mode: also disallow our own app to prevent routing loop.
        if (mode == SplitTunnelSettings.Mode.EXCLUDE) {
            addDisallowedApplication(packageName)
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
        // Always force known-good public DNS to prevent carrier DNS leaks.
        // Carrier DNS (10.x.x.x) is rejected by Psiphon SOCKS5 (reply 5).
        val forcedDns = listOf("1.1.1.1", "8.8.8.8")
        forcedDns.forEach { addDnsServer(InetAddress.getByName(it)) }

        // Also add any DNS servers from config (for non-Psiphon protocols).
        val configured = JSONObject(config).optString("dns_servers")
        configured.split(',', ';', ' ', '\n')
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
            .filter { it.hostAddress !in forcedDns }
            .forEach { addDnsServer(it) }

        ConnectionLog.record("DNS forced to public resolvers, carrier DNS excluded")
        return this
    }
}

// ── ConnectionLog ──

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