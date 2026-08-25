package com.msnguard.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import android.net.VpnService

class MsnGuardTileService : TileService() {

    override fun onTileAdded() {
        super.onTileAdded()
        updateTile()
    }

    override fun onTileRemoved() {
        super.onTileRemoved()
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        // toggleConnection() reports whether it already dealt with the shade —
        // the consent path opens the app, which collapses it. Starting a second
        // activity on top of that would cover Android's consent dialog.
        if (!toggleConnection()) collapseShade()
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val isConnected = TunnelStatus.isActive()
        val state = if (isConnected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE

        tile.state = state
        tile.icon = Icon.createWithResource(
            this,
            R.drawable.ic_notification
        )
        tile.label = getString(R.string.vpn_tile_label)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (isConnected) getString(R.string.vpn_connected) else getString(R.string.vpn_disconnected)
        }
        tile.updateTile()
    }

    /**
     * Applies the tap.
     *
     * @return true when this call already started an activity (and therefore
     *   collapsed the shade itself), so the caller must not start another.
     */
    private fun toggleConnection(): Boolean {
        val tile = qsTile ?: return false
        val isConnected = TunnelStatus.isActive()

        if (isConnected) {
            // Disconnect
            startService(Intent(this, MsnGuardVpnService::class.java).setAction(MsnGuardVpnService.ACTION_DISCONNECT))
            tile.state = Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.vpn_disconnected)
            }
            tile.updateTile()
            return false
        }

        // Connect. VPN mode is the only mode, so Android's VPN consent is
        // always required before the service may build a TUN.
        val permissionIntent = VpnService.prepare(this)
        if (permissionIntent == null) {
            // Already have permission
            val config = configJson()
            startForegroundService(
                Intent(this, MsnGuardVpnService::class.java)
                    .setAction(MsnGuardVpnService.ACTION_CONNECT)
                    .putExtra(MsnGuardVpnService.EXTRA_CONFIG, config)
            )
            tile.state = Tile.STATE_ACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.vpn_connecting)
            }
            tile.updateTile()
            return false
        }

        // No VPN consent yet. A TileService cannot host the consent dialog, so
        // open the app and let it ask — silently logging left the user tapping a
        // tile that visibly did nothing.
        Log.w(LOG_TAG, "VPN permission required; opening the app to ask")
        openApp()
        return true
    }

    /**
     * Collapses the Quick Settings shade after a toggle.
     *
     * `startActivityAndCollapse` is the only supported way to do this, and it
     * insists on a real activity — hence [ShadeCollapseActivity], which finishes
     * immediately and draws nothing.
     *
     * Skipped when the consent path already ran: that path calls [openApp], which
     * collapses the shade itself, and starting a second activity on top would
     * cover the consent dialog.
     */
    private fun collapseShade() {
        val intent = Intent(this, ShadeCollapseActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startActivityAndCollapse(
                    PendingIntent.getActivity(
                        this,
                        1,
                        intent,
                        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                    )
                )
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (error: Exception) {
            // Never let a cosmetic shade animation break the toggle: some OEM
            // shells restrict activity starts from a tile. The connect/disconnect
            // has already been issued by this point.
            Log.w(LOG_TAG, "Could not collapse the shade: ${error.message}")
        }
    }

    /**
     * Brings the app up so it can ask for VPN consent, and closes the shade.
     *
     * The `Intent` overload of `startActivityAndCollapse` throws on API 34+, and
     * the `PendingIntent` overload does not exist below it, so both are needed.
     */
    private fun openApp() {
        val intent = Intent(this, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(
                PendingIntent.getActivity(
                    this,
                    0,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
            )
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    /**
     * Config for a tile-initiated connect.
     *
     * Honours the chain card: the tile's whole promise is "reconnect the way I
     * last connected", so if Psiphon-over-WARP is armed the tile must raise the
     * chain, not the bare transport underneath it.
     *
     * Tor needs nothing here. Its config is the plain `tor` one either way and the
     * service decides the chain from `TorManager.chainArmed`, so a tile connect
     * picks up Tor-over-WARP automatically.
     */
    private fun configJson(): String {
        val prefs = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        val armed = prefs.getBoolean(CHAIN_ARMED, CHAIN_ARMED_DEFAULT)
        val picked = prefs.getString(DEFAULT_PROTOCOL, Protocol.MASQUE.coreName)
        // Same rule as the main screen: this marker is Psiphon's, so it only applies
        // when Psiphon is the selected transport.
        return if (armed && picked == Protocol.PSIPHON.coreName) {
            CoreConfig.json(this, MsnGuardVpnService.CHAIN_PROTOCOL_MARKER.lowercase())
        } else {
            CoreConfig.json(this)
        }
    }

    private val selectedProtocolcoreName: String
        get() = getSharedPreferences(SETTINGS, MODE_PRIVATE)
            .getString(DEFAULT_PROTOCOL, Protocol.MASQUE.coreName)
            ?.let { name -> Protocol.entries.find { it.coreName == name } }
            ?.coreName ?: Protocol.MASQUE.coreName

    private fun defaultScan(): ScanTarget {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE).getString(DEFAULT_SCAN, ScanTarget.IPV4.coreName)
        return ScanTarget.entries.find { it.coreName == name } ?: ScanTarget.IPV4
    }

    private fun defaultScanMode(): ScanMode {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE).getString(DEFAULT_SCAN_MODE, ScanMode.BALANCED.coreName)
        return ScanMode.entries.find { it.coreName == name } ?: ScanMode.BALANCED
    }

    private fun defaultEndpointDiscovery(): EndpointDiscovery {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE)
            .getString(ENDPOINT_DISCOVERY, EndpointDiscovery.CACHE.coreName)
        return EndpointDiscovery.entries.find { it.coreName == name } ?: EndpointDiscovery.CACHE
    }

    private fun defaultMasqueTransport(): MasqueTransport {
        val name = getSharedPreferences(SETTINGS, MODE_PRIVATE)
            .getString(DEFAULT_MASQUE_TRANSPORT, MasqueTransport.H3.coreName)
        return MasqueTransport.entries.find { it.coreName == name } ?: MasqueTransport.H3
    }

    private fun obfuscationProfile(): ObfuscationProfile = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getString(OBFUSCATION_PROFILE, ObfuscationProfile.BALANCED.coreName)
        ?.let { name -> ObfuscationProfile.entries.find { it.coreName == name } }
        ?: ObfuscationProfile.BALANCED

    private fun manualEndpoint(): String? = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getString(MANUAL_ENDPOINT, null)?.takeIf { it.isNotBlank() }

    private fun retryObfuscationProfiles(): Boolean = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getBoolean(RETRY_OBFUSCATION, true)

    private fun tlsCurvePreset(): TlsCurvePreset = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getString(TLS_CURVE_PRESET, TlsCurvePreset.CHROME.coreName)
        ?.let { name -> TlsCurvePreset.entries.find { it.coreName == name } }
        ?: TlsCurvePreset.CHROME

    private fun wireGuardDataCheck(): Boolean = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getBoolean(WIREGUARD_DATA_CHECK, true)

    private fun logLevel(): String = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getString(LOG_LEVEL, "info") ?: "info"

    private fun perfProfile(): String = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getString(PERF_PROFILE, "auto") ?: "auto"

    private fun h2Fragmentation(): Boolean = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getString(H2_FRAGMENTATION, "on") == "on"

    companion object {
        private const val LOG_TAG = "AetherTile"

        // From MainActivity
        const val SETTINGS = "settings"
        const val DEFAULT_SCAN = "default_scan"
        const val DEFAULT_SCAN_MODE = "default_scan_mode"
        const val ENDPOINT_DISCOVERY = "endpoint_discovery"
        const val DEFAULT_MASQUE_TRANSPORT = "default_masque_transport"
        const val OBFUSCATION_PROFILE = "obfuscation_profile"
        const val MANUAL_ENDPOINT = "manual_endpoint"
        const val RETRY_OBFUSCATION = "retry_obfuscation_profiles"
        const val TLS_CURVE_PRESET = "tls_curve_preset"
        const val WIREGUARD_DATA_CHECK = "wireguard_data_check"
        const val LOG_LEVEL = "log_level"
        const val PERF_PROFILE = "perf_profile"
        const val H2_FRAGMENTATION = "h2_fragmentation"
        const val DEFAULT_PROTOCOL = "default_protocol"
        /** Mirrors MainActivity.CHAIN_ARMED — same SharedPreferences file. */
        const val CHAIN_ARMED = "chain_armed"

        /**
         * Mirrors MainActivity.CHAIN_ARMED_DEFAULT.
         *
         * Must stay in step with it: the tile's promise is "reconnect the way I last
         * connected", so if the two defaults disagree, a tile-initiated connect on a
         * fresh install raises a different tunnel shape than the button does.
         */
        const val CHAIN_ARMED_DEFAULT = true


        enum class Protocol(
            val label: String,
            val coreName: String,
            val description: String,
        ) {
            MASQUE("MASQUE", "masque", "HTTP/3 tunnel"),
            WIREGUARD("WireGuard", "wireguard", "WireGuard tunnel"),
            WARP_IN_WARP("WARP-on-WARP", "gool", "Double-layer tunnel"),
            PSIPHON("Psiphon", "psiphon", "SOCKS5 proxy tunnel"),
            TOR("Tor", "tor", "Onion routing"),
        }

        enum class ScanTarget(
            val label: String,
            val coreName: String,
            val description: String,
        ) {
            IPV4("IPv4", "v4", "Scan IPv4 endpoints only"),
            IPV6("IPv6", "v6", "Scan IPv6 endpoints only"),
            BOTH("Both", "both", "Scan IPv4 and IPv6 endpoints"),
        }

        enum class ScanMode(
            val label: String,
            val coreName: String,
            val description: String,
        ) {
            TURBO("Turbo", "turbo", "Fastest scan; first verified route wins"),
            BALANCED("Balanced", "balanced", "Default mix of speed and coverage"),
            THOROUGH("Thorough", "thorough", "Deep scan; selects best latency"),
            STEALTH("Stealth", "stealth", "Quiet, patient probing"),
            IRONCLAD("Ironclad", "ironclad", "Strict CONNECT-IP verification before selection"),
        }

        enum class EndpointDiscovery(
            val label: String,
            val coreName: String,
            val description: String,
        ) {
            CACHE("Cache & refresh", "cache", "Use verified gateways first, then discover more"),
            FRESH("Fresh scan", "fresh", "Start a new scan every connection"),
        }

        enum class MasqueTransport(
            val label: String,
            val coreName: String,
            val description: String,
        ) {
            H3("HTTP/3", "h3", "QUIC; best on healthy UDP networks"),
            H2("HTTP/2", "h2", "TCP; use when UDP or QUIC is blocked"),
        }

        enum class ObfuscationProfile(val label: String, val coreName: String, val description: String) {
            OFF("Off", "off", "No traffic-shape padding"),
            LIGHT("Light", "light", "Lower overhead on mild filtering"),
            BALANCED("Balanced", "balanced", "Recommended filtering resistance"),
            AGGRESSIVE("Aggressive", "aggressive", "Highest resistance; slower setup"),
        }

        enum class TlsCurvePreset(val label: String, val coreName: String, val description: String) {
            CHROME("Chrome", "chrome", "Chrome TLS curve ordering"),
            COMPATIBILITY("Compatibility", "compatibility", "P-256 and X25519 only"),
        }
    }
}
