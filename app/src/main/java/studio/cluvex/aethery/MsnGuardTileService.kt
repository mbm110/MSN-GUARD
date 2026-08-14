package studio.cluvex.aethery

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
        toggleConnection()
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

    private fun toggleConnection() {
        val tile = qsTile ?: return
        val isConnected = TunnelStatus.isActive()

        if (isConnected) {
            // Disconnect
            startService(Intent(this, MsnGuardVpnService::class.java).setAction(MsnGuardVpnService.ACTION_DISCONNECT))
            tile.state = Tile.STATE_INACTIVE
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                tile.subtitle = getString(R.string.vpn_disconnected)
            }
            tile.updateTile()
        } else {
            // Connect - need VPN permission first
            val connectionType = connectionType()
            if (connectionType == ConnectionType.PROXY) {
                // Proxy mode doesn't need VPN permission
                val config = configJson()
                startForegroundService(
                    Intent(this, MsnGuardVpnService::class.java)
                        .setAction(MsnGuardVpnService.ACTION_CONNECT)
                        .putExtra(MsnGuardVpnService.EXTRA_CONFIG, config)
                        .putExtra(MsnGuardVpnService.EXTRA_VPN_MODE, false)
                )
                tile.state = Tile.STATE_ACTIVE
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = getString(R.string.vpn_connecting)
                }
                tile.updateTile()
            } else {
                // VPN mode - need permission
                val permissionIntent = VpnService.prepare(this)
                if (permissionIntent == null) {
                    // Already have permission
                    val config = configJson()
                    startForegroundService(
                        Intent(this, MsnGuardVpnService::class.java)
                            .setAction(MsnGuardVpnService.ACTION_CONNECT)
                            .putExtra(MsnGuardVpnService.EXTRA_CONFIG, config)
                            .putExtra(MsnGuardVpnService.EXTRA_VPN_MODE, true)
                    )
                    tile.state = Tile.STATE_ACTIVE
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        tile.subtitle = getString(R.string.vpn_connecting)
                    }
                    tile.updateTile()
                } else {
                    // Need to ask for permission - can't start activity from here
                    Log.w(LOG_TAG, "VPN permission required, cannot start from tile")
                }
            }
        }
    }

    private fun configJson(): String = CoreConfig.json(this)

    private fun connectionType(): ConnectionType {
        val prefs = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        val name = prefs.getString(CONNECTION_TYPE, ConnectionType.VPN.name) ?: ConnectionType.VPN.name
        return ConnectionType.entries.find { it.name == name } ?: ConnectionType.VPN
    }

    private val selectedProtocolcoreName: String
        get() = getSharedPreferences(SETTINGS, MODE_PRIVATE)
            .getString(DEFAULT_PROTOCOL, Protocol.MASQUE.coreName)
            ?.let { name -> Protocol.entries.find { it.coreName == name } }
            ?.coreName ?: Protocol.MASQUE.coreName

    private fun socksPort(): Int = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getInt(DEFAULT_SOCKS_PORT, DEFAULT_SOCKS_PORT_VALUE)

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

    private fun lanSharingEnabled(): Boolean = getSharedPreferences(SETTINGS, MODE_PRIVATE)
        .getBoolean(LAN_SHARING, false)

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
        const val CONNECTION_TYPE = "connection_type"
        const val DEFAULT_SCAN = "default_scan"
        const val DEFAULT_SCAN_MODE = "default_scan_mode"
        const val ENDPOINT_DISCOVERY = "endpoint_discovery"
        const val DEFAULT_MASQUE_TRANSPORT = "default_masque_transport"
        const val OBFUSCATION_PROFILE = "obfuscation_profile"
        const val MANUAL_ENDPOINT = "manual_endpoint"
        const val RETRY_OBFUSCATION = "retry_obfuscation_profiles"
        const val TLS_CURVE_PRESET = "tls_curve_preset"
        const val WIREGUARD_DATA_CHECK = "wireguard_data_check"
        const val LAN_SHARING = "lan_sharing"
        const val LOG_LEVEL = "log_level"
        const val PERF_PROFILE = "perf_profile"
        const val H2_FRAGMENTATION = "h2_fragmentation"
        const val DEFAULT_SOCKS_PORT = "default_socks_port"
        const val DEFAULT_SOCKS_PORT_VALUE = 1819
        const val DEFAULT_PROTOCOL = "default_protocol"

        enum class ConnectionType(val label: String, val description: String) {
            VPN("VPN", "Routes device traffic through Android VPN"),
            PROXY("Proxy", "Starts local SOCKS5 at 127.0.0.1:1819"),
        }

        enum class Protocol(
            val label: String,
            val coreName: String,
            val description: String,
        ) {
            MASQUE("MASQUE", "masque", "HTTP/3 tunnel"),
            WIREGUARD("WireGuard", "wireguard", "WireGuard tunnel"),
            WARP_IN_WARP("WARP-on-WARP", "gool", "Double-layer tunnel"),
            PSIPHON("Psiphon", "psiphon", "SOCKS5 proxy tunnel"),
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
