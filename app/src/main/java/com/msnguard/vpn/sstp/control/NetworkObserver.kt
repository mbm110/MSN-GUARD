package com.msnguard.vpn.sstp.control

import com.msnguard.vpn.sstp.*
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import com.msnguard.vpn.sstp.SharedBridge
import com.msnguard.vpn.sstp.OscPrefKey
import com.msnguard.vpn.sstp.getBooleanPrefValue
import com.msnguard.vpn.sstp.getStringPrefValue
import com.msnguard.vpn.sstp.setStringPrefValue


internal class NetworkObserver(val bridge: SharedBridge) {
    private val manager = bridge.service.networkManager()
    private val callback: ConnectivityManager.NetworkCallback

    init {
        wipeStatus()

        val request = NetworkRequest.Builder().let {
            it.addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            it.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            it.build()
        }


        callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
                    manager.getLinkProperties(network)?.also {
                        updateSummary(it)
                    }
                }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                updateSummary(linkProperties)
            }
        }

        manager.registerNetworkCallback(request, callback)
    }

    private fun updateSummary(properties: LinkProperties) {
        val summary = mutableListOf<String>()

        summary.add("[Assigned IP Address]")
        properties.linkAddresses.forEach {
            summary.add(it.address.hostAddress ?: "")
        }
        summary.add("")

        summary.add("[DNS Server Address]")
        if (properties.dnsServers.isNotEmpty()) {
            properties.dnsServers.forEach {
                summary.add(it.hostAddress ?: "")
            }
        } else {
            summary.add("Not specified")
        }
        summary.add("")

        summary.add("[Routing]")
        properties.routes.forEach {
            summary.add(it.toString())
        }
        summary.add("")

        val doEnableAppBasedRule = getBooleanPrefValue(OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE, bridge.prefs)
        if (doEnableAppBasedRule) {
            summary.add("[${getStringPrefValue(OscPrefKey.ROUTE_APP_LIST_TYPE, bridge.prefs)}]")
            bridge.selectedApps.forEach { summary.add(it.label) }
        }

        summary.reduce { acc, s ->
            acc + "\n" + s
        }.also {
            setStringPrefValue(it, OscPrefKey.HOME_STATUS, bridge.prefs)
        }
    }

    private fun wipeStatus() {
        setStringPrefValue("", OscPrefKey.HOME_STATUS, bridge.prefs)
    }

    internal fun close() {
        try {
            manager.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {} // already unregistered

        wipeStatus()
    }
}
