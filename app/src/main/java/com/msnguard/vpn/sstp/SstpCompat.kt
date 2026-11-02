package com.msnguard.vpn.sstp

import android.content.SharedPreferences
import android.net.Uri

internal enum class OscPrefKey {
    HOME_HOSTNAME, HOME_USERNAME, HOME_PASSWORD, SSL_PORT, SSL_VERSION, SSL_DO_VERIFY,
    SSL_DO_SPECIFY_CERT, SSL_CERT_DIR, SSL_DO_SELECT_SUITES, SSL_SUITES,
    SSL_DO_USE_CUSTOM_SNI, SSL_CUSTOM_SNI, PROXY_DO_USE_PROXY, PROXY_HOSTNAME,
    PROXY_PORT, PROXY_USERNAME, PROXY_PASSWORD, PPP_MRU, PPP_MTU, PPP_AUTH_PROTOCOLS,
    PPP_AUTH_TIMEOUT, PPP_IPv4_ENABLED, PPP_DO_REQUEST_STATIC_IPv4_ADDRESS,
    PPP_STATIC_IPv4_ADDRESS, PPP_IPv6_ENABLED, DNS_DO_REQUEST_ADDRESS,
    DNS_DO_USE_CUSTOM_SERVER, DNS_CUSTOM_ADDRESS, ROUTE_DO_ADD_DEFAULT_ROUTE,
    ROUTE_DO_ROUTE_PRIVATE_ADDRESSES, ROUTE_DO_ADD_CUSTOM_ROUTES, ROUTE_CUSTOM_ROUTES,
    ROUTE_DO_ENABLE_APP_BASED_RULE, ROUTE_APP_LIST_TYPE, ROUTE_SELECTED_APPS,
    RECONNECTION_ENABLED, RECONNECTION_LIFE, HOME_STATUS
}

internal const val LIST_TYPE_ALLOWED = "Allowed Apps"
internal const val AUTH_PROTOCOl_PAP = "PAP"
internal const val AUTH_PROTOCOL_MSCHAPv2 = "MSCHAPv2"
internal const val AUTH_PROTOCOL_EAP_MSCHAPv2 = "EAP-MSCHAPv2"
internal const val DEFAULT_MRU = 1500
internal const val DEFAULT_MTU = 1500
internal const val MIN_MRU = 576
internal const val MAX_MRU = 1500
internal const val MIN_MTU = 576
internal const val MAX_MTU = 1500
internal const val TEMP_KEY_HEADER = "_"

internal fun assertAlways(value: Boolean) { check(value) }
internal class ParsingDataUnitException : Exception("Failed to parse data unit")

internal fun getStringPrefValue(key: OscPrefKey, prefs: SharedPreferences): String = when (key) {
    OscPrefKey.HOME_HOSTNAME -> prefs.getString("sstp_host", "")
    OscPrefKey.HOME_USERNAME -> prefs.getString("sstp_user", "vpn")
    OscPrefKey.HOME_PASSWORD -> prefs.getString("sstp_password", "vpn")
    OscPrefKey.SSL_VERSION -> "DEFAULT"
    OscPrefKey.SSL_CUSTOM_SNI, OscPrefKey.PROXY_HOSTNAME, OscPrefKey.PROXY_USERNAME,
    OscPrefKey.PROXY_PASSWORD, OscPrefKey.PPP_STATIC_IPv4_ADDRESS,
    OscPrefKey.ROUTE_CUSTOM_ROUTES, OscPrefKey.HOME_STATUS -> ""
    OscPrefKey.DNS_CUSTOM_ADDRESS -> "1.1.1.1"
    OscPrefKey.ROUTE_APP_LIST_TYPE -> LIST_TYPE_ALLOWED
    else -> ""
} ?: ""

internal fun getIntPrefValue(key: OscPrefKey, prefs: SharedPreferences): Int = when (key) {
    OscPrefKey.SSL_PORT -> prefs.getInt("sstp_port", 443)
    OscPrefKey.PROXY_PORT -> 8080
    OscPrefKey.PPP_MRU, OscPrefKey.PPP_MTU -> 1500
    OscPrefKey.PPP_AUTH_TIMEOUT -> 15
    OscPrefKey.RECONNECTION_LIFE -> 0
    else -> 0
}

internal fun getBooleanPrefValue(key: OscPrefKey, prefs: SharedPreferences): Boolean = when (key) {
    OscPrefKey.SSL_DO_VERIFY -> true
    OscPrefKey.PPP_IPv4_ENABLED, OscPrefKey.PPP_IPv6_ENABLED,
    OscPrefKey.DNS_DO_REQUEST_ADDRESS, OscPrefKey.ROUTE_DO_ADD_DEFAULT_ROUTE -> true
    else -> false
}

internal fun getSetPrefValue(key: OscPrefKey, prefs: SharedPreferences): Set<String> = setOf(AUTH_PROTOCOl_PAP, AUTH_PROTOCOL_MSCHAPv2)
internal fun getURIPrefValue(key: OscPrefKey, prefs: SharedPreferences): Uri? = null
internal fun setStringPrefValue(value: String, key: OscPrefKey, prefs: SharedPreferences) = Unit
internal fun resetReconnectionLife(prefs: SharedPreferences) = Unit
internal data class AppString(val packageName: String, val label: String)
