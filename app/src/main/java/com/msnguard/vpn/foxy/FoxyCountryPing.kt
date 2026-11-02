package com.msnguard.vpn.foxy

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

/** Measures the user's direct TCP latency to Foxy's candidate edge servers. */
object FoxyCountryPing {
    private const val TIMEOUT_MS = 1_500
    private const val MAX_COUNTRIES_IN_FLIGHT = 8

    suspend fun measure(countries: List<VpnCountry>): List<VpnCountry> = withContext(Dispatchers.IO) {
        coroutineScope {
            val permits = Semaphore(MAX_COUNTRIES_IN_FLIGHT)
            countries.map { country ->
                async {
                    permits.withPermit { country.copy(pingMs = pingCountry(country)) }
                }
            }.awaitAll()
        }
    }

    private fun pingCountry(country: VpnCountry): Long {
        val targets = country.cities.asSequence()
            .flatMap { it.servers.asSequence() }
            .filter { !it.quarantined && it.hostname.isNotBlank() && it.port in 1..65535 }
            .map { it.hostname to it.port }
            .distinct()
            .take(3)
            .toList()
        var best = Long.MAX_VALUE
        for ((host, port) in targets) {
            val started = System.nanoTime()
            runCatching {
                Socket().use { socket ->
                    socket.tcpNoDelay = true
                    socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
                }
            }.onSuccess {
                best = minOf(best, (System.nanoTime() - started) / 1_000_000L)
            }
        }
        return if (best == Long.MAX_VALUE) -1L else best
    }
}
