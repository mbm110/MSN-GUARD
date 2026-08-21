package com.msnguard.vpn

import java.net.HttpURLConnection

/**
 * Reachability probe for well-known sites, grouped by what a user actually wants
 * to know: "does the thing I care about work through this tunnel?"
 *
 * Two design decisions worth keeping:
 *
 * 1. **`403`/`451` are reported as SANCTIONED, not as failures.** A site that is
 *    geo-blocking the exit IP answers; a site the censor is blocking does not.
 *    Collapsing both into "failed" hides the single most actionable result —
 *    "your tunnel works, but this service is refusing your exit country", which
 *    is fixed by changing the preferred country, not by reconnecting.
 *
 * 2. **No third-party API.** Every probe is a plain HEAD/GET to the site itself,
 *    so nothing is told about the user beyond the request they were going to make
 *    anyway. Reputation/geo-intelligence services were deliberately not used.
 *
 * Threading: [probe] blocks, so callers run it on a background thread. The list
 * is static data with no Android dependency, which keeps it unit-testable.
 */
object NetMonitor {

    data class Site(val name: String, val host: String)

    data class Category(val title: String, val sites: List<Site>)

    sealed class Result {
        /** Not probed yet. */
        object Idle : Result()
        object Testing : Result()

        /** Answered. [ms] is wall-clock time to first response line. */
        data class Reachable(val ms: Int) : Result()

        /** Answered with 403/451 — reachable, but refusing this exit country. */
        object Sanctioned : Result()

        /** No answer inside the timeout, or a transport-level failure. */
        object Blocked : Result()

        val label: String
            get() = when (this) {
                is Idle -> "—"
                is Testing -> "testing…"
                is Reachable -> "$ms ms"
                is Sanctioned -> "sanctioned"
                is Blocked -> "blocked"
            }
    }

    private val ai = listOf(
        Site("OpenAI", "api.openai.com"),
        Site("ChatGPT", "chatgpt.com"),
        Site("Claude", "claude.ai"),
        Site("Gemini", "gemini.google.com"),
        Site("Perplexity", "www.perplexity.ai"),
        Site("DeepSeek", "www.deepseek.com"),
        Site("Grok", "grok.com"),
        Site("Hugging Face", "huggingface.co"),
        Site("OpenRouter", "openrouter.ai"),
        Site("GitHub Copilot", "copilot.microsoft.com"),
    )

    private val social = listOf(
        Site("Telegram", "core.telegram.org"),
        Site("WhatsApp", "web.whatsapp.com"),
        Site("Instagram", "www.instagram.com"),
        Site("X", "x.com"),
        Site("Facebook", "www.facebook.com"),
        Site("YouTube", "www.youtube.com"),
        Site("Reddit", "www.reddit.com"),
        Site("Discord", "discord.com"),
        Site("TikTok", "www.tiktok.com"),
        Site("LinkedIn", "www.linkedin.com"),
        Site("Signal", "signal.org"),
        Site("Spotify", "open.spotify.com"),
    )

    private val gaming = listOf(
        Site("Steam", "store.steampowered.com"),
        Site("Epic Games", "store.epicgames.com"),
        Site("PlayStation", "www.playstation.com"),
        Site("Xbox", "www.xbox.com"),
        Site("Riot Games", "www.riotgames.com"),
        Site("Battle.net", "us.shop.battle.net"),
        Site("EA", "www.ea.com"),
        Site("Ubisoft", "store.ubisoft.com"),
        Site("Roblox", "www.roblox.com"),
        Site("Twitch", "www.twitch.tv"),
        Site("Supercell", "supercell.com"),
    )

    private val trading = listOf(
        Site("TradingView", "www.tradingview.com"),
        Site("Binance", "www.binance.com"),
        Site("Coinbase", "www.coinbase.com"),
        Site("Bybit", "www.bybit.com"),
        Site("OKX", "www.okx.com"),
        Site("KuCoin", "www.kucoin.com"),
        Site("CoinMarketCap", "coinmarketcap.com"),
        Site("Investing", "www.investing.com"),
        Site("PayPal", "www.paypal.com"),
        Site("Amazon", "www.amazon.com"),
    )

    private val news = listOf(
        Site("BBC", "www.bbc.com"),
        Site("BBC Persian", "www.bbc.com/persian"),
        Site("Iran International", "www.iranintl.com"),
        Site("Radio Farda", "www.radiofarda.com"),
        Site("DW", "www.dw.com"),
        Site("Reuters", "www.reuters.com"),
        Site("Al Jazeera", "www.aljazeera.com"),
        Site("The Guardian", "www.theguardian.com"),
        Site("Euronews", "www.euronews.com"),
    )

    private val iranian = listOf(
        Site("Digikala", "www.digikala.com"),
        Site("Aparat", "www.aparat.com"),
        Site("Divar", "divar.ir"),
        Site("Torob", "torob.com"),
        Site("Filimo", "www.filimo.com"),
        Site("Balad", "balad.ir"),
        Site("Cafe Bazaar", "cafebazaar.ir"),
        Site("Nobitex", "nobitex.ir"),
        Site("Bank Melli", "bmi.ir"),
        Site("Shaparak", "shaparak.ir"),
        Site("Tapsi", "tapsi.ir"),
    )

    /**
     * Category order is deliberate: the two a censorship-circumvention user checks
     * first come first, and Iranian sites come last because those are the ones
     * expected to work *without* a tunnel.
     */
    val categories = listOf(
        Category("AI", ai.sortedBy { it.name.lowercase() }),
        Category("Social & messaging", social.sortedBy { it.name.lowercase() }),
        Category("Gaming", gaming.sortedBy { it.name.lowercase() }),
        Category("Trading & shopping", trading.sortedBy { it.name.lowercase() }),
        Category("News", news.sortedBy { it.name.lowercase() }),
        Category("Iranian services", iranian.sortedBy { it.name.lowercase() }),
    )

    /** Every site across every category, deduplicated by host. */
    val allSites: List<Site> = categories.flatMap { it.sites }.distinctBy { it.host }

    const val TIMEOUT_MS = 6_000

    /**
     * Probes one site. Blocking — call from a background thread.
     *
     * @param open supplies the connection, so the caller decides whether the
     *   request goes through the tunnel's SOCKS listener or direct. This class
     *   deliberately does not know: on the native paths there is no local SOCKS
     *   port at all, and that decision already lives in one place in the activity.
     */
    fun probe(site: Site, open: (String) -> HttpURLConnection): Result {
        val startedAt = System.nanoTime()
        val connection = runCatching { open("https://${site.host}/") }.getOrNull()
            ?: return Result.Blocked
        return try {
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            connection.requestMethod = "GET"
            // Redirects off: a 301 to the same host is already proof the host
            // answered, and following them turns one probe into several requests.
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Android)")
            connection.setRequestProperty("Accept", "*/*")
            val code = connection.responseCode
            val ms = ((System.nanoTime() - startedAt) / 1_000_000).toInt()
            when (code) {
                // 403 Forbidden / 451 Unavailable For Legal Reasons: the site
                // answered and refused. That is a geo/sanction verdict on the exit
                // IP, not a censorship block, and the fix is a different exit
                // country rather than a different tunnel.
                403, 451 -> Result.Sanctioned
                else -> Result.Reachable(ms)
            }
        } catch (_: Exception) {
            Result.Blocked
        } finally {
            runCatching { connection.disconnect() }
        }
    }
}
