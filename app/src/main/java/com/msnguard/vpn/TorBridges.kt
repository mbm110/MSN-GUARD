package com.msnguard.vpn

/**
 * Bridge lines Tor is given for each transport.
 *
 * These are **configuration values, not code**: the public built-in bridges that
 * Tor Browser itself ships, plus the CDN77 broker/front settings that are known
 * to be reachable from Iran. Reproducing them here carries no licence weight.
 *
 * Two things to know before editing:
 *
 *  - Public bridges are the first to be blocked, precisely because they are
 *    public. When a transport stops working for many users, these lines are the
 *    first suspect, and the fix is a fresh set — not a code change.
 *  - The `192.0.2.x` addresses are from the documentation range and are **not
 *    mistakes**. Tor's config parser requires an address in every `Bridge` line,
 *    but for meek and snowflake the transport reaches its rendezvous by URL or
 *    broker and never dials that address. Replacing them with something
 *    "real-looking" would make Tor try to connect there.
 */
internal object TorBridges {

    /**
     * obfs4 bridges.
     *
     * `iat-mode=1` on the last two adds inter-arrival-time obfuscation: better
     * against timing analysis, measurably slower. Keeping both kinds in the list
     * is deliberate — on a network that fingerprints packet timing the slower
     * ones are the only ones that work.
     */
    val OBFS4 = listOf(
        "obfs4 51.222.13.177:80 5EDAC3B810E12B01F6FD8050D2FD3E277B289A08 cert=2uplIpLQ0q9+0qMFrK5pkaYRDOe460LL9WHBvatgkuRr/SL31wBOEupaMMJ6koRE6Ld0ew iat-mode=0",
        "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0",
        "obfs4 45.145.95.6:27015 C5B7CD6946FF10C5B3E89691A7D3F2C122D2117C cert=TD7PbUO0/0k6xYHMPW3vJxICfkMZNdkRrb63Zhl5j9dW3iRGiCx0A7mPhe5T2EDzQ35+Zw iat-mode=0",
        "obfs4 209.148.46.65:443 74FAD13168806246602538555B5521A0383A1875 cert=ssH+9rP8dG2NLDN2XuFw63hIO/9MNNinLmxQDpVa+7kTOa9/m+tGWT1SmSYpQ9uTBGa6Hw iat-mode=0",
        // 146.57.248.225:22 was here and is gone: the field log shows Tor
        // retrying it nine times in one 60-second attempt, and dialling it from
        // an uncensored VPS returns ECONNREFUSED while the other six accept —
        // the bridge is down, not blocked. A dead entry is worse than a missing
        // one, because Tor spends the rung's budget retrying it.
        "obfs4 212.83.43.95:443 BFE712113A72899AD685764B211FACD30FF52C31 cert=ayq0XzCwhpdysn5o0EyDUbmSOx3X/oTEbzDMvczHOdBJKlvIdHHLJGkZARtT4dcBFArPPg iat-mode=1",
        "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr+S8JTVZo6MPdHnkTwXJPILWADLqfMGoVvhZClMq/Urndyd42BwX9YFJHZnBB3H0XCw iat-mode=1",
    )

    /**
     * meek_lite via CDN77.
     *
     * Labelled "Meek" in the UI rather than "Meek Azure" because the front is
     * CDN77, not Azure. `utls=HelloRandomizedALPN` makes the TLS handshake look
     * like an ordinary randomised browser hello instead of Go's distinctive one.
     */
    val MEEK = listOf(
        "meek_lite 192.0.2.20:80 url=https://1603026938.rsc.cdn77.org front=www.phpmyadmin.net utls=HelloRandomizedALPN",
    )

    /**
     * Snowflake, configured entirely on the bridge line.
     *
     * Unlike SlipNet — which bundles a separate gomobile Snowflake client with
     * the broker settings compiled in — we drive lyrebird's built-in snowflake
     * transport, so every parameter has to be passed here as SOCKS args.
     *
     * The STUN list is deliberately Google-free: `stun.l.google.com` is the
     * obvious one to block and is unreachable from Iran. Ports 443 and 10000
     * appear because 3478 is the well-known STUN port and the first blocked.
     */
    val SNOWFLAKE = listOf(
        "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72" +
            " url=https://1098762253.rsc.cdn77.org/" +
            " front=www.cdn77.com" +
            " ice=stun:stun.antisip.com:3478,stun:stun.epygi.com:3478," +
            "stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478," +
            "stun:stun.mixvoip.com:3478,stun:stun.nextcloud.com:3478," +
            "stun:stun.bethesda.net:3478,stun:stun.nextcloud.com:443," +
            "stun:stun.sipgate.net:3478,stun:stun.sipgate.net:10000," +
            "stun:stun.sonetel.com:3478,stun:stun.voipia.net:3478" +
            " utls-imitate=hellorandomizedalpn",
    )
}
