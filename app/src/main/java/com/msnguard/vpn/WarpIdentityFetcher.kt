package com.msnguard.vpn

import android.content.Context
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Manual WARP identity fetcher for Warp Setting — ECH path only.
 *
 * Runs the bundled engine (libaether.so) as a side process on
 * 127.0.0.1:1839 so the registration takes the same ECH-camouflaged
 * route a normal WARP connect would. This fixes filtered carriers
 * where a plain HttpURLConnection POST to api.cloudflareclient.com
 * times out, while the engine's BoringSSL + ECH stack reaches it.
 *
 * Scope is strictly Warp Setting: it never starts the main tunnel,
 * never touches SHARD/Tor/Psiphon/WireGuard/WoW/Masque connect flow,
 * and only writes the identity files (aether.toml etc) the core
 * later loads. See sibling WarpKeyFetcher pattern for the file
 * layout and the backup/restore that keeps a previous identity safe
 * on failure/timeout/cancel.
 */
object WarpIdentityFetcher {

    private const val TAG = "WarpIdentity"
    private const val BIND = "127.0.0.1:1839"
    private const val TIMEOUT_MS = 240_000L
    private const val POLL_MS = 400L
    private const val BACKUP_SUFFIX = ".warp-bak"

    private const val PRIMARY_WG = "aether.toml"
    private const val SECONDARY_WG = "aether-secondary.toml"
    private const val PRIMARY_MASQUE = "aether-masque.toml"
    private const val SECONDARY_MASQUE = "aether-masque-secondary.toml"
    private val ALL_FILES = listOf(PRIMARY_WG, SECONDARY_WG, PRIMARY_MASQUE, SECONDARY_MASQUE)

    private const val ECH_DOMAIN = "cloudflare-ech.com"
    private const val ECH_DNS = "https://1.1.1.1/dns-query"

    fun canRun(): Boolean = !NativeCore.isRunning()

    fun fetch(context: Context, protocol: String): Boolean {
        val dir = context.filesDir
        val bin = File(context.applicationInfo.nativeLibraryDir, "libaether.so")
        if (!bin.exists()) {
            Log.e(TAG, "engine binary missing: ${bin.absolutePath}")
            ConnectionLog.record("Warp Identity: engine binary missing")
            return false
        }
        if (NativeCore.isRunning()) {
            Log.w(TAG, "tunnel is running — disconnect before fetching identity")
            ConnectionLog.record("Warp Identity: tunnel is running — disconnect first")
            return false
        }

        val norm = protocol.lowercase()
        val masque = norm in setOf("masque", "mim", "masque-in-masque", "masque over masque")
        val targets = identityFiles(dir, norm)
        if (targets.isEmpty()) {
            Log.w(TAG, "unknown protocol $protocol")
            return false
        }

        recover(dir)

        val moved = mutableListOf<File>()
        for (file in targets) {
            if (!file.exists()) continue
            val bak = backupOf(file)
            bak.delete()
            if (!file.renameTo(bak)) {
                Log.e(TAG, "could not set ${file.name} aside")
                ConnectionLog.record("Warp Identity: could not set ${file.name} aside")
                restore(moved)
                return false
            }
            moved += file
        }

        var process: Process? = null
        var ok = false
        try {
            val args = argsFor(norm)
            val cmd = buildList {
                add(bin.absolutePath)
                addAll(args)
            }
            val env = buildEnv(context, norm)
            Log.i(TAG, "requesting fresh $protocol identity via ECH (bind $BIND) args=$args")
            ConnectionLog.record("Warp Identity: requesting $protocol via ECH")

            val builder = ProcessBuilder(cmd).directory(dir).redirectErrorStream(true)
            builder.environment().apply {
                putAll(env)
                put("AETHER_LOG_LEVEL", "info")
                put("HOME", dir.absolutePath)
                put("TMPDIR", dir.absolutePath)
            }
            val proc = builder.start()
            process = proc
            drain(proc)

            val deadline = SystemClock.elapsedRealtime() + TIMEOUT_MS
            while (true) {
                if (targets.all { complete(it, masque) }) {
                    ok = true
                    break
                }
                if (!proc.isAlive) {
                    ok = targets.all { complete(it, masque) }
                    break
                }
                if (SystemClock.elapsedRealtime() >= deadline) {
                    Log.w(TAG, "Warp identity request timed out after ${TIMEOUT_MS}ms")
                    ConnectionLog.record("Warp Identity: timed out after ${TIMEOUT_MS / 1000}s")
                    break
                }
                try { Thread.sleep(POLL_MS) } catch (_: InterruptedException) { Thread.currentThread().interrupt(); break }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Warp identity fetcher crashed: ${e.message}")
            ConnectionLog.record("Warp Identity: crashed — ${e.message}")
        } finally {
            process?.let { stop(it) }
            if (ok) {
                moved.forEach { backupOf(it).delete() }
                Log.i(TAG, "new $protocol identity saved via ECH")
                ConnectionLog.record("Warp Identity: $protocol saved")
            } else {
                restore(moved)
                Log.w(TAG, "$protocol Warp identity failed — previous identity kept")
                ConnectionLog.record("Warp Identity: $protocol failed — previous kept")
            }
        }
        return ok
    }

    private fun argsFor(norm: String): List<String> {
        val protoFlag = when (norm) {
            "masque" -> "--masque"
            "mim", "masque-in-masque", "masque over masque" -> "--mim"
            "wireguard", "wg" -> "--wg"
            "gool", "wow", "warp-in-warp" -> "--gool-classic"
            else -> "--wg"
        }
        return listOf(protoFlag, "--turbo", "--no-quick-reconnect", "--ech", "auto", "--bind", BIND)
    }

    private fun buildEnv(context: Context, norm: String): Map<String, String> {
        val protoForEnv = when (norm) {
            "masque", "mim", "masque-in-masque", "masque over masque" -> "masque"
            "gool", "wow", "warp-in-warp" -> "gool"
            else -> "wireguard"
        }
        val base = CoreConfig.env(context, protocol = protoForEnv)
        val out = LinkedHashMap(base)
        // Force ECH the same way every session would when the switch is on —
        // single DoH resolver, embedded domain, auto key. This is what makes
        // the registration survive the carrier's DPI.
        out["AETHER_ECH"] = "auto"
        out["AETHER_ECH_DOMAIN"] = ECH_DOMAIN
        out["AETHER_ECH_DNS"] = ECH_DNS
        out["AETHER_SCAN"] = "turbo"
        out["AETHER_QUICK_RECONNECT"] = "0"
        out.remove("AETHER_UPSTREAM")
        // Consumer WARP only: a Zero Trust team would make the file land under
        // aether-team-*.toml which this fetcher does not watch.
        out.remove("AETHER_TEAM")
        out.remove("AETHER_ACCESS_CLIENT_ID")
        out.remove("AETHER_ACCESS_CLIENT_SECRET")
        out.remove("AETHER_ACCESS_TOKEN")
        out.remove("AETHER_ACCESS_EMAIL")
        return out
    }

    private fun identityFiles(dir: File, norm: String): List<File> = when (norm) {
        "wireguard", "wg" -> listOf(PRIMARY_WG)
        "gool", "wow", "warp-in-warp" -> listOf(PRIMARY_WG, SECONDARY_WG)
        "masque" -> listOf(PRIMARY_MASQUE)
        "mim", "masque-in-masque", "masque over masque" -> listOf(PRIMARY_MASQUE, SECONDARY_MASQUE)
        else -> emptyList()
    }.map { File(dir, it) }

    private fun backupOf(file: File): File = File(file.parentFile, file.name + BACKUP_SUFFIX)

    private fun restore(moved: List<File>) {
        for (file in moved) {
            val bak = backupOf(file)
            if (!bak.exists()) continue
            file.delete()
            if (!bak.renameTo(file)) Log.w(TAG, "could not restore ${file.name}")
        }
    }

    private fun recover(dir: File) {
        for (name in ALL_FILES) {
            val file = File(dir, name)
            val bak = backupOf(file)
            if (!bak.exists()) continue
            if (complete(file, name.contains("masque"))) bak.delete()
            else { file.delete(); bak.renameTo(file) }
        }
    }

    private fun complete(file: File, masque: Boolean): Boolean {
        val text = runCatching { file.readText() }.getOrNull() ?: return false
        if (!hasValue(text, "device_id")) return false
        if (!hasValue(text, "wg_private_key") || !hasValue(text, "wg_peer_public_key")) return false
        return !masque || (hasValue(text, "cert_pem") && hasValue(text, "key_pem"))
    }

    private fun hasValue(text: String, key: String): Boolean {
        val m = Regex("""(?m)^\s*${Regex.escape(key)}\s*=\s*(.+)$""").find(text) ?: return false
        val v = m.groupValues[1].trim()
        return v.isNotEmpty() && v != "\"\"" && v != "''"
    }

    private fun drain(process: Process) {
        Thread({
            runCatching { process.inputStream.bufferedReader().useLines { lines -> lines.forEach { Log.d(TAG, it) } } }
        }, "warp-identity-drain").apply { isDaemon = true }.start()
    }

    private fun stop(process: Process) {
        runCatching {
            process.destroy()
            if (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
                process.destroyForcibly()
                process.waitFor(1_000, TimeUnit.MILLISECONDS)
            }
        }
    }
}
