package studio.cluvex.aethery

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.widget.LinearLayout
import android.widget.ProgressBar
import androidx.core.content.FileProvider
import androidx.appcompat.app.AlertDialog
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.Executors

class AppUpdater(private val activity: Activity) {
    private val worker = Executors.newSingleThreadExecutor()
    private var pendingApk: File? = null
    private var progressDialog: AlertDialog? = null
    private var progressBar: ProgressBar? = null
    private var busy = false

    fun checkForUpdate() {
        if (busy) return
        busy = true
        showProgress("Checking for updates", indeterminate = true)
        worker.execute {
            val result = runCatching(::latestRelease)
            activity.runOnUiThread {
                dismissProgress()
                busy = false
                result.onFailure { showMessage("Update check failed", it.message ?: "Try again later") }
                    .onSuccess { release ->
                        when {
                            release == null -> showMessage("No update available", "No compatible release was found")
                            !isNewer(release.version, appVersion()) -> showMessage("You're up to date", "Aethery ${appVersion()} is installed")
                            else -> confirmDownload(release)
                        }
                    }
            }
        }
    }

    fun resumeInstallIfPermitted() {
        val apk = pendingApk ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !activity.packageManager.canRequestPackageInstalls()) return
        pendingApk = null
        install(apk)
    }

    private fun confirmDownload(release: Release) {
        dialogBuilder()
            .setTitle("Update available")
            .setMessage("Aethery ${release.version} is ready to download.")
            .setNegativeButton("Not now", null)
            .setPositiveButton("Download") { _, _ -> download(release) }
            .show()
    }

    private fun download(release: Release) {
        if (busy) return
        busy = true
        showProgress("Downloading ${release.version}", indeterminate = false)
        worker.execute {
            val result = runCatching { downloadApk(release) }
            activity.runOnUiThread {
                dismissProgress()
                busy = false
                result.onFailure { showMessage("Download failed", it.message ?: "Try again later") }
                    .onSuccess { requestInstall(it) }
            }
        }
    }

    private fun requestInstall(apk: File) {
        pendingApk = apk
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !activity.packageManager.canRequestPackageInstalls()) {
            dialogBuilder()
                .setTitle("Allow update installs")
                .setMessage("Android needs permission to install the downloaded Aethery update.")
                .setNegativeButton("Cancel") { _, _ -> pendingApk = null }
                .setPositiveButton("Open settings") { _, _ ->
                    activity.startActivity(Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:${activity.packageName}"),
                    ))
                }
                .show()
        } else {
            resumeInstallIfPermitted()
        }
    }

    private fun install(apk: File) {
        val uri = FileProvider.getUriForFile(activity, "${activity.packageName}.fileprovider", apk)
        activity.startActivity(Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION))
    }

    private fun latestRelease(): Release? {
        val connection = (URL(RELEASE_URL).openConnection() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 20_000
            setRequestProperty("Accept", "application/vnd.github+json")
            setRequestProperty("User-Agent", "Aethery-Android")
        }
        try {
            if (connection.responseCode == HttpURLConnection.HTTP_NOT_FOUND) return null
            check(connection.responseCode == HttpURLConnection.HTTP_OK) { "GitHub returned ${connection.responseCode}" }
            val json = JSONObject(connection.inputStream.bufferedReader().use { reader -> reader.readText() })
            val version = json.getString("tag_name").removePrefix("v")
            val assets = json.getJSONArray("assets")
            val apk = Build.SUPPORTED_ABIS.asSequence()
                .mapNotNull { abi -> assetForAbi(assets, abi) }
                .firstOrNull()
                ?: return null
            return Release(version, apk.first, apk.second)
        } finally {
            connection.disconnect()
        }
    }

    private fun assetForAbi(assets: org.json.JSONArray, abi: String): Pair<String, String>? {
        val token = when (abi) {
            "arm64-v8a" -> "arm64-v8a"
            "armeabi-v7a" -> "armeabi-v7a"
            else -> abi
        }
        for (index in 0 until assets.length()) {
            val asset = assets.getJSONObject(index)
            val name = asset.getString("name")
            if (name.endsWith(".apk") && name.contains(token, ignoreCase = true)) {
                return name to asset.getString("browser_download_url")
            }
        }
        return null
    }

    private fun downloadApk(release: Release): File {
        val target = File(activity.cacheDir, "updates/${release.assetName}").apply {
            parentFile?.mkdirs()
            delete()
        }
        val connection = (URL(release.downloadUrl).openConnection() as HttpURLConnection).apply {
            connectTimeout = 10_000
            readTimeout = 30_000
            setRequestProperty("User-Agent", "Aethery-Android")
        }
        try {
            check(connection.responseCode == HttpURLConnection.HTTP_OK) { "Download returned ${connection.responseCode}" }
            val total = connection.contentLengthLong
            var downloaded = 0L
            connection.inputStream.use { input ->
                target.outputStream().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        downloaded += read
                        if (total > 0) updateProgress((downloaded * 100 / total).toInt())
                    }
                }
            }
        } finally {
            connection.disconnect()
        }
        check(target.length() > 0) { "Downloaded update is empty" }
        return target
    }

    private fun showProgress(title: String, indeterminate: Boolean) {
        val layout = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(8), dp(24), dp(8))
        }
        progressBar = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply {
            isIndeterminate = indeterminate
            max = 100
        }
        layout.addView(progressBar)
        progressDialog = dialogBuilder()
            .setTitle(title)
            .setView(layout)
            .setCancelable(false)
            .create()
            .also { it.show() }
    }

    private fun updateProgress(value: Int) = activity.runOnUiThread {
        progressBar?.progress = value.coerceIn(0, 100)
    }

    private fun dismissProgress() {
        progressDialog?.dismiss()
        progressDialog = null
        progressBar = null
    }

    private fun showMessage(title: String, message: String) {
        dialogBuilder().setTitle(title).setMessage(message).setPositiveButton("OK", null).show()
    }

    private fun dialogBuilder() = MaterialAlertDialogBuilder(activity, R.style.ThemeOverlay_Aethery_AlertDialog)

    private fun appVersion(): String = activity.packageManager
        .getPackageInfo(activity.packageName, 0).versionName ?: "0.0.0"

    private fun dp(value: Int): Int = (value * activity.resources.displayMetrics.density).toInt()

    private data class Release(val version: String, val assetName: String, val downloadUrl: String)

    private companion object {
        const val RELEASE_URL = "https://api.github.com/repos/ZethRise/Aethery/releases/latest"

        fun isNewer(remote: String, local: String): Boolean {
            val remoteParts = remote.split('.', '-', '+').map { it.toIntOrNull() ?: 0 }
            val localParts = local.split('.', '-', '+').map { it.toIntOrNull() ?: 0 }
            for (index in 0 until maxOf(remoteParts.size, localParts.size)) {
                val comparison = remoteParts.getOrElse(index) { 0 }.compareTo(localParts.getOrElse(index) { 0 })
                if (comparison != 0) return comparison > 0
            }
            return false
        }
    }
}
