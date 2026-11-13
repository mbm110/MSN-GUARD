package com.msnguard.vpn.foxy

import com.msnguard.vpn.Strings
import android.annotation.SuppressLint
import android.app.Activity
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.ProgressBar
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.view.WindowManager
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.lang.ref.WeakReference

/** Firefox Accounts browser flow used by current Foxy releases. */
object FoxyBrowserLogin {
    private const val CHANNEL_ID = "account_updates"
    private const val CMD_FXA_STATUS = "fxaccounts:fxa_status"
    private const val CMD_CAN_LINK_ACCOUNT = "fxaccounts:can_link_account"
    private const val CMD_LOGIN = "fxaccounts:login"
    private val tokenPattern = Regex("^[0-9a-fA-F]{64}$")
    private val allowedHost = Regex("^(accounts|api|oauth)\\.firefox\\.com$|^([a-z0-9-]+\\.)*mozilla\\.org$")

    private var backAction: (() -> Unit)? = null
    private var closeAction: (() -> Unit)? = null

    fun handleBack(): Boolean {
        val action = backAction ?: return false
        action()
        return true
    }

    fun close() { closeAction?.invoke() }

    @SuppressLint("SetJavaScriptEnabled")
    fun show(activity: Activity, onResult: (Result<Unit>) -> Unit) {
        if (backAction != null) return
        FoxyRemoteConfig.init(activity.applicationContext)
        FoxyRemoteConfig.triggerRefresh()
        val host = activity.findViewById<ViewGroup>(android.R.id.content)
        val oldSoftInputMode = activity.window.attributes.softInputMode
        val density = activity.resources.displayMetrics.density
        val page = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(if (com.msnguard.vpn.AppAppearance.isNight(activity)) 0xFF161622.toInt() else 0xFFF7F8FC.toInt())
            isClickable = true
        }
        val web = WebView(activity).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.loadWithOverviewMode = true
            settings.useWideViewPort = true
            settings.setSupportZoom(false)
            settings.builtInZoomControls = false
            settings.javaScriptCanOpenWindowsAutomatically = false
            settings.userAgentString = FirefoxAccountHeaders.browserUserAgent
            isFocusable = true
            isFocusableInTouchMode = true
            CookieManager.getInstance().setAcceptCookie(true)
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
        }
        val loginScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        var completing = false
        var finished = false
        var notifying = true
        fun finish(result: Result<Unit>) {
            if (finished) return
            finished = true
            loginScope.cancel()
            backAction = null
            closeAction = null
            activity.window.setSoftInputMode(oldSoftInputMode)
            host.removeView(page)
            runCatching { CookieManager.getInstance().flush() }
            web.stopLoading()
            web.removeJavascriptInterface("foxyWebChannel")
            page.removeView(web)
            web.destroy()
            if (notifying && !activity.isDestroyed && !activity.isFinishing) onResult(result)
        }
        val repository = FxaAuthRepository(FxoTokenStore(activity.applicationContext))
        backAction = {
            if (web.canGoBack()) web.goBack()
            else finish(Result.failure(IllegalStateException("Sign-in cancelled")))
        }
        closeAction = {
            notifying = false
            finish(Result.failure(IllegalStateException("Sign-in cancelled")))
        }
        val header = TextView(activity).apply {
            text = "‹  " + Strings.t("Sign in with Firefox")
            textSize = 18f
            setTextColor(if (com.msnguard.vpn.AppAppearance.isNight(activity)) 0xFFF5F5FA.toInt() else 0xFF202034.toInt())
            setPadding((16 * density).toInt(), (16 * density).toInt(), (16 * density).toInt(), (16 * density).toInt())
            setOnClickListener { handleBack() }
        }
        val progress = ProgressBar(activity, null, android.R.attr.progressBarStyleHorizontal).apply { max = 100 }
        page.addView(header, LinearLayout.LayoutParams(-1, -2))
        page.addView(progress, LinearLayout.LayoutParams(-1, (3 * density).toInt()))
        page.addView(web, LinearLayout.LayoutParams(-1, 0, 1f))
        lateinit var bridge: WebChannelBridge
        bridge = WebChannelBridge(
            web,
            onSessionToken = { token ->
                if (!finished && !completing) {
                    completing = true
                    loginScope.launch {
                        val result = repository.completeBrowserLogin(token)
                        completing = false
                        if (!finished) {
                            if (result.isSuccess) finish(result)
                            else {
                                bridge.retrySessionToken()
                                android.widget.Toast.makeText(activity,
                                    result.exceptionOrNull()?.message ?: "Sign-in failed. Please try again.",
                                    android.widget.Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            },
        )
        web.addJavascriptInterface(bridge, "foxyWebChannel")
        web.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val scheme = request.url.scheme?.lowercase().orEmpty()
                if (scheme != "http" && scheme != "https") return false
                val host = request.url.host?.lowercase().orEmpty()
                if (allowedHost.matches(host)) return false
                runCatching { view.context.startActivity(Intent(Intent.ACTION_VIEW, request.url)) }
                return true
            }

            override fun onPageStarted(view: WebView, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                runCatching { view.evaluateJavascript(HOOK, null) }
            }

            override fun onPageFinished(view: WebView, url: String?) {
                super.onPageFinished(view, url)
                runCatching {
                    CookieManager.getInstance().flush()
                    FoxyControlPlaneHttp.cookieJar.syncFromWebView()
                    view.evaluateJavascript(HOOK, null)
                }
            }
        }
        web.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                progress.progress = newProgress
                progress.visibility = if (newProgress < 100) View.VISIBLE else View.GONE
            }
        }
        page.setOnApplyWindowInsetsListener { _, insets ->
            val bottom = if (Build.VERSION.SDK_INT >= 30) {
                insets.getInsets(android.view.WindowInsets.Type.ime() or android.view.WindowInsets.Type.systemBars()).bottom
            } else insets.systemWindowInsetBottom
            page.setPadding(insets.systemWindowInsetLeft, insets.systemWindowInsetTop,
                insets.systemWindowInsetRight, bottom)
            insets
        }
        activity.window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        host.addView(page, ViewGroup.LayoutParams(-1, -1))
        page.requestApplyInsets()
        web.loadUrl(repository.browserLoginUrl())
        web.requestFocus(View.FOCUS_DOWN)
    }

    private class WebChannelBridge(
        webView: WebView,
        private val onSessionToken: (String) -> Unit,
    ) {
        private val webViewRef = WeakReference(webView)
        @Volatile private var pendingSessionToken: String? = null
        @Volatile private var dispatchedSessionToken: String? = null

        fun retrySessionToken() { dispatchedSessionToken = null }

        @JavascriptInterface
        fun onMessage(payload: String) = onMessage(payload, "https://accounts.firefox.com")

        @JavascriptInterface
        fun onMessage(payload: String, originUrl: String) {
            val host = runCatching { Uri.parse(originUrl).host?.lowercase() }.getOrNull().orEmpty()
            if (!FoxyBrowserLogin.allowedHost.matches(host)) return
            val envelope = runCatching { JSONObject(payload) }.getOrNull() ?: return
            val channelId = envelope.optString("id").ifBlank { CHANNEL_ID }
            val message = envelope.optJSONObject("message") ?: return
            val command = message.optString("command")
            val data = message.optJSONObject("data") ?: JSONObject()
            val messageId = message.optString("messageId")
            when (command) {
                CMD_FXA_STATUS -> reply(channelId, messageId, command, "{\"capabilities\":{},\"signedInUser\":null}")
                CMD_CAN_LINK_ACCOUNT -> reply(channelId, messageId, command, "{\"ok\":true}")
                CMD_LOGIN, "fxaccounts:oauth_login" -> {
                    val token = data.optString("sessionToken").ifBlank { data.optString("token") }.trim()
                    if (tokenPattern.matches(token)) {
                        pendingSessionToken = token
                        val verified = !data.has("verified") || data.optBoolean("verified", true)
                        if (verified && data.optString("verificationReason").isBlank()) notifySessionToken(token)
                    }
                    if (messageId.isNotBlank()) reply(channelId, messageId, command, "{\"ok\":true}")
                }
                else -> {
                    if (command.contains("verified", ignoreCase = true)) {
                        val token = data.optString("sessionToken").ifBlank { data.optString("token") }
                            .ifBlank { pendingSessionToken.orEmpty() }.trim()
                        if (tokenPattern.matches(token)) notifySessionToken(token)
                    }
                    if (messageId.isNotBlank()) reply(channelId, messageId, command, "{\"ok\":true}")
                }
            }
        }

        @JavascriptInterface
        fun onSessionVerified() = pendingSessionToken?.let { notifySessionToken(it) }

        private fun notifySessionToken(token: String) {
            if (!tokenPattern.matches(token) || token == dispatchedSessionToken) return
            dispatchedSessionToken = token
            pendingSessionToken = token
            runCatching { CookieManager.getInstance().flush() }
            webViewRef.get()?.post { onSessionToken(token) } ?: onSessionToken(token)
        }

        private fun reply(channelId: String, messageId: String, command: String, data: String) {
            if (messageId.isBlank()) return
            val view = webViewRef.get() ?: return
            val script = "window.__foxyReply && window.__foxyReply(" +
                "${JSONObject.quote(channelId)},${JSONObject.quote(messageId)}," +
                "${JSONObject.quote(command)},$data);"
            view.post { runCatching { view.evaluateJavascript(script, null) } }
        }
    }

    private val HOOK = """
        (function() {
          if (window.__foxyChannelHooked) return;
          window.__foxyChannelHooked = true;
          var send = function(o) {
            try {
              var host = window.location.hostname;
              if (host !== 'accounts.firefox.com' && !host.endsWith('.firefox.com')) return;
              var payload = typeof o === 'string' ? o : JSON.stringify(o);
              foxyWebChannel.onMessage(payload, window.location.href);
            } catch (e) {}
          };
          var onChannel = function(e) {
            var d = e.detail;
            if (typeof d === 'string') { try { d = JSON.parse(d); } catch (e) { return; } }
            if (d && d.message) send(d);
          };
          window.addEventListener('WebChannelMessageToChrome', onChannel);
          document.addEventListener('WebChannelMessageToChrome', onChannel);
          window.__foxyReply = function(id, messageId, command, data) {
            var detail = { id: id, message: { messageId: messageId, command: command, data: data } };
            window.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail }));
            document.dispatchEvent(new CustomEvent('WebChannelMessageToContent', { detail: detail }));
          };
        })();
    """.trimIndent()
}
