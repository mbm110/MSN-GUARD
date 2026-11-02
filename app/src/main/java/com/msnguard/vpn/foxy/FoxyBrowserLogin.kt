package com.msnguard.vpn.foxy

import com.msnguard.vpn.Strings
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
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
    private val userAgent =
        "Mozilla/5.0 (Android ${Build.VERSION.RELEASE.ifBlank { "14" }}; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0"

    @SuppressLint("SetJavaScriptEnabled")
    fun show(activity: Activity, onResult: (Result<Unit>) -> Unit) {
        val web = WebView(activity).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.loadWithOverviewMode = true
            settings.useWideViewPort = true
            settings.userAgentString = userAgent
            CookieManager.getInstance().setAcceptCookie(true)
            CookieManager.getInstance().setAcceptThirdPartyCookies(this, true)
        }
        var finished = false
        fun finish(result: Result<Unit>) {
            if (finished) return
            finished = true
            runCatching { CookieManager.getInstance().flush() }
            web.stopLoading()
            web.destroy()
            onResult(result)
        }
        val repository = FxaAuthRepository(FxoTokenStore(activity.applicationContext))
        val dialog = AlertDialog.Builder(activity)
            .setTitle(Strings.t("Sign in with Firefox"))
            .setView(web)
            .setNegativeButton("Cancel") { _, _ ->
                finish(Result.failure(IllegalStateException("Sign-in cancelled")))
            }
            .create()
        val bridge = WebChannelBridge(
            web,
            repository,
            onTokens = { access, refresh, expires ->
                Thread {
                    val result = kotlinx.coroutines.runBlocking {
                        repository.completeBrowserLoginWithTokens(access, refresh, expires)
                    }
                    activity.runOnUiThread { finish(result) }
                }.start()
            },
            onSessionToken = { token ->
                Thread {
                    val result = kotlinx.coroutines.runBlocking {
                        repository.completeBrowserLogin(token)
                    }
                    activity.runOnUiThread { finish(result) }
                }.start()
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
        web.webChromeClient = WebChromeClient()
        dialog.setOnDismissListener {
            if (!finished) finish(Result.failure(IllegalStateException("Sign-in cancelled")))
        }
        dialog.setOnShowListener { web.loadUrl(repository.browserLoginUrl()) }
        dialog.show()
        dialog.window?.setLayout(
            (activity.resources.displayMetrics.widthPixels * .96).toInt(),
            (activity.resources.displayMetrics.heightPixels * .90).toInt(),
        )
    }

    private class WebChannelBridge(
        webView: WebView,
        private val authRepository: FxaAuthRepository,
        private val onTokens: (String, String?, Long) -> Unit,
        private val onSessionToken: (String) -> Unit,
    ) {
        private val webViewRef = WeakReference(webView)
        @Volatile private var pendingSessionToken: String? = null
        @Volatile private var exchangeInProgress = false

        @JavascriptInterface
        fun onMessage(payload: String) = onMessage(payload, "https://accounts.firefox.com")

        @JavascriptInterface
        fun onMessage(payload: String, originUrl: String) {
            val host = runCatching { Uri.parse(originUrl).host?.lowercase() }.getOrNull().orEmpty()
            if (!FoxyBrowserLogin.allowedHost.matches(host)) return
            val message = runCatching { JSONObject(payload).optJSONObject("message") }.getOrNull() ?: return
            val command = message.optString("command")
            val data = message.optJSONObject("data") ?: JSONObject()
            val messageId = message.optString("messageId")
            when (command) {
                CMD_FXA_STATUS -> reply(messageId, command, "{\"capabilities\":{},\"signedInUser\":null}")
                CMD_CAN_LINK_ACCOUNT -> reply(messageId, command, "{\"ok\":true}")
                CMD_LOGIN, "fxaccounts:oauth_login" -> {
                    val token = data.optString("sessionToken").ifBlank { data.optString("token") }.trim()
                    if (tokenPattern.matches(token)) {
                        pendingSessionToken = token
                        val verified = !data.has("verified") || data.optBoolean("verified", true)
                        if (verified && data.optString("verificationReason").isBlank()) notifySessionToken(token)
                    }
                    if (messageId.isNotBlank()) reply(messageId, command, "{\"ok\":true}")
                }
                else -> {
                    if (command.contains("verified", ignoreCase = true)) {
                        val token = data.optString("sessionToken").ifBlank { data.optString("token") }
                            .ifBlank { pendingSessionToken.orEmpty() }.trim()
                        if (tokenPattern.matches(token)) notifySessionToken(token)
                    }
                    if (messageId.isNotBlank()) reply(messageId, command, "{\"ok\":true}")
                }
            }
        }

        @JavascriptInterface
        fun onSessionVerified() = pendingSessionToken?.let { notifySessionToken(it) }

        @JavascriptInterface
        fun onOAuthResult(status: Int, body: String) {
            val token = pendingSessionToken
            if (status in 200..299) {
                runCatching {
                    val json = JSONObject(body)
                    onTokens(json.getString("access_token"), json.optString("refresh_token").ifBlank { null }, json.optLong("expires_in", 0L))
                }.onFailure { token?.let(::fallbackSession) }
            } else token?.let(::fallbackSession)
        }

        @JavascriptInterface
        fun onOAuthError(error: String) {
            FoxyLog.w("BrowserLogin", "in-browser OAuth exchange failed: $error")
            pendingSessionToken?.let(::fallbackSession)
        }

        private fun notifySessionToken(token: String) {
            if (!tokenPattern.matches(token) || exchangeInProgress) return
            pendingSessionToken = token
            exchangeInProgress = true
            runCatching {
                CookieManager.getInstance().flush()
                FoxyControlPlaneHttp.cookieJar.syncFromWebView()
            }
            val hawk = runCatching { authRepository.buildOAuthHawkHeader(token) }.getOrNull()
            val view = webViewRef.get()
            if (hawk == null || view == null) {
                fallbackSession(token)
                return
            }
            val script = """
                (function() {
                  fetch('https://api.accounts.firefox.com/v1/oauth/token', {
                    method: 'POST',
                    headers: {'Authorization': ${JSONObject.quote(hawk.first)}, 'Content-Type': 'application/json'},
                    body: ${JSONObject.quote(hawk.second)}
                  }).then(function(r) { return r.text().then(function(t) {
                    foxyWebChannel.onOAuthResult(r.status, t);
                  }); }).catch(function(e) {
                    foxyWebChannel.onOAuthError(e ? (e.message || '' + e) : 'fetch_failed');
                  });
                })();
            """.trimIndent()
            view.post { runCatching { view.evaluateJavascript(script, null) }.onFailure { fallbackSession(token) } }
        }

        private fun fallbackSession(token: String) {
            exchangeInProgress = false
            webViewRef.get()?.post { onSessionToken(token) } ?: onSessionToken(token)
        }

        private fun reply(messageId: String, command: String, data: String) {
            if (messageId.isBlank()) return
            val view = webViewRef.get() ?: return
            val script = "window.__foxyReply && window.__foxyReply(" +
                "${JSONObject.quote(CHANNEL_ID)},${JSONObject.quote(messageId)}," +
                "${JSONObject.quote(command)},${JSONObject.quote(data)});"
            view.post { runCatching { view.evaluateJavascript(script, null) } }
        }
    }

    private val HOOK = """
        (function() {
          if (window.__foxyChannelHooked) return;
          window.__foxyChannelHooked = true;
          function forward(detail) { try {
            var h=window.location.hostname;
            if(h!=='accounts.firefox.com' && h.indexOf('.firefox.com')===-1)return;
            foxyWebChannel.onMessage(typeof detail==='string'?detail:JSON.stringify(detail),window.location.href);
          } catch(e){} }
          window.addEventListener('WebChannelMessageToChrome',function(e){forward(e.detail);});
          document.addEventListener('WebChannelMessageToChrome',function(e){forward(e.detail);});
          window.__foxyReply=function(i,m,c,d){try{var o={id:i,message:{messageId:m,command:c,data:JSON.parse(d)}};window.dispatchEvent(new CustomEvent('WebChannelMessageToContent',{detail:o}));document.dispatchEvent(new CustomEvent('WebChannelMessageToContent',{detail:JSON.stringify(o)}));}catch(e){}};
          function u(a){return typeof a==='string'?a:(a&&(a.url||a.href))||'';}
          function v(a){var s=u(a).toLowerCase();return s.indexOf('/verify')>=0||s.indexOf('/totp')>=0||s.indexOf('enter_code')>=0||s.indexOf('confirm_')>=0||s.indexOf('success')>=0||s.indexOf('/complete')>=0;}
          if(window.fetch){var f=window.fetch;window.fetch=function(){var a=arguments[0];return f.apply(this,arguments).then(function(r){try{if(r.ok&&v(a))foxyWebChannel.onSessionVerified();}catch(e){}return r;});};}
          if(window.XMLHttpRequest){var xo=XMLHttpRequest.prototype.open,xs=XMLHttpRequest.prototype.send;XMLHttpRequest.prototype.open=function(m,u){this.__foxyUrl=u;return xo.apply(this,arguments);};XMLHttpRequest.prototype.send=function(){this.addEventListener('load',function(){try{if(this.status>=200&&this.status<300&&v(this.__foxyUrl))foxyWebChannel.onSessionVerified();}catch(e){}});return xs.apply(this,arguments);};}
          var p=history.pushState;if(p)history.pushState=function(){var r=p.apply(this,arguments);if(v(location.href))foxyWebChannel.onSessionVerified();return r;};
          var q=history.replaceState;if(q)history.replaceState=function(){var r=q.apply(this,arguments);if(v(location.href))foxyWebChannel.onSessionVerified();return r;};
        })();
    """.trimIndent()
}
