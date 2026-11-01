package com.msnguard.vpn.foxy

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.graphics.Color
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import org.json.JSONObject

/** Firefox Accounts browser flow used by current Foxy releases. */
object FoxyBrowserLogin {
    private val tokenPattern = Regex("^[0-9a-fA-F]{64}$")

    @SuppressLint("SetJavaScriptEnabled")
    fun show(activity: Activity, onResult: (Result<Unit>) -> Unit) {
        val web = WebView(activity).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            settings.userAgentString =
                "Mozilla/5.0 (Android ${android.os.Build.VERSION.RELEASE}; Mobile; rv:135.0) Gecko/135.0 Firefox/135.0"
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
        val dialog = AlertDialog.Builder(activity)
            .setTitle("Sign in with Firefox")
            .setView(web)
            .setNegativeButton("Cancel") { _, _ -> finish(Result.failure(IllegalStateException("Sign-in cancelled"))) }
            .create()
        web.addJavascriptInterface(object {
            @JavascriptInterface
            fun onMessage(payload: String) {
                val root = runCatching { JSONObject(payload) }.getOrNull()
                val message = root?.optJSONObject("message")
                val command = message?.optString("command").orEmpty()
                val messageId = message?.optString("messageId").orEmpty()
                if (messageId.isNotBlank() && (command == "fxaccounts:fxa_status" || command == "fxaccounts:can_link_account")) {
                    web.post {
                        web.evaluateJavascript("window.__msnFoxyReply && window.__msnFoxyReply(" +
                            JSONObject.quote(messageId) + "," + JSONObject.quote(command) + "," +
                            JSONObject.quote(if (command == "fxaccounts:fxa_status") "{\\\"capabilities\\\":{},\\\"signedInUser\\\":null}" else "{\\\"ok\\\":true}") + ");", null)
                    }
                }
                val token = runCatching {
                    val root = JSONObject(payload)
                    val message = root.optJSONObject("message") ?: root
                    val data = message.optJSONObject("data") ?: message
                    data.optString("sessionToken").ifBlank { data.optString("token") }
                }.getOrNull().orEmpty()
                if (tokenPattern.matches(token)) {
                    Thread {
                        val result = runCatching {
                            FxaAuthRepository(FxoTokenStore(activity.applicationContext))
                                .completeBrowserSession(token).getOrThrow()
                        }
                        activity.runOnUiThread { finish(result) }
                    }.start()
                }
            }
        }, "foxyWebChannel")
        web.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView, url: String?) {
                super.onPageFinished(view, url)
                view.evaluateJavascript(HOOK, null)
                FoxyControlPlaneHttp.cookieJar.syncFromWebView()
            }
        }
        web.webChromeClient = WebChromeClient()
        dialog.setOnDismissListener {
            if (!finished) finish(Result.failure(IllegalStateException("Sign-in cancelled")))
        }
        dialog.setOnShowListener { web.loadUrl(FxaAuthRepository(FxoTokenStore(activity.applicationContext)).browserLoginUrl()) }
        dialog.show()
        dialog.window?.setLayout((activity.resources.displayMetrics.widthPixels * .96).toInt(), (activity.resources.displayMetrics.heightPixels * .90).toInt())
    }

    private val HOOK = """
        (function(){
          if(window.__msnFoxyHook)return; window.__msnFoxyHook=true;
          function send(x){try{foxyWebChannel.onMessage(typeof x==='string'?x:JSON.stringify(x));}catch(e){}}
          window.addEventListener('WebChannelMessageToChrome',function(e){send(e.detail)});
          document.addEventListener('WebChannelMessageToChrome',function(e){send(e.detail)});
          window.__msnFoxyReply=function(id,messageId,command,dataJson){
            try { window.dispatchEvent(new CustomEvent('WebChannelMessageToContent',{detail:JSON.stringify({id:id,message:{messageId:messageId,command:command,data:JSON.parse(dataJson)}})})); } catch(e) {}
          };
          var oldPush=history.pushState; if(oldPush) history.pushState=function(){var r=oldPush.apply(this,arguments);return r;};
        })();
    """.trimIndent()
}
