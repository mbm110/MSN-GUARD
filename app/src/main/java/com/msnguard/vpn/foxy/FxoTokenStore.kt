package com.msnguard.vpn.foxy

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.msnguard.vpn.foxy.RuntimeAuth

private const val TAG = "TokenStore"

class FxoTokenStore(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "foxy_vpn_tokens",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )

    class StorageException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

    fun saveAuth(auth: RuntimeAuth) {
        try {
            val nextEpoch = prefs.getLong(KEY_SESSION_EPOCH, 0L) + 1L
            check(prefs.edit()
                .putString(KEY_ACCESS_TOKEN, auth.accessToken)
                .putString(KEY_REFRESH_TOKEN, auth.refreshToken)
                .putLong(KEY_EXPIRES_AT, auth.expiresAtEpochSeconds)
                .putLong(KEY_SESSION_EPOCH, nextEpoch)
                .commit()) { "Could not persist Firefox session" }
        } catch (failure: Exception) {
            FoxyLog.e(TAG, "could not persist the Firefox session", failure)
            throw StorageException("Could not persist Firefox session", failure)
        }
    }

    fun sessionEpoch(): Long = runCatching { prefs.getLong(KEY_SESSION_EPOCH, 0L) }
        .getOrElse { throw StorageException("Could not read Firefox session epoch", it) }

    fun loadAuth(): RuntimeAuth? = runCatching {
        val access = prefs.getString(KEY_ACCESS_TOKEN, null)?.takeIf { it.isNotBlank() } ?: return@runCatching null
        val refresh = prefs.getString(KEY_REFRESH_TOKEN, null)?.takeIf { it.isNotBlank() }
        val expiresAt = prefs.getLong(KEY_EXPIRES_AT, 0L)
        RuntimeAuth(access, refresh, expiresAt)
    }.onFailure {
        FoxyLog.w(TAG, "could not read the stored session", it)
    }.getOrNull()

    fun hasValidAccessToken(): Boolean {
        val auth = loadAuth() ?: return false
        if (auth.expiresAtEpochSeconds <= 0L) return false
        val nowSeconds = System.currentTimeMillis() / 1000
        return auth.expiresAtEpochSeconds - nowSeconds > CLOCK_SKEW_TOLERANCE_SECONDS
    }

    fun hasStoredSession(): Boolean = loadAuth() != null

    fun hasRefreshToken(): Boolean = loadAuth()?.refreshToken != null

    var pendingSessionToken: String?
        get() = prefs.getString(KEY_PENDING_SESSION_TOKEN, null)?.takeIf { it.isNotBlank() }
        set(value) {
            if (value != null) {
                prefs.edit().putString(KEY_PENDING_SESSION_TOKEN, value).apply()
            } else {
                prefs.edit().remove(KEY_PENDING_SESSION_TOKEN).apply()
            }
        }

    /**
     * The email the user signed in with — kept so reopening the Foxy page shows
     * the filled-in form. The password is deliberately never persisted (it is
     * only the FxA proof at login time); nothing else needs it afterwards.
     */
    var savedEmail: String?
        get() = prefs.getString(KEY_SAVED_EMAIL, null)?.takeIf { it.isNotBlank() }
        set(value) {
            if (value.isNullOrBlank()) {
                prefs.edit().remove(KEY_SAVED_EMAIL).apply()
            } else {
                prefs.edit().putString(KEY_SAVED_EMAIL, value).apply()
            }
        }

    fun clear() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_REFRESH_TOKEN = "refresh_token"
        private const val KEY_EXPIRES_AT = "expires_at"
        private const val KEY_SESSION_EPOCH = "session_epoch"
        private const val KEY_PENDING_SESSION_TOKEN = "pending_session_token"
        private const val KEY_SAVED_EMAIL = "saved_email"

        private const val CLOCK_SKEW_TOLERANCE_SECONDS = 60L
    }
}
