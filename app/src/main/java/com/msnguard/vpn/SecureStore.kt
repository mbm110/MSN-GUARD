package com.msnguard.vpn

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object SecureStore {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    // Renaming this is safe precisely because the package changed: AndroidKeyStore
    // is scoped per app UID, so com.msnguard.vpn starts with an empty keystore and
    // the alias is generated fresh on first use. There is nothing to migrate.
    private const val KEY_ALIAS = "msnguard_credential_key"
    private const val PREFS_NAME = "secure_settings"
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 128

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) {
            val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
            if (entry != null) return entry.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    fun encrypt(plainText: String): String {
        if (plainText.isEmpty()) return ""
        return try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
            val combined = ByteArray(iv.size + cipherText.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(cipherText, 0, combined, iv.size, cipherText.size)
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (_: Exception) {
            plainText
        }
    }

    fun decrypt(encryptedBase64: String): String {
        if (encryptedBase64.isEmpty()) return ""
        return try {
            val combined = Base64.decode(encryptedBase64, Base64.NO_WRAP)
            if (combined.size <= GCM_IV_LENGTH) return encryptedBase64
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, combined, 0, GCM_IV_LENGTH)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            val plainBytes = cipher.doFinal(combined, GCM_IV_LENGTH, combined.size - GCM_IV_LENGTH)
            String(plainBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            encryptedBase64
        }
    }

    fun putSecret(context: Context, key: String, value: String) {
        val encrypted = if (value.isNotBlank()) encrypt(value) else ""
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(key, encrypted)
            .apply()
        // Clean from plain prefs if it was there
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .edit()
            .remove(key)
            .apply()
    }

    fun getSecret(context: Context, key: String, fallback: String = ""): String {
        val securePrefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encrypted = securePrefs.getString(key, null)
        if (encrypted != null) {
            return decrypt(encrypted).ifBlank { fallback }
        }
        // Fallback to legacy plain settings for migration
        val plainPrefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val legacy = plainPrefs.getString(key, null)
        if (!legacy.isNullOrBlank()) {
            putSecret(context, key, legacy)
            return legacy
        }
        return fallback
    }

    fun removeSecret(context: Context, key: String) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(key)
            .apply()
        context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            .edit()
            .remove(key)
            .apply()
    }
}
