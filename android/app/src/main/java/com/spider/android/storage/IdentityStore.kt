package com.spider.android.storage

import android.content.ContentValues
import android.content.Context
import android.util.Base64
import com.spider.android.crypto.KeyManager
import com.spider.android.network.Protocol
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 身份存储 — 加密存储私钥和身份信息。
 *
 * 对齐 Spider Python 客户端的 identity.py：
 * - 私钥用 PIN 派生的 AES-256-GCM 密钥加密
 * - 胁迫 PIN 独立盐值 + 哈希
 * - 安全擦除
 */
class IdentityStore(context: Context) {

    private val dbHelper = DatabaseHelper(context)

    data class StoredIdentity(
        val uuid: String,
        val macAddress: String,
        val x25519Public: String,
        val x25519PrivateEnc: String,
        val x25519PrivateNonce: String,
        val ed25519Public: String,
        val ed25519PrivateEnc: String,
        val ed25519PrivateNonce: String,
        val serverHost: String,
        val serverPort: Int,
        val displayName: String,
        val encryptionSalt: String,
        val duressSalt: String,
        val duressPinHash: String,
        val hasDuressPin: Boolean
    )

    /**
     * 保存身份（私钥加密存储）。
     */
    fun saveIdentity(identity: KeyManager.Identity, pin: String,
                      duressPin: String = "", keyManager: KeyManager) {
        val salt = keyManager.generateSalt()
        val encKey = keyManager.deriveKeyFromPin(pin, salt)

        // 加密 X25519 私钥
        val xPrivEnc = encryptData(
            Base64.decode(identity.x25519Private, Base64.NO_WRAP), encKey
        )
        // 加密 Ed25519 私钥
        val ePrivEnc = encryptData(
            Base64.decode(identity.ed25519Private, Base64.NO_WRAP), encKey
        )

        // 胁迫 PIN
        var duressSalt = ""
        var duressHash = ""
        var hasDuress = 0
        if (duressPin.isNotEmpty()) {
            val dSalt = keyManager.generateSalt()
            val dKey = keyManager.deriveKeyFromPin(duressPin, dSalt)
            duressSalt = Base64.encodeToString(dSalt, Base64.NO_WRAP)
            duressHash = Base64.encodeToString(dKey, Base64.NO_WRAP)
            hasDuress = 1
        }

        // 解锁 PIN 哈希（用于检测反向输入密码）
        val uSalt = keyManager.generateSalt()
        val uKey = keyManager.deriveKeyFromPin(pin, uSalt)
        val unlockSalt = Base64.encodeToString(uSalt, Base64.NO_WRAP)
        val unlockHash = Base64.encodeToString(uKey, Base64.NO_WRAP)

        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("uuid", identity.uuid)
            put("mac_address", identity.macAddress)
            put("x25519_public", identity.x25519Public)
            put("x25519_private_enc", xPrivEnc.first)
            put("ed25519_public", identity.ed25519Public)
            put("ed25519_private_enc", ePrivEnc.first)
            put("server_host", identity.serverHost)
            put("server_port", identity.serverPort)
            put("display_name", identity.displayName)
            put("encryption_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
            put("duress_salt", duressSalt)
            put("duress_pin_hash", duressHash)
            put("has_duress_pin", hasDuress)
            put("unlock_pin_salt", unlockSalt)
            put("unlock_pin_hash", unlockHash)
        }
        // 存储 nonce 在 settings 表
        db.insertWithOnConflict(
            DatabaseHelper.TABLE_IDENTITY, null, values,
            android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE
        )
        saveSetting("x25519_priv_nonce", xPrivEnc.second)
        saveSetting("ed25519_priv_nonce", ePrivEnc.second)
    }

    /**
     * 加载并解密身份。
     */
    fun loadIdentity(pin: String, keyManager: KeyManager): KeyManager.Identity? {
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            DatabaseHelper.TABLE_IDENTITY, null, null, null,
            null, null, null, "1"
        )
        cursor.use {
            if (!it.moveToFirst()) return null
            val saltB64 = it.getString(it.getColumnIndexOrThrow("encryption_salt")) ?: return null
            val salt = Base64.decode(saltB64, Base64.NO_WRAP)
            val encKey = keyManager.deriveKeyFromPin(pin, salt)

            val xPrivEnc = it.getString(it.getColumnIndexOrThrow("x25519_private_enc")) ?: return null
            val xNonce = getSetting("x25519_priv_nonce") ?: return null
            val ePrivEnc = it.getString(it.getColumnIndexOrThrow("ed25519_private_enc")) ?: return null
            val eNonce = getSetting("ed25519_priv_nonce") ?: return null

            val xPriv = decryptData(xPrivEnc, xNonce, encKey) ?: return null
            val ePriv = decryptData(ePrivEnc, eNonce, encKey) ?: return null

            return KeyManager.Identity(
                uuid = it.getString(it.getColumnIndexOrThrow("uuid")),
                macAddress = it.getString(it.getColumnIndexOrThrow("mac_address")) ?: "",
                x25519Public = it.getString(it.getColumnIndexOrThrow("x25519_public")) ?: "",
                x25519Private = Base64.encodeToString(xPriv, Base64.NO_WRAP),
                ed25519Public = it.getString(it.getColumnIndexOrThrow("ed25519_public")) ?: "",
                ed25519Private = Base64.encodeToString(ePriv, Base64.NO_WRAP),
                serverHost = it.getString(it.getColumnIndexOrThrow("server_host")) ?: "",
                serverPort = it.getInt(it.getColumnIndexOrThrow("server_port")),
                displayName = it.getString(it.getColumnIndexOrThrow("display_name")) ?: ""
            )
        }
    }

    /**
     * 检查是否有已存储的身份。
     */
    fun hasIdentity(): Boolean {
        val db = dbHelper.readableDatabase
        val cursor = db.rawQuery("SELECT COUNT(*) FROM ${DatabaseHelper.TABLE_IDENTITY}", null)
        cursor.use {
            if (it.moveToFirst()) {
                return it.getInt(0) > 0
            }
        }
        return false
    }

    /**
     * 获取胁迫 PIN 信息（用于验证，不解密私钥）。
     */
    fun getDuressInfo(): Pair<String, String>? {
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            DatabaseHelper.TABLE_IDENTITY,
            arrayOf("duress_salt", "duress_pin_hash", "has_duress_pin"),
            null, null, null, null, null, "1"
        )
        cursor.use {
            if (!it.moveToFirst()) return null
            if (it.getInt(2) == 0) return null
            val salt = it.getString(0) ?: return null
            val hash = it.getString(1) ?: return null
            return Pair(salt, hash)
        }
    }

    /**
     * 验证胁迫 PIN。
     */
    fun verifyDuressPin(pin: String, keyManager: KeyManager): Boolean {
        val info = getDuressInfo() ?: return false
        val salt = Base64.decode(info.first, Base64.NO_WRAP)
        val key = keyManager.deriveKeyFromPin(pin, salt)
        val hash = Base64.encodeToString(key, Base64.NO_WRAP)
        return hash == info.second
    }

    /**
     * 获取解锁 PIN 哈希信息（用于检测反向输入密码，不解密私钥）。
     */
    fun getUnlockPinInfo(): Pair<String, String>? {
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            DatabaseHelper.TABLE_IDENTITY,
            arrayOf("unlock_pin_salt", "unlock_pin_hash"),
            null, null, null, null, null, "1"
        )
        cursor.use {
            if (!it.moveToFirst()) return null
            val salt = it.getString(0) ?: return null
            val hash = it.getString(1) ?: return null
            if (salt.isEmpty() || hash.isEmpty()) return null
            return Pair(salt, hash)
        }
    }

    /**
     * 验证解锁 PIN 哈希（用于检测用户是否输入了解锁 PIN 的倒序）。
     */
    fun verifyUnlockPinHash(pin: String, keyManager: KeyManager): Boolean {
        val info = getUnlockPinInfo() ?: return false
        val salt = Base64.decode(info.first, Base64.NO_WRAP)
        val key = keyManager.deriveKeyFromPin(pin, salt)
        val hash = Base64.encodeToString(key, Base64.NO_WRAP)
        return hash == info.second
    }

    private fun saveSetting(key: String, value: String) {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("key", key)
            put("value", value)
        }
        db.insertWithOnConflict(
            DatabaseHelper.TABLE_SETTINGS, null, values,
            android.database.sqlite.SQLiteDatabase.CONFLICT_REPLACE
        )
    }

    private fun getSetting(key: String): String? {
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            DatabaseHelper.TABLE_SETTINGS, arrayOf("value"),
            "key = ?", arrayOf(key), null, null, null
        )
        cursor.use {
            if (it.moveToFirst()) {
                return it.getString(0)
            }
        }
        return null
    }

    private fun encryptData(data: ByteArray, key: ByteArray): Pair<String, String> {
        val nonce = ByteArray(Protocol.NONCE_SIZE)
        java.security.SecureRandom().nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        val encrypted = cipher.doFinal(data)
        return Pair(
            Base64.encodeToString(encrypted, Base64.NO_WRAP),
            Base64.encodeToString(nonce, Base64.NO_WRAP)
        )
    }

    private fun decryptData(encryptedB64: String, nonceB64: String, key: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(128, Base64.decode(nonceB64, Base64.NO_WRAP))
            )
            cipher.doFinal(Base64.decode(encryptedB64, Base64.NO_WRAP))
        } catch (e: Exception) {
            null
        }
    }
}
