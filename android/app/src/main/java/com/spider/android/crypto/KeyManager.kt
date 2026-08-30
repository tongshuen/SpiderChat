package com.spider.android.crypto

import android.content.Context
import android.util.Base64
import com.spider.android.network.Protocol
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.SecureRandom
import java.security.Security
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * 密钥管理器 — X25519（密钥交换）+ Ed25519（签名）+ PIN 派生加密。
 *
 * 对齐 Spider Python 客户端的 KeyManager：
 * - UUIDv1 + MAC 身份（Android 用 ANDROID_ID 作为 MAC 替代）
 * - X25519 密钥对用于 ECDH 密钥协商
 * - Ed25519 密钥对用于消息签名
 * - 私钥用 PIN 派生的 AES-256 密钥加密存储
 * - 胁迫 PIN 独立盐值 + 哈希
 */
class KeyManager(private val context: Context) {

    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    data class Identity(
        val uuid: String,
        val macAddress: String,
        val x25519Public: String,
        val x25519Private: String,
        val ed25519Public: String,
        val ed25519Private: String,
        val serverHost: String = "",
        val serverPort: Int = 0,
        val displayName: String = ""
    )

    private val secureRandom = SecureRandom()
    private var currentIdentity: Identity? = null
    private var duressPinHash: String? = null
    private var duressSalt: String? = null

    /**
     * 生成新的 X25519 密钥对。
     */
    fun generateX25519KeyPair(): Pair<String, String> {
        val generator = X25519KeyPairGenerator()
        generator.init(X25519KeyGenerationParameters(secureRandom))
        val pair: AsymmetricCipherKeyPair = generator.generateKeyPair()
        val priv = pair.private as X25519PrivateKeyParameters
        val pub = pair.public as X25519PublicKeyParameters
        return Pair(
            Base64.encodeToString(pub.encoded, Base64.NO_WRAP),
            Base64.encodeToString(priv.encoded, Base64.NO_WRAP)
        )
    }

    /**
     * 生成新的 Ed25519 密钥对。
     */
    fun generateEd25519KeyPair(): Pair<String, String> {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(secureRandom))
        val pair: AsymmetricCipherKeyPair = generator.generateKeyPair()
        val priv = pair.private as Ed25519PrivateKeyParameters
        val pub = pair.public as Ed25519PublicKeyParameters
        return Pair(
            Base64.encodeToString(pub.encoded, Base64.NO_WRAP),
            Base64.encodeToString(priv.encoded, Base64.NO_WRAP)
        )
    }

    /**
     * 用 PIN 派生 AES-256 密钥（PBKDF2-HMAC-SHA256）。
     */
    fun deriveKeyFromPin(pin: String, salt: ByteArray): ByteArray {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(pin.toCharArray(), salt, Protocol.PBKDF2_ITERATIONS, 256)
        return factory.generateSecret(spec).encoded
    }

    /**
     * 生成随机盐值。
     */
    fun generateSalt(): ByteArray {
        val salt = ByteArray(Protocol.SALT_SIZE)
        secureRandom.nextBytes(salt)
        return salt
    }

    /**
     * 生成随机 UUID（模拟 UUIDv1 + MAC，Android 环境用随机 UUID）。
     */
    fun generateUuid(): String {
        return java.util.UUID.randomUUID().toString()
    }

    /**
     * 获取 Android ID 作为 MAC 地址替代。
     */
    fun getMacAddress(): String {
        return android.provider.Settings.Secure.getString(
            context.contentResolver,
            android.provider.Settings.Secure.ANDROID_ID
        ) ?: "00:00:00:00:00:00"
    }

    /**
     * 创建新身份（注册时调用）。
     */
    fun createIdentity(serverHost: String, serverPort: Int, displayName: String): Identity {
        val (xPub, xPriv) = generateX25519KeyPair()
        val (ePub, ePriv) = generateEd25519KeyPair()
        val uuid = generateUuid()
        val mac = getMacAddress()
        return Identity(
            uuid = uuid,
            macAddress = mac,
            x25519Public = xPub,
            x25519Private = xPriv,
            ed25519Public = ePub,
            ed25519Private = ePriv,
            serverHost = serverHost,
            serverPort = serverPort,
            displayName = displayName
        )
    }

    /**
     * 设置当前已解锁身份。
     */
    fun setIdentity(identity: Identity) {
        currentIdentity = identity
    }

    /**
     * 获取当前身份（需先解锁）。
     */
    fun getIdentity(): Identity? = currentIdentity

    /**
     * 获取当前 UUID。
     */
    fun getUuid(): String = currentIdentity?.uuid ?: ""

    /**
     * 设置胁迫 PIN 哈希。
     */
    fun setDuressPin(pin: String) {
        val salt = generateSalt()
        duressSalt = Base64.encodeToString(salt, Base64.NO_WRAP)
        val key = deriveKeyFromPin(pin, salt)
        duressPinHash = Base64.encodeToString(key, Base64.NO_WRAP)
    }

    /**
     * 验证胁迫 PIN。
     */
    fun checkDuressPin(pin: String): Boolean {
        if (duressPinHash == null || duressSalt == null) return false
        val salt = Base64.decode(duressSalt, Base64.NO_WRAP)
        val key = deriveKeyFromPin(pin, salt)
        val hash = Base64.encodeToString(key, Base64.NO_WRAP)
        return hash == duressPinHash
    }

    fun hasDuressPin(): Boolean = duressPinHash != null

    fun getDuressSalt(): String? = duressSalt
    fun getDuressPinHash(): String? = duressPinHash

    fun loadDuressFromStorage(salt: String, hash: String) {
        duressSalt = salt
        duressPinHash = hash
    }

    /**
     * 清除所有密钥数据（胁迫擦除时调用）。
     */
    fun wipe() {
        currentIdentity = null
        duressPinHash = null
        duressSalt = null
    }
}
