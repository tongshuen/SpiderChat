package com.spider.android.crypto

import android.util.Base64
import com.spider.android.network.Protocol
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 消息加密管理器 — X25519 ECDH + HKDF-SHA256 + AES-256-GCM + Ed25519 签名。
 *
 * 完全对齐 Spider Python 客户端和 Minecraft 模组的加密流程：
 * 1. 发送方用临时 X25519 私钥 + 接收方 X25519 公钥做 ECDH
 * 2. 标准 HKDF-SHA256 派生 AES-256-GCM 会话密钥（info="spider-msg-ephemeral-v1"）
 * 3. 加密消息（AAD = JSON {"from","to","ts","proto"}，键排序对齐 Python sort_keys=True）
 * 4. 发送方用 Ed25519 私钥签名
 */
class CryptoManager(private val keyManager: KeyManager) {

    private val secureRandom = SecureRandom()

    data class EncryptedMessage(
        val ciphertext: String,      // Base64
        val nonce: String,           // Base64
        val tag: String,             // Base64
        val ephemeralPubKey: String, // Base64 (发送方临时 X25519 公钥)
        val aad: String              // Base64
    )

    /**
     * 加密消息。
     *
     * @param plaintext 明文
     * @param recipientUuid 接收方 UUID（用于 AAD）
     * @param recipientX25519Pub 接收方 X25519 公钥（Base64）
     * @param senderEd25519Priv 发送方 Ed25519 私钥（Base64）
     */
    fun encryptMessage(
        plaintext: String,
        recipientUuid: String,
        recipientX25519Pub: String,
        senderEd25519Priv: String
    ): EncryptedMessage? {
        return try {
            // 1. 生成临时 X25519 密钥对（前向保密）
            val ephemeralKeyPair = keyManager.generateX25519KeyPair()
            val ephemeralPriv = ephemeralKeyPair.second
            val ephemeralPub = ephemeralKeyPair.first

            // 2. ECDH 密钥协商
            val sharedSecret = computeSharedSecret(ephemeralPriv, recipientX25519Pub)

            // 3. 标准 HKDF-SHA256 派生会话密钥（对齐 Python/Minecraft）
            val sessionKey = hkdfDerive(
                ikm = sharedSecret,
                info = "spider-msg-ephemeral-v1".toByteArray(Charsets.UTF_8),
                length = 32
            )

            // 4. 生成 nonce
            val nonce = ByteArray(Protocol.NONCE_SIZE)
            secureRandom.nextBytes(nonce)

            // 5. AAD（附加认证数据）— JSON 格式，键排序，对齐 Python json.dumps(sort_keys=True)
            val identity = keyManager.getIdentity() ?: return null
            val timestamp = System.currentTimeMillis() / 1000
            val aad = buildAad(identity.uuid, recipientUuid, timestamp)

            // 6. AES-256-GCM 加密
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(sessionKey, "AES")
            val gcmSpec = GCMParameterSpec(Protocol.TAG_SIZE * 8, nonce)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(aad)
            val ciphertextWithTag = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))

            // 分离 ciphertext 和 tag
            val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - Protocol.TAG_SIZE)
            val tag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - Protocol.TAG_SIZE, ciphertextWithTag.size)

            EncryptedMessage(
                ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
                nonce = Base64.encodeToString(nonce, Base64.NO_WRAP),
                tag = Base64.encodeToString(tag, Base64.NO_WRAP),
                ephemeralPubKey = ephemeralPub,
                aad = Base64.encodeToString(aad, Base64.NO_WRAP)
            )
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 解密消息。
     */
    fun decryptMessage(
        encrypted: EncryptedMessage,
        recipientX25519Priv: String,
        senderEd25519Pub: String
    ): String? {
        return try {
            // 1. ECDH 密钥协商（接收方私钥 + 发送方临时公钥）
            val sharedSecret = computeSharedSecret(recipientX25519Priv, encrypted.ephemeralPubKey)

            // 2. 标准 HKDF-SHA256 派生会话密钥（对齐 Python/Minecraft）
            val sessionKey = hkdfDerive(
                ikm = sharedSecret,
                info = "spider-msg-ephemeral-v1".toByteArray(Charsets.UTF_8),
                length = 32
            )

            // 3. AES-256-GCM 解密
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(sessionKey, "AES")
            val nonce = Base64.decode(encrypted.nonce, Base64.NO_WRAP)
            val gcmSpec = GCMParameterSpec(Protocol.TAG_SIZE * 8, nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
            cipher.updateAAD(Base64.decode(encrypted.aad, Base64.NO_WRAP))

            val ciphertext = Base64.decode(encrypted.ciphertext, Base64.NO_WRAP)
            val tag = Base64.decode(encrypted.tag, Base64.NO_WRAP)
            val combined = ciphertext + tag
            val plaintext = cipher.doFinal(combined)
            String(plaintext, Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 用 Ed25519 签名数据。
     */
    fun signData(data: ByteArray, privateKeyB64: String): String? {
        return try {
            val privKey = Ed25519PrivateKeyParameters(Base64.decode(privateKeyB64, Base64.NO_WRAP), 0)
            val signer = Ed25519Signer()
            signer.init(true, privKey)
            signer.update(data, 0, data.size)
            val signature = signer.generateSignature()
            Base64.encodeToString(signature, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 验证 Ed25519 签名。
     */
    fun verifySignature(data: ByteArray, signatureB64: String, publicKeyB64: String): Boolean {
        return try {
            val pubKey = Ed25519PublicKeyParameters(Base64.decode(publicKeyB64, Base64.NO_WRAP), 0)
            val signer = Ed25519Signer()
            signer.init(false, pubKey)
            signer.update(data, 0, data.size)
            val signature = Base64.decode(signatureB64, Base64.NO_WRAP)
            signer.verifySignature(signature)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 计算 X25519 ECDH 共享密钥。
     */
    private fun computeSharedSecret(privateKeyB64: String, publicKeyB64: String): ByteArray {
        val privKey = X25519PrivateKeyParameters(Base64.decode(privateKeyB64, Base64.NO_WRAP), 0)
        val pubKey = X25519PublicKeyParameters(Base64.decode(publicKeyB64, Base64.NO_WRAP), 0)
        val agreement = X25519Agreement()
        agreement.init(privKey)
        val shared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(pubKey, shared, 0)
        return shared
    }

    /**
     * 标准 HKDF-SHA256（RFC 5869）— 对齐 Python cryptography 库和 Minecraft 实现。
     *
     * Extract: PRK = HMAC-SHA256(salt, IKM)
     * Expand:  OKM = T(1) | T(2) | ...
     *          T(0) = empty
     *          T(i) = HMAC-SHA256(PRK, T(i-1) | info | counter)
     *
     * @param ikm 输入密钥材料（ECDH 共享密钥）
     * @param info 上下文信息（如 "spider-msg-ephemeral-v1"）
     * @param length 输出密钥长度（字节）
     * @param salt 盐值，null 时使用 32 字节全零（对齐 Python salt=None 和 Minecraft salt=null）
     */
    private fun hkdfDerive(ikm: ByteArray, info: ByteArray, length: Int = 32, salt: ByteArray? = null): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")

        // Extract 阶段
        val actualSalt = salt ?: ByteArray(32) // 全零盐，对齐 Python salt=None
        mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)

        // Expand 阶段
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val result = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1

        while (offset < length) {
            mac.reset()
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val copyLen = minOf(t.size, length - offset)
            System.arraycopy(t, 0, result, offset, copyLen)
            offset += copyLen
            counter++
        }

        return result
    }

    /**
     * 构建 AAD（附加认证数据）。
     *
     * 对齐 Python: json.dumps({"from": uuid, "to": uuid, "ts": timestamp, "proto": "spider/2.0"}, sort_keys=True)
     * 键排序后: from, proto, to, ts
     * Python 默认 separators=(', ', ': ')，即逗号和冒号后有空格
     */
    private fun buildAad(fromUuid: String, toUuid: String, timestamp: Long): ByteArray {
        val aad = "{\"from\": \"$fromUuid\", \"proto\": \"spider/2.0\", \"to\": \"$toUuid\", \"ts\": $timestamp}"
        return aad.toByteArray(Charsets.UTF_8)
    }

    /**
     * 加密文件数据。
     */
    fun encryptFileData(fileData: ByteArray, recipientUuid: String, recipientX25519Pub: String): EncryptedMessage? {
        return encryptMessage(
            Base64.encodeToString(fileData, Base64.NO_WRAP),
            recipientUuid,
            recipientX25519Pub,
            keyManager.getIdentity()?.ed25519Private ?: ""
        )
    }

    /**
     * 解密文件数据。
     */
    fun decryptFileData(encrypted: EncryptedMessage, senderEd25519Pub: String): ByteArray? {
        val identity = keyManager.getIdentity() ?: return null
        val plaintext = decryptMessage(encrypted, identity.x25519Private, senderEd25519Pub) ?: return null
        return Base64.decode(plaintext, Base64.NO_WRAP)
    }
}
