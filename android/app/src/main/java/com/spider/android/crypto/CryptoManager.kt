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
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 消息加密管理器 — X25519 ECDH + AES-256-GCM + Ed25519 签名。
 *
 * 对齐 Spider Python 客户端的加密流程：
 * 1. 发送方用临时 X25519 私钥 + 接收方 X25519 公钥做 ECDH
 * 2. HKDF 派生 AES-256-GCM 会话密钥
 * 3. 加密消息（含 AAD：发送者、接收者、时间戳、协议版本）
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
     */
    fun encryptMessage(
        plaintext: String,
        recipientX25519Pub: String,
        senderEd25519Priv: String
    ): EncryptedMessage? {
        return try {
            // 1. 生成临时 X25519 密钥对
            val ephemeralKeyPair = keyManager.generateX25519KeyPair()
            val ephemeralPriv = ephemeralKeyPair.second
            val ephemeralPub = ephemeralKeyPair.first

            // 2. ECDH 密钥协商
            val sharedSecret = computeSharedSecret(ephemeralPriv, recipientX25519Pub)

            // 3. HKDF 派生会话密钥（简化版：直接 SHA-256）
            val sessionKey = hkdfDerive(sharedSecret, ephemeralPub, recipientX25519Pub)

            // 4. 生成 nonce
            val nonce = ByteArray(Protocol.NONCE_SIZE)
            secureRandom.nextBytes(nonce)

            // 5. AAD（附加认证数据）
            val identity = keyManager.getIdentity() ?: return null
            val aad = buildAad(identity.uuid, recipientX25519Pub, System.currentTimeMillis() / 1000)

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

            // 2. HKDF 派生会话密钥
            val identity = keyManager.getIdentity() ?: return null
            val sessionKey = hkdfDerive(sharedSecret, encrypted.ephemeralPubKey, identity.x25519Public)

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
     * HKDF 派生会话密钥（简化版：SHA-256(sharedSecret + ephemeralPub + recipientPub)）。
     */
    private fun hkdfDerive(sharedSecret: ByteArray, ephemeralPub: String, recipientPub: String): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        md.update(sharedSecret)
        md.update(ephemeralPub.toByteArray(Charsets.UTF_8))
        md.update(recipientPub.toByteArray(Charsets.UTF_8))
        return md.digest()
    }

    /**
     * 构建 AAD（附加认证数据）。
     */
    private fun buildAad(fromUuid: String, toPubKey: String, timestamp: Long): ByteArray {
        val aad = "spider-msg|$fromUuid|$toPubKey|$timestamp|${Protocol.PROTOCOL_VERSION}"
        return aad.toByteArray(Charsets.UTF_8)
    }

    /**
     * 加密文件数据。
     */
    fun encryptFileData(fileData: ByteArray, recipientX25519Pub: String): EncryptedMessage? {
        return encryptMessage(Base64.encodeToString(fileData, Base64.NO_WRAP), recipientX25519Pub,
            keyManager.getIdentity()?.ed25519Private ?: "")
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
