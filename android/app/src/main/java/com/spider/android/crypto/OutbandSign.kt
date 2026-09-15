package com.spider.android.crypto

import android.util.Base64
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.MessageDigest

/**
 * 带外签名（Out-of-Band Signature）工具。
 *
 * 签名串单行格式（与 Python 端逐字节对齐）：
 * ```
 * spider-sig:v1;uuid=xxx;timestamp=1757888888;data_hash=sha256hex;sig=base64
 * ```
 *
 * 两种模式（域分离，防止重放）：
 *  - ownership（账号所有权证明）：
 *      签名字节 = "spider-outband-ownership\n" + challenge(UTF-8) + "\n" + uuid(UTF-8)
 *  - content（消息内容签名）：
 *      签名字节 = "spider-outband-content\n" + content(UTF-8) + "\n" + uuid(UTF-8)
 *
 * data_hash = SHA-256(原始输入文本) 的小写十六进制字符串
 * sig      = Ed25519（RFC 8032）签名的标准 Base64（NO_WRAP）
 *
 * 跨端互通说明：
 *  - Python 端使用 cryptography 库的 Ed25519（RFC 8032 标准）；
 *  - Android 端使用 BouncyCastle 的 Ed25519Signer（同样是 RFC 8032）；
 *  - 两者签名字节完全一致时签名互通；Base64 均为标准编码、无换行（NO_WRAP）；
 *    SHA-256 hex 均为小写。
 *
 * Python 端参考实现（仅供对照，不要在 Android 端引入）：
 * ```python
 * import base64, hashlib, time
 * from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 *
 * def sign_outband(text: str, mode: str, priv_b64: str, uuid: str) -> str:
 *     priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
 *     prefix = b"spider-outband-ownership\n" if mode == "ownership" \
 *         else b"spider-outband-content\n"
 *     signed = prefix + text.encode("utf-8") + b"\n" + uuid.encode("utf-8")
 *     sig = priv.sign(signed)
 *     data_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
 *     return (f"spider-sig:v1;uuid={uuid};timestamp={int(time.time())};"
 *             f"data_hash={data_hash};sig={base64.b64encode(sig).decode('ascii')}")
 * ```
 *
 * 硬约束：私钥永远不上传服务器，签名全部在本地完成。
 */
object OutbandSign {

    const val MODE_OWNERSHIP = "ownership"
    const val MODE_CONTENT = "content"

    private const val PREFIX_OWNERSHIP = "spider-outband-ownership\n"
    private const val PREFIX_CONTENT = "spider-outband-content\n"
    private const val SCHEME = "spider-sig:v1"
    private const val FIELD_SEP = ";"
    private const val KV_SEP = "="

    data class VerifyResult(
        val valid: Boolean,
        val uuid: String,
        val timestamp: Long,
        val mode: String,
        val error: String
    )

    /**
     * 生成签名串。
     *
     * @param text 待签名文本：ownership 模式为 challenge（nonce）；content 模式为消息原文
     * @param mode [MODE_OWNERSHIP] 或 [MODE_CONTENT]
     * @param ed25519PrivB64 Ed25519 私钥（Base64 NO_WRAP，32 字节原始私钥）
     * @param uuid 签名者账号 UUID
     * @return 签名串；任何一步失败返回 null
     */
    fun sign(
        text: String,
        mode: String,
        ed25519PrivB64: String,
        uuid: String
    ): String? {
        return try {
            val signedBytes = buildSignedBytes(mode, text, uuid) ?: return null
            val dataHash = sha256Hex(text)
            val timestamp = System.currentTimeMillis() / 1000L

            val privKey = Ed25519PrivateKeyParameters(
                Base64.decode(ed25519PrivB64, Base64.NO_WRAP), 0
            )
            val signer = Ed25519Signer()
            signer.init(true, privKey)
            signer.update(signedBytes, 0, signedBytes.size)
            val sigBytes = signer.generateSignature()
            val sigB64 = Base64.encodeToString(sigBytes, Base64.NO_WRAP)

            "$SCHEME$FIELD_SEP" +
                    "uuid=$uuid$FIELD_SEP" +
                    "timestamp=$timestamp$FIELD_SEP" +
                    "data_hash=$dataHash$FIELD_SEP" +
                    "sig=$sigB64"
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    /**
     * 校验签名串。
     *
     * 校验步骤：
     *  1. 解析签名串，提取 uuid / timestamp / data_hash / sig；
     *  2. 重算 SHA-256(originalText) hex，与 data_hash 做常量时间比较；
     *  3. 签名串本身不带 mode 字段，依次尝试 ownership / content 两种域分离前缀，
     *     哪一种能通过 Ed25519 验签即为有效，并把该模式写入 [VerifyResult.mode]。
     *
     * @param signatureString 完整签名串
     * @param originalText 原始输入文本（必须与签名时的 text 完全一致）
     * @param ed25519PubB64 签名者 Ed25519 公钥（Base64 NO_WRAP，32 字节原始公钥）
     */
    fun verify(
        signatureString: String,
        originalText: String,
        ed25519PubB64: String
    ): VerifyResult {
        val parsed = parse(signatureString)
            ?: return VerifyResult(false, "", 0L, "", "签名串格式错误")

        val sigUuid = parsed["uuid"]
            ?: return VerifyResult(false, "", 0L, "", "缺少 uuid 字段")
        val sigTimestamp = parsed["timestamp"]?.toLongOrNull()
            ?: return VerifyResult(false, sigUuid, 0L, "", "缺少 timestamp 字段")
        val sigDataHash = parsed["data_hash"]
            ?: return VerifyResult(false, sigUuid, sigTimestamp, "", "缺少 data_hash 字段")
        val sigB64 = parsed["sig"]
            ?: return VerifyResult(false, sigUuid, sigTimestamp, "", "缺少 sig 字段")

        // 1. data_hash 必须与原文匹配（防原文被替换）
        val actualHash = sha256Hex(originalText)
        if (!constantTimeEquals(actualHash, sigDataHash)) {
            return VerifyResult(false, sigUuid, sigTimestamp, "", "data_hash 与原文不匹配")
        }

        // 2. 解码公钥与签名
        val pubKey = try {
            Ed25519PublicKeyParameters(Base64.decode(ed25519PubB64, Base64.NO_WRAP), 0)
        } catch (e: Exception) {
            return VerifyResult(false, sigUuid, sigTimestamp, "", "公钥格式错误")
        }
        val sigBytes = try {
            Base64.decode(sigB64, Base64.NO_WRAP)
        } catch (e: Exception) {
            return VerifyResult(false, sigUuid, sigTimestamp, "", "签名 Base64 解码失败")
        }

        // 3. 依次尝试两种域分离前缀
        for (m in listOf(MODE_OWNERSHIP, MODE_CONTENT)) {
            val signedBytes = buildSignedBytes(m, originalText, sigUuid) ?: continue
            try {
                val verifier = Ed25519Signer()
                verifier.init(false, pubKey)
                verifier.update(signedBytes, 0, signedBytes.size)
                if (verifier.verifySignature(sigBytes)) {
                    return VerifyResult(true, sigUuid, sigTimestamp, m, "")
                }
            } catch (e: Exception) {
                // 当前前缀不匹配，尝试下一种
            }
        }
        return VerifyResult(false, sigUuid, sigTimestamp, "", "Ed25519 签名校验失败")
    }

    /**
     * 解析签名串为字段字典。格式错误返回 null。
     */
    fun parse(signatureString: String): Map<String, String>? {
        val s = signatureString.trim()
        if (!s.startsWith("$SCHEME$FIELD_SEP")) return null
        val body = s.removePrefix("$SCHEME$FIELD_SEP")
        if (body.isEmpty()) return null
        val map = HashMap<String, String>()
        for (pair in body.split(FIELD_SEP)) {
            val idx = pair.indexOf(KV_SEP)
            if (idx <= 0) return null
            val k = pair.substring(0, idx)
            val v = pair.substring(idx + 1)
            map[k] = v
        }
        // 必备字段
        if (!map.containsKey("uuid") || !map.containsKey("timestamp") ||
            !map.containsKey("data_hash") || !map.containsKey("sig")
        ) {
            return null
        }
        return map
    }

    /**
     * 构造实际参与 Ed25519 签名的字节（域分离前缀 + text + "\n" + uuid）。
     */
    private fun buildSignedBytes(mode: String, text: String, uuid: String): ByteArray? {
        val prefix = when (mode) {
            MODE_OWNERSHIP -> PREFIX_OWNERSHIP
            MODE_CONTENT -> PREFIX_CONTENT
            else -> return null
        }
        val prefixBytes = prefix.toByteArray(Charsets.UTF_8)
        val textBytes = text.toByteArray(Charsets.UTF_8)
        val nlBytes = "\n".toByteArray(Charsets.UTF_8)
        val uuidBytes = uuid.toByteArray(Charsets.UTF_8)
        return prefixBytes + textBytes + nlBytes + uuidBytes
    }

    private fun sha256Hex(input: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(input.toByteArray(Charsets.UTF_8))
        // %02x 输出小写 hex，与 Python hashlib.sha256(...).hexdigest() 一致
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var r = 0
        for (i in a.indices) {
            r = r or (a[i].code xor b[i].code)
        }
        return r == 0
    }

    /**
     * 本地自测（在设备上调用，用于验证签/验签闭环）。
     *
     * 生成一次性 Ed25519 密钥对，分别对 ownership / content 两种模式签名并验签，
     * 同时验证 data_hash 与签名串格式。返回 true 表示本地闭环通过。
     *
     * 跨端互通验证方法：
     *  1. 在 Python 端用 [sign_outband] 生成签名串；
     *  2. 把该签名串与原文粘贴到本工具的校验区；
     *  3. 若返回"有效"，即证明 Kotlin(BouncyCastle) 与 Python(cryptography) 互通。
     */
    fun selftest(): Boolean {
        return try {
            val gen = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
            gen.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(
                java.security.SecureRandom()
            ))
            val pair = gen.generateKeyPair()
            val priv = pair.private as org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
            val pub = pair.public as org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
            val privB64 = Base64.encodeToString(priv.encoded, Base64.NO_WRAP)
            val pubB64 = Base64.encodeToString(pub.encoded, Base64.NO_WRAP)
            val uuid = "11111111-2222-3333-4444-555555555555"

            for (mode in listOf(MODE_OWNERSHIP, MODE_CONTENT)) {
                val text = "hello-outband-$mode"
                val sigStr = sign(text, mode, privB64, uuid) ?: return false
                if (!sigStr.startsWith("$SCHEME;")) return false
                val r = verify(sigStr, text, pubB64)
                if (!r.valid || r.mode != mode || r.uuid != uuid) return false
                // 篡改原文应当验签失败
                val bad = verify(sigStr, text + "x", pubB64)
                if (bad.valid) return false
            }
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}
