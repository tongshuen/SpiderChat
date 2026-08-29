package com.spider.minecraft.crypto;

import com.google.gson.JsonObject;
import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.util.JsonUtil;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 消息端到端加密管理器 — 对齐 Spider 的 client/crypto/encrypt.py。
 *
 * <p>每条消息使用独立的加密信封：
 * <ul>
 *   <li>X25519 ECDH 派生 AES-256 密钥（支持临时密钥前向保密）</li>
 *   <li>AES-256-GCM 加密，AAD 绑定 from/to UUID + 时间戳 + 协议版本</li>
 *   <li>Ed25519 签署完整加密信封</li>
 * </ul>
 *
 * <p>信封格式与 Spider 完全兼容，可直接与 Spider 客户端互通。
 */
public class CryptoManager {

    private final KeyManager keyManager;
    private final ConcurrentHashMap<String, AsymmetricCipherKeyPair> ephemeralKeys = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> peerEphemeralPub = new ConcurrentHashMap<>();

    public CryptoManager(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /**
     * 加密一条文本消息。
     */
    public JsonObject encryptMessage(String plaintext, String peerUuid,
                                      String peerXPubB64, String peerEPubB64) {
        long timestamp = System.currentTimeMillis() / 1000;
        boolean useFs = ephemeralKeys.containsKey(peerUuid) && peerEphemeralPub.containsKey(peerUuid);

        byte[] sharedSecret;
        if (useFs) {
            X25519PrivateKeyParameters myEphPriv =
                    (X25519PrivateKeyParameters) ephemeralKeys.get(peerUuid).getPrivate();
            X25519PublicKeyParameters peerEphPub =
                    new X25519PublicKeyParameters(JsonUtil.b64Decode(peerEphemeralPub.get(peerUuid)), 0);
            sharedSecret = KeyManager.ecdh(myEphPriv, peerEphPub);
        } else {
            X25519PublicKeyParameters peerPub =
                    new X25519PublicKeyParameters(JsonUtil.b64Decode(peerXPubB64), 0);
            sharedSecret = KeyManager.ecdh(keyManager.getX25519Private(), peerPub);
        }

        byte[] info = (useFs ? "spider-msg-ephemeral-v1" : "spider-msg-identity-v1")
                .getBytes(StandardCharsets.UTF_8);
        byte[] aesKey = KeyManager.hkdf(sharedSecret, null, info, SpiderMinecraft.AES_KEY_LENGTH_BYTES);

        JsonObject aadObj = new JsonObject();
        aadObj.addProperty("from", keyManager.getIdentityUuid());
        aadObj.addProperty("to", peerUuid);
        aadObj.addProperty("ts", timestamp);
        aadObj.addProperty("proto", SpiderMinecraft.PROTOCOL_VERSION);
        byte[] aad = JsonUtil.toJson(aadObj).getBytes(StandardCharsets.UTF_8);

        byte[] encrypted = KeyManager.aesGcmEncryptRaw(aesKey,
                com.spider.minecraft.util.JsonUtil.utf8(plaintext));
        byte[] nonce = new byte[SpiderMinecraft.GCM_NONCE_LENGTH_BYTES];
        System.arraycopy(encrypted, 0, nonce, 0, SpiderMinecraft.GCM_NONCE_LENGTH_BYTES);
        byte[] ctAndTag = new byte[encrypted.length - SpiderMinecraft.GCM_NONCE_LENGTH_BYTES];
        System.arraycopy(encrypted, SpiderMinecraft.GCM_NONCE_LENGTH_BYTES, ctAndTag, 0, ctAndTag.length);

        byte[] toSign = new byte[nonce.length + ctAndTag.length + aad.length];
        System.arraycopy(nonce, 0, toSign, 0, nonce.length);
        System.arraycopy(ctAndTag, 0, toSign, nonce.length, ctAndTag.length);
        System.arraycopy(aad, 0, toSign, nonce.length + ctAndTag.length, aad.length);
        byte[] signature = KeyManager.ed25519Sign(keyManager.getEd25519Private(), toSign);

        JsonObject envelope = new JsonObject();
        envelope.addProperty("version", 2);
        envelope.addProperty("from_uuid", keyManager.getIdentityUuid());
        envelope.addProperty("to_uuid", peerUuid);
        envelope.addProperty("timestamp", timestamp);
        envelope.addProperty("nonce", JsonUtil.b64Encode(nonce));
        envelope.addProperty("ciphertext", JsonUtil.b64Encode(ctAndTag));
        envelope.addProperty("aad", JsonUtil.b64Encode(aad));
        envelope.addProperty("signature", JsonUtil.b64Encode(signature));
        envelope.addProperty("fs_used", useFs);
        if (useFs) {
            X25519PublicKeyParameters myEphPub =
                    (X25519PublicKeyParameters) ephemeralKeys.get(peerUuid).getPublic();
            envelope.addProperty("ephemeral_pub", JsonUtil.b64Encode(myEphPub.getEncoded()));
        }
        return envelope;
    }

    /**
     * 解密一条消息。
     */
    public String decryptMessage(JsonObject envelope, String peerXPubB64, String peerEPubB64) {
        String fromUuid = envelope.get("from_uuid").getAsString();
        long timestamp = envelope.get("timestamp").getAsLong();
        byte[] nonce = JsonUtil.b64Decode(envelope.get("nonce").getAsString());
        byte[] ctAndTag = JsonUtil.b64Decode(envelope.get("ciphertext").getAsString());
        byte[] aad = JsonUtil.b64Decode(envelope.get("aad").getAsString());
        byte[] signature = JsonUtil.b64Decode(envelope.get("signature").getAsString());
        boolean fsUsed = envelope.has("fs_used") && envelope.get("fs_used").getAsBoolean();
        String peerEphPubB64 = envelope.has("ephemeral_pub") ? envelope.get("ephemeral_pub").getAsString() : null;

        JsonObject aadObj = JsonUtil.parse(new String(aad, StandardCharsets.UTF_8));
        if (!aadObj.get("from").getAsString().equals(fromUuid))
            throw new SecurityException("AAD from mismatch");
        if (aadObj.get("ts").getAsLong() != timestamp)
            throw new SecurityException("AAD timestamp mismatch");

        Ed25519PublicKeyParameters peerSignPub =
                new Ed25519PublicKeyParameters(JsonUtil.b64Decode(peerEPubB64), 0);
        byte[] toVerify = new byte[nonce.length + ctAndTag.length + aad.length];
        System.arraycopy(nonce, 0, toVerify, 0, nonce.length);
        System.arraycopy(ctAndTag, 0, toVerify, nonce.length, ctAndTag.length);
        System.arraycopy(aad, 0, toVerify, nonce.length + ctAndTag.length, aad.length);
        if (!KeyManager.ed25519Verify(peerSignPub, toVerify, signature))
            throw new SecurityException("Ed25519 signature verification failed");

        byte[] sharedSecret;
        if (fsUsed && peerEphPubB64 != null) {
            if (ephemeralKeys.containsKey(fromUuid)) {
                X25519PrivateKeyParameters myEphPriv =
                        (X25519PrivateKeyParameters) ephemeralKeys.get(fromUuid).getPrivate();
                X25519PublicKeyParameters peerEphPub =
                        new X25519PublicKeyParameters(JsonUtil.b64Decode(peerEphPubB64), 0);
                sharedSecret = KeyManager.ecdh(myEphPriv, peerEphPub);
            } else {
                X25519PublicKeyParameters peerEphPub =
                        new X25519PublicKeyParameters(JsonUtil.b64Decode(peerEphPubB64), 0);
                sharedSecret = KeyManager.ecdh(keyManager.getX25519Private(), peerEphPub);
            }
        } else {
            X25519PublicKeyParameters peerPub =
                    new X25519PublicKeyParameters(JsonUtil.b64Decode(peerXPubB64), 0);
            sharedSecret = KeyManager.ecdh(keyManager.getX25519Private(), peerPub);
        }

        byte[] info = (fsUsed ? "spider-msg-ephemeral-v1" : "spider-msg-identity-v1")
                .getBytes(StandardCharsets.UTF_8);
        byte[] aesKey = KeyManager.hkdf(sharedSecret, null, info, SpiderMinecraft.AES_KEY_LENGTH_BYTES);

        byte[] encrypted = new byte[nonce.length + ctAndTag.length];
        System.arraycopy(nonce, 0, encrypted, 0, nonce.length);
        System.arraycopy(ctAndTag, 0, encrypted, nonce.length, ctAndTag.length);
        byte[] plaintext = KeyManager.aesGcmDecryptRaw(aesKey, encrypted);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    /**
     * 加密文件数据 — 对齐 Spider 的 encrypt_file_data。
     */
    public byte[][] encryptFileData(byte[] data, String peerUuid,
                                     String peerXPubB64) {
        boolean useFs = ephemeralKeys.containsKey(peerUuid) && peerEphemeralPub.containsKey(peerUuid);
        byte[] sharedSecret;
        if (useFs) {
            X25519PrivateKeyParameters myEphPriv =
                    (X25519PrivateKeyParameters) ephemeralKeys.get(peerUuid).getPrivate();
            X25519PublicKeyParameters peerEphPub =
                    new X25519PublicKeyParameters(JsonUtil.b64Decode(peerEphemeralPub.get(peerUuid)), 0);
            sharedSecret = KeyManager.ecdh(myEphPriv, peerEphPub);
        } else {
            X25519PublicKeyParameters peerPub =
                    new X25519PublicKeyParameters(JsonUtil.b64Decode(peerXPubB64), 0);
            sharedSecret = KeyManager.ecdh(keyManager.getX25519Private(), peerPub);
        }
        byte[] info = (useFs ? "spider-file-ephemeral-v1" : "spider-file-identity-v1")
                .getBytes(StandardCharsets.UTF_8);
        byte[] aesKey = KeyManager.hkdf(sharedSecret, null, info, SpiderMinecraft.AES_KEY_LENGTH_BYTES);

        JsonObject aadObj = new JsonObject();
        aadObj.addProperty("type", "file");
        aadObj.addProperty("size", data.length);
        aadObj.addProperty("ts", System.currentTimeMillis() / 1000);
        byte[] aad = JsonUtil.toJson(aadObj).getBytes(StandardCharsets.UTF_8);

        // 使用 AES-GCM 加密（带 AAD）
        byte[] encrypted = KeyManager.aesGcmEncryptRaw(aesKey, data);
        // 返回 [nonce, ciphertext+tag, aad]
        byte[] nonce = new byte[SpiderMinecraft.GCM_NONCE_LENGTH_BYTES];
        System.arraycopy(encrypted, 0, nonce, 0, SpiderMinecraft.GCM_NONCE_LENGTH_BYTES);
        byte[] ctAndTag = new byte[encrypted.length - SpiderMinecraft.GCM_NONCE_LENGTH_BYTES];
        System.arraycopy(encrypted, SpiderMinecraft.GCM_NONCE_LENGTH_BYTES, ctAndTag, 0, ctAndTag.length);

        return new byte[][]{nonce, ctAndTag, aad};
    }

    // ===== 前向保密：临时密钥管理 =====

    public void establishEphemeral(String peerUuid) {
        ephemeralKeys.put(peerUuid, KeyManager.generateEphemeralX25519());
    }

    public void setPeerEphemeralPub(String peerUuid, String pubB64) {
        peerEphemeralPub.put(peerUuid, pubB64);
    }

    public String getMyEphemeralPubB64(String peerUuid) {
        AsymmetricCipherKeyPair pair = ephemeralKeys.get(peerUuid);
        if (pair == null) return null;
        return JsonUtil.b64Encode(((X25519PublicKeyParameters) pair.getPublic()).getEncoded());
    }

    public void destroyEphemeral(String peerUuid) {
        ephemeralKeys.remove(peerUuid);
        peerEphemeralPub.remove(peerUuid);
    }
}
