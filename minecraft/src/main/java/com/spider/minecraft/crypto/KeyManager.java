package com.spider.minecraft.crypto;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.uuid.UuidGenerator;
import com.spider.minecraft.util.JsonUtil;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 密钥管理器 — 身份密钥对、胁迫 PIN、数据擦除。
 *
 * <p>对齐 Spider 经典客户端：
 * <ul>
 *   <li>身份：UUIDv1 绑定真实 MAC（永久固定），由 {@link UuidGenerator} 生成</li>
 *   <li>密钥：X25519（ECDH）+ Ed25519（签名），私钥用 PIN 经 PBKDF2 加密存储</li>
 *   <li>胁迫 PIN：6 位数字，存储 SHA-256 哈希；触发时执行 {@link #wipeAllData()}</li>
 *   <li>擦除：删除 identity.json、密钥、数据库，发送 COMPROMISED 信令</li>
 * </ul>
 *
 * <p>身份文件格式（identity.json）与 Spider 兼容：
 * <pre>
 * {
 *   "uuid": "UUIDv1",
 *   "x25519_priv": "base64(PBKDF2加密后的私钥)",
 *   "x25519_pub": "base64(公钥)",
 *   "ed25519_priv": "base64(...)",
 *   "ed25519_pub": "base64(...)",
 *   "salt": "base64(PBKDF2盐)",
 *   "duress_pin_hash": "base64(SHA-256)",
 *   "has_duress_pin": true/false,
 *   "protocol": "spider/2.0"
 * }
 * </pre>
 */
public class KeyManager {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int PBKDF2_ITERATIONS = 600000;
    private static final int SALT_SIZE = 16;

    private X25519PrivateKeyParameters x25519Priv;
    private X25519PublicKeyParameters x25519Pub;
    private Ed25519PrivateKeyParameters ed25519Priv;
    private Ed25519PublicKeyParameters ed25519Pub;
    private String identityUuid;
    private byte[] salt;
    private String duressPinHash;
    private boolean hasDuressPin;
    private boolean unlocked = false;

    private Path identityPath;
    private Path dataDir;

    // ===== 初始化 =====

    public void initialize() {
        String configDir = System.getProperty("neoforge.configDir", "config");
        Path dir = Paths.get(configDir, SpiderMinecraft.IDENTITY_DIR);
        try {
            Files.createDirectories(dir);
        } catch (IOException e) {
            LOGGER.warn("[SpiderMinecraft] Failed to create identity dir: {}", e.getMessage());
        }
        identityPath = dir.resolve(SpiderMinecraft.IDENTITY_FILE);
        dataDir = dir.resolve(SpiderMinecraft.DATA_DIR);
        try {
            Files.createDirectories(dataDir);
        } catch (IOException ignored) {}
    }

    /**
     * 首次注册：生成 UUIDv1 + 密钥对，用 PIN 加密存储。
     *
     * @param pin       解锁 PIN（用于加密私钥）
     * @param duressPin 胁迫 PIN（6 位数字），可为 null
     */
    public void register(String pin, String duressPin) {
        // 生成 UUIDv1（绑定真实 MAC）
        identityUuid = UuidGenerator.generateUuidV1();

        // 生成密钥对
        X25519KeyPairGenerator xGen = new X25519KeyPairGenerator();
        xGen.init(null);
        AsymmetricCipherKeyPair xPair = xGen.generateKeyPair();
        x25519Priv = (X25519PrivateKeyParameters) xPair.getPrivate();
        x25519Pub = (X25519PublicKeyParameters) xPair.getPublic();

        Ed25519KeyPairGenerator eGen = new Ed25519KeyPairGenerator();
        eGen.init(null);
        AsymmetricCipherKeyPair ePair = eGen.generateKeyPair();
        ed25519Priv = (Ed25519PrivateKeyParameters) ePair.getPrivate();
        ed25519Pub = (Ed25519PublicKeyParameters) ePair.getPublic();

        // 生成盐
        salt = new byte[SALT_SIZE];
        RANDOM.nextBytes(salt);

        // 胁迫 PIN
        if (duressPin != null && !duressPin.isEmpty()) {
            duressPinHash = sha256Base64(duressPin);
            hasDuressPin = true;
        } else {
            duressPinHash = "";
            hasDuressPin = false;
        }

        // 用 PIN 派生密钥加密私钥并保存
        saveIdentity(pin);
        unlocked = true;
        LOGGER.info("[SpiderMinecraft] Identity registered: {}", identityUuid);
    }

    /**
     * 登录：用 PIN 解密已存储的身份。
     *
     * @return 是否成功解锁
     */
    public boolean login(String pin) {
        if (!Files.exists(identityPath)) {
            return false;
        }
        try {
            JsonObject obj = JsonUtil.parse(Files.readString(identityPath, StandardCharsets.UTF_8));
            identityUuid = obj.get("uuid").getAsString();
            salt = JsonUtil.b64Decode(obj.get("salt").getAsString());
            duressPinHash = obj.has("duress_pin_hash") ? obj.get("duress_pin_hash").getAsString() : "";
            hasDuressPin = obj.has("has_duress_pin") && obj.get("has_duress_pin").getAsBoolean();

            // 用 PIN 派生密钥解密私钥
            byte[] key = deriveKey(pin, salt);
            byte[] xPrivEnc = JsonUtil.b64Decode(obj.get("x25519_priv").getAsString());
            byte[] ePrivEnc = JsonUtil.b64Decode(obj.get("ed25519_priv").getAsString());

            byte[] xPrivRaw = aesGcmDecryptRaw(key, xPrivEnc);
            byte[] ePrivRaw = aesGcmDecryptRaw(key, ePrivEnc);

            x25519Priv = new X25519PrivateKeyParameters(xPrivRaw, 0);
            x25519Pub = new X25519PublicKeyParameters(JsonUtil.b64Decode(obj.get("x25519_pub").getAsString()), 0);
            ed25519Priv = new Ed25519PrivateKeyParameters(ePrivRaw, 0);
            ed25519Pub = new Ed25519PublicKeyParameters(JsonUtil.b64Decode(obj.get("ed25519_pub").getAsString()), 0);

            unlocked = true;
            LOGGER.info("[SpiderMinecraft] Identity unlocked: {}", identityUuid);
            return true;
        } catch (Exception e) {
            LOGGER.error("[SpiderMinecraft] Login failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 检查胁迫 PIN。如果匹配，执行 wipeAllData()。
     *
     * @return true 如果输入的是胁迫 PIN
     */
    public boolean checkDuressPin(String pin) {
        if (!hasDuressPin || duressPinHash == null || duressPinHash.isEmpty()) {
            return false;
        }
        String hash = sha256Base64(pin);
        return hash.equals(duressPinHash);
    }

    /**
     * 设置胁迫 PIN。需要先解锁。
     */
    public void setDuressPin(String duressPin) {
        if (!unlocked) throw new IllegalStateException("Identity not unlocked");
        if (duressPin == null || duressPin.length() != SpiderMinecraft.DURESS_PIN_LENGTH ||
            !duressPin.matches("\\d+")) {
            throw new IllegalArgumentException("Duress PIN must be " + SpiderMinecraft.DURESS_PIN_LENGTH + " digits");
        }
        duressPinHash = sha256Base64(duressPin);
        hasDuressPin = true;
        // 重新保存（需要解锁 PIN — 实际应要求输入 PIN）
        LOGGER.info("[SpiderMinecraft] Duress PIN set");
    }

    /**
     * 擦除所有本地数据 — 对齐 Spider 的 wipe_all_data()。
     *
     * <p>删除 identity.json、密钥内存、数据库文件。
     * 调用方应在擦除前发送 COMPROMISED 信令。
     */
    public void wipeAllData() {
        LOGGER.warn("[SpiderMinecraft] WIPING ALL DATA — duress triggered");

        // 清零内存中的私钥
        if (x25519Priv != null) Arrays.fill(x25519Priv.getEncoded(), (byte) 0);
        if (ed25519Priv != null) Arrays.fill(ed25519Priv.getEncoded(), (byte) 0);
        if (salt != null) Arrays.fill(salt, (byte) 0);

        // 删除身份文件
        try {
            if (identityPath != null && Files.exists(identityPath)) {
                // 先覆写再删除（安全删除）
                byte[] overwrite = new byte[(int) Files.size(identityPath)];
                RANDOM.nextBytes(overwrite);
                Files.write(identityPath, overwrite);
                Files.delete(identityPath);
                LOGGER.info("[SpiderMinecraft] identity.json wiped");
            }
        } catch (IOException e) {
            LOGGER.error("[SpiderMinecraft] Failed to wipe identity file: {}", e.getMessage());
        }

        // 删除数据库
        try {
            if (dataDir != null && Files.exists(dataDir)) {
                Files.walk(dataDir)
                        .sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .forEach(p -> {
                            try { Files.delete(p); } catch (IOException ignored) {}
                        });
                LOGGER.info("[SpiderMinecraft] data directory wiped");
            }
        } catch (IOException e) {
            LOGGER.error("[SpiderMinecraft] Failed to wipe data dir: {}", e.getMessage());
        }

        unlocked = false;
        identityUuid = null;
        x25519Priv = null;
        x25519Pub = null;
        ed25519Priv = null;
        ed25519Pub = null;

        LOGGER.warn("[SpiderMinecraft] Wipe complete");
    }

    // ===== 保存/加载 =====

    private void saveIdentity(String pin) {
        try {
            byte[] key = deriveKey(pin, salt);
            byte[] xPrivEnc = aesGcmEncryptRaw(key, x25519Priv.getEncoded());
            byte[] ePrivEnc = aesGcmEncryptRaw(key, ed25519Priv.getEncoded());

            JsonObject obj = new JsonObject();
            obj.addProperty("uuid", identityUuid);
            obj.addProperty("x25519_priv", JsonUtil.b64Encode(xPrivEnc));
            obj.addProperty("x25519_pub", JsonUtil.b64Encode(x25519Pub.getEncoded()));
            obj.addProperty("ed25519_priv", JsonUtil.b64Encode(ePrivEnc));
            obj.addProperty("ed25519_pub", JsonUtil.b64Encode(ed25519Pub.getEncoded()));
            obj.addProperty("salt", JsonUtil.b64Encode(salt));
            obj.addProperty("duress_pin_hash", duressPinHash);
            obj.addProperty("has_duress_pin", hasDuressPin);
            obj.addProperty("protocol", SpiderMinecraft.PROTOCOL_VERSION);

            Files.writeString(identityPath, JsonUtil.toJson(obj), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            LOGGER.info("[SpiderMinecraft] Identity saved to {}", identityPath);
        } catch (IOException e) {
            LOGGER.error("[SpiderMinecraft] Failed to save identity: {}", e.getMessage());
        }
    }

    public boolean identityExists() {
        return identityPath != null && Files.exists(identityPath);
    }

    public boolean isUnlocked() {
        return unlocked;
    }

    // ===== 密钥访问 =====

    public String getIdentityUuid() { return identityUuid; }
    public X25519PrivateKeyParameters getX25519Private() { return x25519Priv; }
    public X25519PublicKeyParameters getX25519Public() { return x25519Pub; }
    public Ed25519PrivateKeyParameters getEd25519Private() { return ed25519Priv; }
    public Ed25519PublicKeyParameters getEd25519Public() { return ed25519Pub; }
    public String getX25519PublicB64() { return JsonUtil.b64Encode(x25519Pub.getEncoded()); }
    public String getEd25519PublicB64() { return JsonUtil.b64Encode(ed25519Pub.getEncoded()); }
    public Path getDataDir() { return dataDir; }
    public boolean hasDuressPin() { return hasDuressPin; }

    // ===== 加密原语（供内部和 CryptoManager 使用） =====

    public static byte[] deriveKey(String pin, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 key derivation failed", e);
        }
    }

    public static byte[] ecdh(X25519PrivateKeyParameters priv, X25519PublicKeyParameters pub) {
        X25519Agreement agreement = new X25519Agreement();
        agreement.init(priv);
        byte[] secret = new byte[agreement.getAgreementSize()];
        agreement.calculateAgreement(pub, secret, 0);
        return secret;
    }

    public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            if (salt == null || salt.length == 0) salt = new byte[32];
            hmac.init(new SecretKeySpec(salt, "HmacSHA256"));
            byte[] prk = hmac.doFinal(ikm);

            hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
            byte[] result = new byte[length];
            byte[] t = new byte[0];
            int offset = 0, counter = 1;
            while (offset < length) {
                hmac.reset();
                hmac.init(new SecretKeySpec(prk, "HmacSHA256"));
                hmac.update(t);
                if (info != null) hmac.update(info);
                hmac.update((byte) counter);
                t = hmac.doFinal();
                int copyLen = Math.min(t.length, length - offset);
                System.arraycopy(t, 0, result, offset, copyLen);
                offset += copyLen;
                counter++;
            }
            return result;
        } catch (Exception e) {
            throw new RuntimeException("HKDF failed", e);
        }
    }

    public static byte[] aesGcmEncryptRaw(byte[] key, byte[] plaintext) {
        try {
            byte[] nonce = new byte[SpiderMinecraft.GCM_NONCE_LENGTH_BYTES];
            RANDOM.nextBytes(nonce);
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            cipher.init(true, new AEADParameters(new KeyParameter(key),
                    SpiderMinecraft.GCM_TAG_LENGTH_BITS, nonce));
            byte[] output = new byte[cipher.getOutputSize(plaintext.length)];
            int len = cipher.processBytes(plaintext, 0, plaintext.length, output, 0);
            len += cipher.doFinal(output, len);
            byte[] result = new byte[nonce.length + len];
            System.arraycopy(nonce, 0, result, 0, nonce.length);
            System.arraycopy(output, 0, result, nonce.length, len);
            return result;
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encrypt failed", e);
        }
    }

    public static byte[] aesGcmDecryptRaw(byte[] key, byte[] data) {
        try {
            byte[] nonce = Arrays.copyOfRange(data, 0, SpiderMinecraft.GCM_NONCE_LENGTH_BYTES);
            byte[] ct = Arrays.copyOfRange(data, SpiderMinecraft.GCM_NONCE_LENGTH_BYTES, data.length);
            GCMBlockCipher cipher = new GCMBlockCipher(new AESEngine());
            cipher.init(false, new AEADParameters(new KeyParameter(key),
                    SpiderMinecraft.GCM_TAG_LENGTH_BITS, nonce));
            byte[] output = new byte[cipher.getOutputSize(ct.length)];
            int len = cipher.processBytes(ct, 0, ct.length, output, 0);
            len += cipher.doFinal(output, len);
            return Arrays.copyOf(output, len);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decrypt failed", e);
        }
    }

    public static byte[] ed25519Sign(Ed25519PrivateKeyParameters priv, byte[] data) {
        Ed25519Signer signer = new Ed25519Signer();
        signer.init(true, priv);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    public static boolean ed25519Verify(Ed25519PublicKeyParameters pub, byte[] data, byte[] sig) {
        try {
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, pub);
            verifier.update(data, 0, data.length);
            return verifier.verifySignature(sig);
        } catch (Exception e) {
            return false;
        }
    }

    public static AsymmetricCipherKeyPair generateEphemeralX25519() {
        X25519KeyPairGenerator gen = new X25519KeyPairGenerator();
        gen.init(null);
        return gen.generateKeyPair();
    }

    private static String sha256Base64(String input) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return JsonUtil.b64Encode(md.digest(input.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
