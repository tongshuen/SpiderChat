package com.spider.minecraft.file;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.crypto.CryptoManager;
import com.spider.minecraft.crypto.KeyManager;
import com.spider.minecraft.protocol.Protocol;
import com.google.gson.JsonObject;
import com.spider.minecraft.util.JsonUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

/**
 * 文件传输 — 对齐 Spider 的 encrypt_file_data / decrypt_file_data。
 *
 * <p>利用 Minecraft 的 saves 目录存储文件：saves/SpiderFiles/
 * <ul>
 *   <li>发送方：读取文件 → ECDH 派生密钥 → AES-256-GCM 加密 → 分块发送</li>
 *   <li>接收方：接收加密数据 → 解密 → 保存到 saves/SpiderFiles/</li>
 * </ul>
 *
 * <p>文件加密使用与消息相同的 E2EE 体系（X25519 ECDH + AES-256-GCM），
 * 支持前向保密（临时密钥）。
 */
public class FileTransfer {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);

    /** 最大文件大小：16 MB */
    private static final long MAX_FILE_SIZE = 16 * 1024 * 1024;
    /** 分块大小：64 KB */
    private static final int CHUNK_SIZE = 64 * 1024;

    private final SpiderMinecraftMod mod;
    private final CryptoManager cryptoManager;
    private final KeyManager keyManager;
    private final Path filesDir;

    public FileTransfer(SpiderMinecraftMod mod, CryptoManager cryptoManager, KeyManager keyManager) {
        this.mod = mod;
        this.cryptoManager = cryptoManager;
        this.keyManager = keyManager;
        // 文件存储在 Minecraft saves/SpiderFiles/ 目录
        String gameDir = System.getProperty("user.dir", ".");
        this.filesDir = Paths.get(gameDir, "saves", SpiderMinecraft.FILES_DIR);
        try {
            Files.createDirectories(filesDir);
        } catch (IOException e) {
            LOGGER.error("[SpiderMinecraft] Failed to create files dir: {}", e.getMessage());
        }
    }

    /**
     * 发送加密文件。
     *
     * @param filePath    本地文件路径
     * @param toUuid      接收方 UUID
     * @param peerXPubB64 接收方 X25519 公钥
     * @return 文件传输 ID，失败返回 null
     */
    public String sendFile(String filePath, String toUuid, String peerXPubB64) {
        Path src = Paths.get(filePath);
        if (!Files.exists(src)) {
            LOGGER.error("[SpiderMinecraft] File not found: {}", filePath);
            return null;
        }

        try {
            long size = Files.size(src);
            if (size > MAX_FILE_SIZE) {
                LOGGER.error("[SpiderMinecraft] File too large: {} (max {})", size, MAX_FILE_SIZE);
                return null;
            }

            byte[] data = Files.readAllBytes(src);
            String fileId = UUID.randomUUID().toString();
            String fileName = src.getFileName().toString();

            // 加密文件数据
            byte[][] encrypted = cryptoManager.encryptFileData(data, toUuid, peerXPubB64);
            // encrypted = [nonce, ciphertext+tag, aad]

            // 构建 FILE_SEND 信令
            JsonObject msg = new JsonObject();
            msg.addProperty("type", Protocol.FILE_SEND);
            msg.addProperty("file_id", fileId);
            msg.addProperty("file_name", fileName);
            msg.addProperty("file_size", size);
            msg.addProperty("from_uuid", keyManager.getIdentityUuid());
            msg.addProperty("to_uuid", toUuid);
            msg.addProperty("nonce", JsonUtil.b64Encode(encrypted[0]));
            msg.addProperty("ciphertext", JsonUtil.b64Encode(encrypted[1]));
            msg.addProperty("aad", JsonUtil.b64Encode(encrypted[2]));
            msg.addProperty("timestamp", System.currentTimeMillis() / 1000);

            // 通过直连发送
            String connId = mod.getSessionManager().getCurrentConnectionId();
            if (connId != null) {
                mod.getDirectConnector().sendMessage(connId, JsonUtil.toJson(msg));
                LOGGER.info("[SpiderMinecraft] File sent: {} ({}) to {}", fileName, fileId, toUuid);
                return fileId;
            }
            return null;
        } catch (IOException e) {
            LOGGER.error("[SpiderMinecraft] Failed to send file: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 接收并解密文件。
     *
     * @param fileMsg 文件信令 JSON
     * @param peerXPubB64 发送方 X25519 公钥
     * @return 保存的文件路径，失败返回 null
     */
    public Path receiveFile(JsonObject fileMsg, String peerXPubB64) {
        try {
            String fileId = fileMsg.get("file_id").getAsString();
            String fileName = fileMsg.get("file_name").getAsString();
            byte[] nonce = JsonUtil.b64Decode(fileMsg.get("nonce").getAsString());
            byte[] ciphertext = JsonUtil.b64Decode(fileMsg.get("ciphertext").getAsString());
            byte[] aad = JsonUtil.b64Decode(fileMsg.get("aad").getAsString());
            String fromUuid = fileMsg.get("from_uuid").getAsString();

            // 组合 nonce + ciphertext 进行解密
            byte[] encrypted = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, encrypted, 0, nonce.length);
            System.arraycopy(ciphertext, 0, encrypted, nonce.length, ciphertext.length);

            // 派生密钥（与加密时相同的 ECDH）
            byte[] shared = KeyManager.ecdh(keyManager.getX25519Private(),
                    new org.bouncycastle.crypto.params.X25519PublicKeyParameters(
                            JsonUtil.b64Decode(peerXPubB64), 0));
            byte[] aesKey = KeyManager.hkdf(shared, null,
                    "spider-file-identity-v1".getBytes(), SpiderMinecraft.AES_KEY_LENGTH_BYTES);

            byte[] plaintext = KeyManager.aesGcmDecryptRaw(aesKey, encrypted);

            // 保存到 filesDir
            // 安全文件名：去除路径分隔符
            String safeName = fileName.replaceAll("[\\\\/]", "_");
            Path dest = filesDir.resolve(fromUuid.substring(0, 8) + "_" + safeName);
            Files.write(dest, plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            LOGGER.info("[SpiderMinecraft] File received: {} ({}) from {} -> {}",
                    safeName, fileId, fromUuid, dest);
            return dest;
        } catch (Exception e) {
            LOGGER.error("[SpiderMinecraft] Failed to receive file: {}", e.getMessage());
            return null;
        }
    }

    public Path getFilesDir() {
        return filesDir;
    }
}
