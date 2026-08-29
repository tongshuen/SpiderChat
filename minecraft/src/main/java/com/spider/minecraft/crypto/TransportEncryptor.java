package com.spider.minecraft.crypto;

import com.spider.minecraft.SpiderMinecraft;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 传输加密器 — 对齐 Spider 的 TransportEncryptor。
 *
 * <p>对 TCP 链路进行全包加密（不仅仅是消息负载），实现前向保密（PFS）。
 *
 * <p>握手流程：
 * <ol>
 *   <li>发起方生成临时 X25519 密钥对，发送公钥</li>
 *   <li>接收方生成临时 X25519 密钥对，发送公钥</li>
 *   <li>双方 ECDH 派生共享密钥，HKDF 派生 AES-256 密钥</li>
 *   <li>后续所有数据使用 AES-256-GCM 全包加密</li>
 *   <li>定期（默认每小时）轮换密钥：生成新临时密钥对，ECDH 派生新密钥</li>
 * </ol>
 *
 * <p>即使攻击者抓取了网络流量并 later 获取了长期密钥，也无法破译历史通信。
 */
public class TransportEncryptor {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final boolean isInitiator;
    private X25519PrivateKeyParameters ephemeralPriv;
    private X25519PublicKeyParameters ephemeralPub;
    private byte[] transportKey;
    private long lastRotationTime;
    private volatile boolean established = false;

    // 帧格式：[4字节长度][nonce(12)][密文+tag(16)]
    private static final int NONCE_SIZE = SpiderMinecraft.GCM_NONCE_LENGTH_BYTES;

    public TransportEncryptor(boolean isInitiator) {
        this.isInitiator = isInitiator;
        this.lastRotationTime = System.currentTimeMillis() / 1000;
    }

    /**
     * 发起方：生成临时密钥对并发送公钥，然后接收对方公钥。
     */
    public void handshakeInitiator(Socket socket) throws IOException {
        // 生成临时密钥对
        AsymmetricCipherKeyPair pair = KeyManager.generateEphemeralX25519();
        ephemeralPriv = (X25519PrivateKeyParameters) pair.getPrivate();
        ephemeralPub = (X25519PublicKeyParameters) pair.getPublic();

        DataOutputStream out = new DataOutputStream(socket.getOutputStream());
        DataInputStream in = new DataInputStream(socket.getInputStream());

        // 发送公钥（32字节）
        byte[] pubBytes = ephemeralPub.getEncoded();
        out.writeInt(pubBytes.length);
        out.write(pubBytes);
        out.flush();

        // 接收对方公钥
        int peerLen = in.readInt();
        byte[] peerPubBytes = new byte[peerLen];
        in.readFully(peerPubBytes);
        X25519PublicKeyParameters peerPub = new X25519PublicKeyParameters(peerPubBytes, 0);

        // ECDH + HKDF
        byte[] shared = KeyManager.ecdh(ephemeralPriv, peerPub);
        transportKey = KeyManager.hkdf(shared, null,
                SpiderMinecraft.TRANSPORT_CONTEXT.getBytes(),
                SpiderMinecraft.AES_KEY_LENGTH_BYTES);

        established = true;
        lastRotationTime = System.currentTimeMillis() / 1000;
        LOGGER.info("[SpiderMinecraft] Transport encryption established (initiator)");
    }

    /**
     * 接收方：接收发起方公钥，生成自己的临时密钥对，发送公钥。
     */
    public void handshakeResponder(Socket socket) throws IOException {
        DataInputStream in = new DataInputStream(socket.getInputStream());
        DataOutputStream out = new DataOutputStream(socket.getOutputStream());

        // 接收发起方公钥
        int peerLen = in.readInt();
        byte[] peerPubBytes = new byte[peerLen];
        in.readFully(peerPubBytes);
        X25519PublicKeyParameters peerPub = new X25519PublicKeyParameters(peerPubBytes, 0);

        // 生成临时密钥对
        AsymmetricCipherKeyPair pair = KeyManager.generateEphemeralX25519();
        ephemeralPriv = (X25519PrivateKeyParameters) pair.getPrivate();
        ephemeralPub = (X25519PublicKeyParameters) pair.getPublic();

        // 发送公钥
        byte[] pubBytes = ephemeralPub.getEncoded();
        out.writeInt(pubBytes.length);
        out.write(pubBytes);
        out.flush();

        // ECDH + HKDF
        byte[] shared = KeyManager.ecdh(ephemeralPriv, peerPub);
        transportKey = KeyManager.hkdf(shared, null,
                SpiderMinecraft.TRANSPORT_CONTEXT.getBytes(),
                SpiderMinecraft.AES_KEY_LENGTH_BYTES);

        established = true;
        lastRotationTime = System.currentTimeMillis() / 1000;
        LOGGER.info("[SpiderMinecraft] Transport encryption established (responder)");
    }

    /**
     * 加密并发送一帧数据。
     */
    public void sendEncrypted(DataOutputStream out, byte[] plaintext) throws IOException {
        if (!established) throw new IllegalStateException("Transport not established");

        byte[] encrypted = KeyManager.aesGcmEncryptRaw(transportKey, plaintext);
        out.writeInt(encrypted.length);
        out.write(encrypted);
        out.flush();
    }

    /**
     * 接收并解密一帧数据。
     */
    public byte[] recvEncrypted(DataInputStream in) throws IOException {
        if (!established) throw new IllegalStateException("Transport not established");

        int len = in.readInt();
        byte[] encrypted = new byte[len];
        in.readFully(encrypted);
        return KeyManager.aesGcmDecryptRaw(transportKey, encrypted);
    }

    /**
     * 密钥轮换 — 生成新临时密钥对，ECDH 派生新密钥。
     * 对齐 Spider 的 rotate_key()。
     */
    public void rotateKey(DataOutputStream out, DataInputStream in) throws IOException {
        if (!established) throw new IllegalStateException("Transport not established");

        // 生成新临时密钥对
        AsymmetricCipherKeyPair newPair = KeyManager.generateEphemeralX25519();
        X25519PrivateKeyParameters newPriv = (X25519PrivateKeyParameters) newPair.getPrivate();
        X25519PublicKeyParameters newPub = (X25519PublicKeyParameters) newPair.getPublic();

        if (isInitiator) {
            // 发起方先发
            byte[] pubBytes = newPub.getEncoded();
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.flush();

            int peerLen = in.readInt();
            byte[] peerPubBytes = new byte[peerLen];
            in.readFully(peerPubBytes);
            X25519PublicKeyParameters peerPub = new X25519PublicKeyParameters(peerPubBytes, 0);

            byte[] shared = KeyManager.ecdh(newPriv, peerPub);
            transportKey = KeyManager.hkdf(shared, null,
                    (SpiderMinecraft.TRANSPORT_CONTEXT + "-rotate").getBytes(),
                    SpiderMinecraft.AES_KEY_LENGTH_BYTES);
        } else {
            // 接收方先收
            int peerLen = in.readInt();
            byte[] peerPubBytes = new byte[peerLen];
            in.readFully(peerPubBytes);
            X25519PublicKeyParameters peerPub = new X25519PublicKeyParameters(peerPubBytes, 0);

            byte[] pubBytes = newPub.getEncoded();
            out.writeInt(pubBytes.length);
            out.write(pubBytes);
            out.flush();

            byte[] shared = KeyManager.ecdh(newPriv, peerPub);
            transportKey = KeyManager.hkdf(shared, null,
                    (SpiderMinecraft.TRANSPORT_CONTEXT + "-rotate").getBytes(),
                    SpiderMinecraft.AES_KEY_LENGTH_BYTES);
        }

        ephemeralPriv = newPriv;
        ephemeralPub = newPub;
        lastRotationTime = System.currentTimeMillis() / 1000;
        LOGGER.info("[SpiderMinecraft] Transport key rotated");
    }

    /**
     * 检查是否应该轮换密钥。
     */
    public boolean shouldRotate(int rotationSec) {
        if (!established) return false;
        long now = System.currentTimeMillis() / 1000;
        return (now - lastRotationTime) >= rotationSec;
    }

    public boolean isEstablished() {
        return established;
    }

    public void close() {
        if (transportKey != null) {
            Arrays.fill(transportKey, (byte) 0);
        }
        established = false;
    }
}
