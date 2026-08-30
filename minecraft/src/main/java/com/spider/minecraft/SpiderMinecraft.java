package com.spider.minecraft;

/**
 * SpiderMinecraft — 全局常量与协议定义。
 *
 * <p>Spider 官方通信网络在 Minecraft 世界中的投射。
 * 纯新增模组，不修改任何 Minecraft 已有类。所有交互通过聊天框命令完成。
 *
 * <p>与 Spider 经典客户端完全对齐：
 * <ul>
 *   <li>身份：UUIDv1 绑定真实 MAC 地址（永久固定）</li>
 *   <li>协议：Spider 标准信令（REGISTER/LOGIN/SEND_MSG/RECV_MSG/回执/COMPROMISED/OFFLINE_QUEUE）</li>
 *   <li>加密：X25519 ECDH + AES-256-GCM + Ed25519 签名 + TransportEncryptor 全包加密</li>
 *   <li>存储：SQLite 持久化（消息/用户/离线队列）</li>
 *   <li>安全：胁迫 PIN + wipe_all_data + 阅后即焚（每人开关）</li>
 *   <li>文件：加密文件传输（saves/SpiderFiles/）</li>
 * </ul>
 */
public final class SpiderMinecraft {

    private SpiderMinecraft() {}

    // ===== 模组标识 =====
    public static final String MOD_ID = "spiderminecraft";
    public static final String MOD_NAME = "SpiderMinecraft";
    public static final String MOD_VERSION = "2.0.0";
    public static final String PROTOCOL_VERSION = "spider/2.0";

    // ===== 网络通道 =====
    public static final String CHANNEL_NAME = "spiderminecraft:main";
    public static final int PROTOCOL_VERSION_INT = 2;

    // ===== 服务发现 (UDP) =====
    public static final String DISCOVERY_MULTICAST_ADDR = "239.255.42.99";
    public static final int DISCOVERY_PORT = 42999;
    public static final long DISCOVERY_BROADCAST_INTERVAL_MS = 3000L;
    public static final long DISCOVERY_ENTRY_TTL_MS = 15000L;

    // ===== 直连 (TCP) — Spider 标准端口 =====
    public static final int DIRECT_TCP_PORT = 42998;
    public static final int DIRECT_CONNECT_TIMEOUT_MS = 5000;
    public static final int DIRECT_READ_TIMEOUT_MS = 60000;

    // ===== 传输加密 =====
    public static final int TRANSPORT_KEY_ROTATION_SEC = 3600; // 每小时轮换
    public static final String TRANSPORT_CONTEXT = "spider-transport-v1";

    // ===== 加密上下文 =====
    public static final String CRYPTO_CONTEXT_MSG = "spider-msg-v1";
    public static final String CRYPTO_CONTEXT_FILE = "spider-file-v1";
    public static final String CRYPTO_CONTEXT_HANDSHAKE = "spider-handshake-v1";
    public static final int AES_KEY_LENGTH_BYTES = 32;
    public static final int GCM_NONCE_LENGTH_BYTES = 12;
    public static final int GCM_TAG_LENGTH_BITS = 128;

    // ===== 命令 =====
    public static final String CMD_ROOT = "spiderminecraft";

    // ===== 身份文件 =====
    public static final String IDENTITY_DIR = "spiderminecraft";
    public static final String IDENTITY_FILE = "identity.json";
    public static final String DATA_DIR = "spider_data";
    public static final String DB_FILE = "spider_data.db";
    public static final String FILES_DIR = "SpiderFiles";

    // ===== PIN 策略 =====
    // PIN 长度：默认 8 位，可选 10/12/16 位
    public static final int DEFAULT_PIN_LENGTH = 8;
    public static final int[] VALID_PIN_LENGTHS = {8, 10, 12, 16};
    // 保留旧常量名以兼容（指向默认值）
    public static final int DURESS_PIN_LENGTH = DEFAULT_PIN_LENGTH;

    // ===== 阅后即焚 =====
    public static final String BURN_FLAG = "expire_after_read";

    // ===== 节点类型 =====
    public static final String NODE_MC_CLIENT = "mc_client";
    public static final String NODE_MC_SERVER = "mc_server";
    public static final String NODE_NORMAL_CLIENT = "normal_client";
    public static final String NODE_NORMAL_SERVER = "normal_server";
}
