package com.spider.minecraft.uuid;

import com.spider.minecraft.SpiderMinecraft;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.UUID;

/**
 * UUIDv1 生成器 — 强制绑定真实 MAC 地址。
 *
 * <p>对齐 Spider 经典客户端 client/utils/uuidgen.py 的实现：
 * <ul>
 *   <li>{@link #getRealMac()} — 获取本机真实物理 MAC 地址，无回退</li>
 *   <li>{@link #generateUuidV1()} — 生成 UUIDv1，将真实 MAC 强制写入 node 字段</li>
 * </ul>
 *
 * <p>UUIDv1 结构：
 * <pre>
 *   time_low (32) | time_mid (16) | time_hi+version (16) |
 *   variant+clock_seq (16) | node (48 = MAC address)
 * </pre>
 *
 * <p>使用真实 MAC 确保身份永久固定 — 重装模组后 UUID 不变，
 * 为接入 Spider 用户数据库和权限系统奠定基础。
 */
public final class UuidGenerator {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);
    private static final SecureRandom RANDOM = new SecureRandom();

    private UuidGenerator() {}

    /**
     * 获取本机真实物理 MAC 地址。
     *
     * <p>对齐 Spider 的 get_real_mac()：遍历所有网络接口，
     * 跳过回环、虚拟、隧道接口，返回第一个真实物理接口的 MAC。
     * 无回退 — 如果找不到真实 MAC，抛出异常。
     *
     * @return MAC 地址作为 48 位整数
     * @throws IllegalStateException 如果找不到真实 MAC 地址
     */
    public static long getRealMac() {
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();

                // 跳过回环、虚拟、未启用接口
                if (iface.isLoopback() || iface.isVirtual() || !iface.isUp()) {
                    continue;
                }

                // 跳过常见虚拟/隧道接口
                String name = iface.getName().toLowerCase();
                String displayName = iface.getDisplayName().toLowerCase();
                if (name.startsWith("lo") || name.startsWith("docker") ||
                    name.startsWith("veth") || name.startsWith("br-") ||
                    name.startsWith("virbr") || name.startsWith("tun") ||
                    name.startsWith("tap") || name.startsWith("vmnet") ||
                    name.startsWith("vboxnet") || name.startsWith("wg") ||
                    displayName.contains("virtual") || displayName.contains("loopback") ||
                    displayName.contains("pseudo") || displayName.contains("miniport")) {
                    continue;
                }

                byte[] mac = iface.getHardwareAddress();
                if (mac != null && mac.length == 6) {
                    // 检查是否为全零或广播 MAC
                    boolean allZero = true;
                    for (byte b : mac) {
                        if (b != 0) { allZero = false; break; }
                    }
                    if (allZero) continue;

                    long macLong = 0;
                    for (byte b : mac) {
                        macLong = (macLong << 8) | (b & 0xFF);
                    }

                    LOGGER.info("[SpiderMinecraft] Real MAC found: {} ({})",
                            formatMac(mac), iface.getName());
                    return macLong;
                }
            }
        } catch (SocketException e) {
            throw new IllegalStateException("Failed to enumerate network interfaces", e);
        }

        throw new IllegalStateException(
                "No real physical MAC address found. SpiderMinecraft requires a real MAC " +
                "for UUIDv1 identity (matching Spider client behavior).");
    }

    /**
     * 生成 UUIDv1，将真实 MAC 地址强制写入 node 字段。
     *
     * <p>对齐 Spider 的 generate_uuid_v1()：
     * <ul>
     *   <li>时间戳：自 1582-10-15 00:00:00 起的 100ns 间隔数</li>
     *   <li>版本：4 位版本号 = 1 (time-based)</li>
     *   <li>变体：2 位 = 10 (RFC 4122)</li>
     *   <li>时钟序列：14 位随机数</li>
     *   <li>节点：48 位真实 MAC 地址</li>
     * </ul>
     *
     * @return UUIDv1 字符串
     */
    public static String generateUuidV1() {
        long mac = getRealMac();

        // 获取当前时间戳（100ns 间隔，自 1582-10-15）
        // UUID 纪元偏移：100ns 间隔数从 1582-10-15 到 1970-01-01
        final long NUM_100NS_INTERVALS_SINCE_UUID_EPOCH = 0x01b21dd213814000L;
        long now = System.currentTimeMillis();
        long timestamp = (now * 10000) + NUM_100NS_INTERVALS_SINCE_UUID_EPOCH;

        // 时间戳低 32 位
        long timeLow = timestamp & 0xFFFFFFFFL;
        // 时间戳中 16 位
        long timeMid = (timestamp >> 32) & 0xFFFFL;
        // 时间戳高 12 位 + 版本号 (0001)
        long timeHiAndVersion = ((timestamp >> 48) & 0x0FFFL) | 0x1000L;

        // 时钟序列：14 位随机数 + 变体 (10)
        int clockSeq = RANDOM.nextInt(0x4000); // 0-16383
        long variantAndClockSeq = (long) (clockSeq | 0x8000); // 设置变体位

        // 组合 most significant bits
        long msb = (timeLow << 32) | (timeMid << 16) | timeHiAndVersion;
        // 组合 least significant bits: variant+clockseq (16) | node (48)
        long lsb = (variantAndClockSeq << 48) | (mac & 0xFFFFFFFFFFFFL);

        UUID uuid = new UUID(msb, lsb);
        String uuidStr = uuid.toString();

        LOGGER.info("[SpiderMinecraft] Generated UUIDv1: {} (MAC-bound, permanent)", uuidStr);
        return uuidStr;
    }

    /**
     * 格式化 MAC 地址为 AA:BB:CC:DD:EE:FF 字符串。
     */
    private static String formatMac(byte[] mac) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", mac[i]));
        }
        return sb.toString();
    }
}
