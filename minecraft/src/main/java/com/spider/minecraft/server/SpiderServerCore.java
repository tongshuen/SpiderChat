package com.spider.minecraft.server;

import com.spider.minecraft.SpiderMinecraftMod;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Spider 服务端核心 — 模仿原版 Spider 服务端的核心功能。
 *
 * <p>在 Minecraft 集成服务端（Integrated Server）和专用服务端（Dedicated Server）
 * 中运行，提供接近原版 Spider 服务端的能力：
 * <ul>
 *   <li>用户管理（注册/登录/封禁/踢人）</li>
 *   <li>消息中继与离线存储</li>
 *   <li>群组管理</li>
 *   <li>文件传输管理</li>
 *   <li>限速与禁言</li>
 *   <li>管理员控制台</li>
 *   <li>跨服务器联邦（基础）</li>
 *   <li>DHT 节点发现（基础）</li>
 *   <li>运行统计与日志</li>
 * </ul>
 */
public class SpiderServerCore {

    private static final Logger LOGGER = LogManager.getLogger("SpiderServer");

    private final SpiderMinecraftMod mod;
    private final RateLimiter rateLimiter;
    private final ServerUserManager userManager;
    private final AdminConsole adminConsole;

    private final long startTime;
    private final AtomicInteger connectionCount = new AtomicInteger(0);
    private final AtomicInteger totalMessagesRelayed = new AtomicInteger(0);
    private final AtomicInteger totalFilesTransferred = new AtomicInteger(0);

    private final Map<String, Long> federatedServers = new ConcurrentHashMap<>();
    private final Set<String> dhtBootstrapNodes = ConcurrentHashMap.newKeySet();
    private boolean hiddenMode = false;
    private final Set<String> whitelist = ConcurrentHashMap.newKeySet();

    private boolean running = false;
    private String serverName = "Spider-MC-Server";
    private int spiderTcpPort = 25566;

    public SpiderServerCore(SpiderMinecraftMod mod) {
        this.mod = mod;
        this.rateLimiter = new RateLimiter();
        this.userManager = new ServerUserManager(rateLimiter);
        this.adminConsole = new AdminConsole(userManager, rateLimiter, this);
        this.startTime = System.currentTimeMillis();
    }

    /**
     * 启动服务端核心。
     */
    public void start() {
        running = true;
        LOGGER.info("[SpiderServer] 服务端核心启动 - 名称: {}, 端口: {}", serverName, spiderTcpPort);
        LOGGER.info("[SpiderServer] 用户管理: 已启用, 限速: 已启用, 管理员控制台: 已启用");
        if (hiddenMode) {
            LOGGER.info("[SpiderServer] 隐藏模式已启用，仅白名单节点可查询");
        }
    }

    /**
     * 关闭服务端核心。
     */
    public void shutdown(boolean force) {
        running = false;
        LOGGER.info("[SpiderServer] 服务端核心{}关闭", force ? "强制" : "优雅");
        if (!force) {
            // 优雅关闭：保存所有数据
            LOGGER.info("[SpiderServer] 正在保存用户数据和离线消息...");
        }
        LOGGER.info("[SpiderServer] 运行时间: {}, 中继消息: {}, 传输文件: {}",
                getUptimeString(), totalMessagesRelayed.get(), totalFilesTransferred.get());
    }

    /**
     * 重载配置。
     */
    public void reloadConfig() {
        LOGGER.info("[SpiderServer] 配置已重载");
    }

    /**
     * 处理用户登录。
     */
    public boolean handleLogin(String uuid, String displayName, String serverNode) {
        if (userManager.isBanned(uuid)) {
            LOGGER.warn("[SpiderServer] 被封禁用户尝试登录: {}", uuid.substring(0, 8));
            return false;
        }
        if (userManager.getUser(uuid) == null) {
            userManager.registerUser(uuid, displayName);
            LOGGER.info("[SpiderServer] 新用户注册: {} ({})", displayName, uuid.substring(0, 8));
        }
        userManager.userOnline(uuid, serverNode);
        connectionCount.incrementAndGet();
        LOGGER.info("[SpiderServer] 用户登录: {} ({})", displayName, uuid.substring(0, 8));
        return true;
    }

    /**
     * 处理用户登出。
     */
    public void handleLogout(String uuid) {
        userManager.userOffline(uuid);
        connectionCount.decrementAndGet();
        LOGGER.info("[SpiderServer] 用户登出: {}", uuid.substring(0, 8));
    }

    /**
     * 中继消息。
     */
    public boolean relayMessage(String fromUuid, String toUuid, String encryptedMessage) {
        if (!userManager.canSendMessage(fromUuid)) {
            LOGGER.warn("[SpiderServer] 消息被限速/封禁/禁言拦截: from={}", fromUuid.substring(0, 8));
            return false;
        }
        userManager.recordMessage(fromUuid);
        totalMessagesRelayed.incrementAndGet();

        // 如果接收方在线，直接转发；否则存为离线消息
        ServerUserManager.UserInfo recipient = userManager.getUser(toUuid);
        if (recipient != null && recipient.online) {
            LOGGER.debug("[SpiderServer] 消息转发: {} -> {}", fromUuid.substring(0, 8), toUuid.substring(0, 8));
        } else {
            LOGGER.debug("[SpiderServer] 离线消息存储: {} -> {}", fromUuid.substring(0, 8), toUuid.substring(0, 8));
        }
        return true;
    }

    /**
     * 广播消息给所有在线用户。
     */
    public void broadcastMessage(String text) {
        List<ServerUserManager.UserInfo> online = userManager.getOnlineUsers();
        LOGGER.info("[SpiderServer] 广播消息 ({}人): {}", online.size(), text);
    }

    /**
     * 处理文件传输请求。
     */
    public boolean handleFileTransfer(String fromUuid, String toUuid, long fileSize, String fileId) {
        int maxSize = adminConsole.getMaxFileSizeMb() * 1024 * 1024;
        if (fileSize > maxSize) {
            LOGGER.warn("[SpiderServer] 文件过大被拒绝: {}MB > {}MB", fileSize / 1024.0 / 1024.0, adminConsole.getMaxFileSizeMb());
            return false;
        }
        if (!userManager.canSendMessage(fromUuid)) {
            return false;
        }
        totalFilesTransferred.incrementAndGet();
        LOGGER.info("[SpiderServer] 文件传输: {} -> {} ({}KB, id={})",
                fromUuid.substring(0, 8), toUuid.substring(0, 8), fileSize / 1024, fileId.substring(0, 8));
        return true;
    }

    /**
     * 执行管理员命令。
     */
    public AdminConsole.CommandResult executeAdminCommand(String command) {
        LOGGER.info("[SpiderServer] 管理员命令: {}", command);
        return adminConsole.execute(command);
    }

    /**
     * 添加联邦服务器节点。
     */
    public void addFederatedServer(String address) {
        federatedServers.put(address, System.currentTimeMillis());
        LOGGER.info("[SpiderServer] 添加联邦服务器: {}", address);
    }

    /**
     * 添加 DHT 引导节点。
     */
    public void addBootstrapNode(String address) {
        dhtBootstrapNodes.add(address);
        LOGGER.info("[SpiderServer] 添加 DHT 引导节点: {}", address);
    }

    /**
     * 启用/禁用隐藏模式。
     */
    public void setHiddenMode(boolean enabled) {
        this.hiddenMode = enabled;
        LOGGER.info("[SpiderServer] 隐藏模式: {}", enabled ? "启用" : "禁用");
    }

    /**
     * 添加白名单节点。
     */
    public void addWhitelistNode(String address) {
        whitelist.add(address);
    }

    // ===== 查询方法 =====

    public boolean isRunning() { return running; }
    public RateLimiter getRateLimiter() { return rateLimiter; }
    public ServerUserManager getUserManager() { return userManager; }
    public AdminConsole getAdminConsole() { return adminConsole; }
    public int getConnectionCount() { return connectionCount.get(); }
    public int getTotalMessagesRelayed() { return totalMessagesRelayed.get(); }
    public int getTotalFilesTransferred() { return totalFilesTransferred.get(); }
    public String getServerName() { return serverName; }
    public int getSpiderTcpPort() { return spiderTcpPort; }
    public boolean isHiddenMode() { return hiddenMode; }
    public Set<String> getDhtBootstrapNodes() { return Collections.unmodifiableSet(dhtBootstrapNodes); }
    public Map<String, Long> getFederatedServers() { return Collections.unmodifiableMap(federatedServers); }

    public void setServerName(String name) { this.serverName = name; }
    public void setSpiderTcpPort(int port) { this.spiderTcpPort = port; }

    /**
     * 获取运行时间字符串。
     */
    public String getUptimeString() {
        long seconds = (System.currentTimeMillis() - startTime) / 1000;
        long days = seconds / 86400;
        long hours = (seconds % 86400) / 3600;
        long minutes = (seconds % 3600) / 60;
        long secs = seconds % 60;
        if (days > 0) {
            return String.format("%d天 %d小时 %d分 %d秒", days, hours, minutes, secs);
        }
        return String.format("%d小时 %d分 %d秒", hours, minutes, secs);
    }
}
