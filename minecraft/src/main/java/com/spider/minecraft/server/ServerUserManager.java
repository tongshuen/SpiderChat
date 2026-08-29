package com.spider.minecraft.server;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务端用户管理器 — 模仿原版 Spider 服务端的用户管理功能。
 *
 * <p>功能：
 * <ul>
 *   <li>用户注册/注销</li>
 *   <li>在线用户追踪</li>
 *   <li>封禁/解封/踢下线</li>
 *   <li>用户列表查询</li>
 *   <li>用户统计</li>
 * </ul>
 */
public class ServerUserManager {

    public static class UserInfo {
        public final String uuid;
        public String displayName;
        public long registeredAt;
        public long lastSeen;
        public boolean online;
        public String currentServer;
        public int messageCount;

        public UserInfo(String uuid, String displayName) {
            this.uuid = uuid;
            this.displayName = displayName;
            this.registeredAt = System.currentTimeMillis();
            this.lastSeen = System.currentTimeMillis();
            this.online = false;
            this.messageCount = 0;
        }
    }

    private final Map<String, UserInfo> users = new ConcurrentHashMap<>();
    private final Set<String> bannedUsers = ConcurrentHashMap.newKeySet();
    private final Map<String, String> banReasons = new ConcurrentHashMap<>();
    private final RateLimiter rateLimiter;

    public ServerUserManager(RateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    /**
     * 注册新用户。
     * @return true=注册成功, false=已存在或被封禁
     */
    public boolean registerUser(String uuid, String displayName) {
        if (bannedUsers.contains(uuid)) {
            return false;
        }
        if (users.containsKey(uuid)) {
            return false;
        }
        users.put(uuid, new UserInfo(uuid, displayName));
        return true;
    }

    /**
     * 用户上线。
     */
    public void userOnline(String uuid, String serverNode) {
        UserInfo info = users.get(uuid);
        if (info != null) {
            info.online = true;
            info.lastSeen = System.currentTimeMillis();
            info.currentServer = serverNode;
        }
    }

    /**
     * 用户下线。
     */
    public void userOffline(String uuid) {
        UserInfo info = users.get(uuid);
        if (info != null) {
            info.online = false;
            info.currentServer = null;
        }
    }

    /**
     * 记录用户发送消息。
     */
    public void recordMessage(String uuid) {
        UserInfo info = users.get(uuid);
        if (info != null) {
            info.messageCount++;
            info.lastSeen = System.currentTimeMillis();
        }
    }

    /**
     * 检查用户是否可以发送消息（结合限速和封禁）。
     */
    public boolean canSendMessage(String uuid) {
        if (bannedUsers.contains(uuid)) return false;
        if (rateLimiter.isMuted(uuid)) return false;
        return rateLimiter.canSend(uuid);
    }

    /**
     * 封禁用户。
     */
    public boolean banUser(String uuid, String reason) {
        bannedUsers.add(uuid);
        banReasons.put(uuid, reason != null ? reason : "无");
        userOffline(uuid);
        return true;
    }

    /**
     * 解封用户。
     */
    public boolean unbanUser(String uuid) {
        bannedUsers.remove(uuid);
        banReasons.remove(uuid);
        return true;
    }

    /**
     * 踢用户下线（不封禁）。
     */
    public boolean kickUser(String uuid) {
        userOffline(uuid);
        return true;
    }

    /**
     * 检查用户是否被封禁。
     */
    public boolean isBanned(String uuid) {
        return bannedUsers.contains(uuid);
    }

    /**
     * 获取封禁原因。
     */
    public String getBanReason(String uuid) {
        return banReasons.getOrDefault(uuid, "");
    }

    /**
     * 获取用户信息。
     */
    public UserInfo getUser(String uuid) {
        return users.get(uuid);
    }

    /**
     * 获取所有在线用户。
     */
    public List<UserInfo> getOnlineUsers() {
        List<UserInfo> online = new ArrayList<>();
        for (UserInfo info : users.values()) {
            if (info.online) online.add(info);
        }
        online.sort(Comparator.comparing(u -> u.displayName));
        return online;
    }

    /**
     * 获取所有用户。
     */
    public List<UserInfo> getAllUsers() {
        List<UserInfo> all = new ArrayList<>(users.values());
        all.sort(Comparator.comparing(u -> u.displayName));
        return all;
    }

    /**
     * 获取被封禁用户列表。
     */
    public List<String> getBannedUsers() {
        return new ArrayList<>(bannedUsers);
    }

    /**
     * 删除用户（注销）。
     */
    public boolean deleteUser(String uuid) {
        users.remove(uuid);
        bannedUsers.remove(uuid);
        banReasons.remove(uuid);
        return true;
    }

    // ===== 统计 =====

    public int getTotalUsers() { return users.size(); }
    public int getOnlineCount() {
        return (int) users.values().stream().filter(u -> u.online).count();
    }
    public int getBannedCount() { return bannedUsers.size(); }
    public int getTotalMessages() {
        return users.values().stream().mapToInt(u -> u.messageCount).sum();
    }

    /**
     * 获取用户管理状态摘要。
     */
    public String getStatusSummary() {
        return String.format("总用户: %d, 在线: %d, 封禁: %d, 总消息: %d",
                getTotalUsers(), getOnlineCount(), getBannedCount(), getTotalMessages());
    }
}
