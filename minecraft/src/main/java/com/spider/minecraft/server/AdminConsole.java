package com.spider.minecraft.server;

import java.util.*;

/**
 * 管理员控制台 — 模仿原版 Spider 服务端的管理员命令系统。
 *
 * <p>支持的命令（与原版 Spider 服务端对齐）：
 * <ul>
 *   <li>LIST_ONLINE — 查看在线用户</li>
 *   <li>LIST_ALL_USERS — 查看所有用户</li>
 *   <li>LIST_BANNED — 查看封禁用户</li>
 *   <li>BAN_USER <uuid> [reason] — 封禁用户</li>
 *   <li>UNBAN_USER <uuid> — 解封用户</li>
 *   <li>KICK_USER <uuid> — 踢用户下线</li>
 *   <li>CREATE_USER <name> — 创建用户</li>
 *   <li>DELETE_USER <uuid> — 删除用户</li>
 *   <li>MUTE_USER <uuid> <seconds> — 禁言用户</li>
 *   <li>UNMUTE_USER <uuid> — 解除禁言</li>
 *   <li>SET_RATE_LIMIT <rate> — 设置全局限速</li>
 *   <li>SET_USER_RATE <rate> — 设置用户限速</li>
 *   <li>SET_MAX_FILE_SIZE <mb> — 设置最大文件大小</li>
 *   <li>BROADCAST_MSG <text> — 广播通知</li>
 *   <li>SHUTDOWN — 优雅关机</li>
 *   <li>FORCE_SHUTDOWN — 强制关机</li>
 *   <li>RELOAD_CONFIG — 重载配置</li>
 *   <li>STATS — 查看统计信息</li>
 *   <li>HELP — 帮助</li>
 * </ul>
 */
public class AdminConsole {

    public static class CommandResult {
        public final boolean success;
        public final String message;

        public CommandResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }
    }

    private final ServerUserManager userManager;
    private final RateLimiter rateLimiter;
    private final SpiderServerCore serverCore;
    private int maxFileSizeMb = 100;
    private boolean running = true;

    public AdminConsole(ServerUserManager userManager, RateLimiter rateLimiter, SpiderServerCore serverCore) {
        this.userManager = userManager;
        this.rateLimiter = rateLimiter;
        this.serverCore = serverCore;
    }

    /**
     * 执行管理员命令。
     * @param input 命令行输入
     * @return 执行结果
     */
    public CommandResult execute(String input) {
        if (input == null || input.trim().isEmpty()) {
            return new CommandResult(false, "空命令");
        }

        String[] parts = input.trim().split("\\s+", 2);
        String cmd = parts[0].toUpperCase();
        String args = parts.length > 1 ? parts[1] : "";

        try {
            switch (cmd) {
                case "HELP": return help();
                case "LIST_ONLINE": return listOnline();
                case "LIST_ALL_USERS": return listAllUsers();
                case "LIST_BANNED": return listBanned();
                case "BAN_USER": return banUser(args);
                case "UNBAN_USER": return unbanUser(args);
                case "KICK_USER": return kickUser(args);
                case "CREATE_USER": return createUser(args);
                case "DELETE_USER": return deleteUser(args);
                case "MUTE_USER": return muteUser(args);
                case "UNMUTE_USER": return unmuteUser(args);
                case "SET_RATE_LIMIT": return setRateLimit(args);
                case "SET_USER_RATE": return setUserRate(args);
                case "SET_MAX_FILE_SIZE": return setMaxFileSize(args);
                case "BROADCAST_MSG": return broadcastMsg(args);
                case "SHUTDOWN": return shutdown(false);
                case "FORCE_SHUTDOWN": return shutdown(true);
                case "RELOAD_CONFIG": return reloadConfig();
                case "STATS": return stats();
                default: return new CommandResult(false, "未知命令: " + cmd + "（输入 HELP 查看帮助）");
            }
        } catch (Exception e) {
            return new CommandResult(false, "命令执行错误: " + e.getMessage());
        }
    }

    // ===== 命令实现 =====

    private CommandResult help() {
        StringBuilder sb = new StringBuilder("=== 管理员命令 ===\n");
        sb.append("LIST_ONLINE — 在线用户列表\n");
        sb.append("LIST_ALL_USERS — 所有用户列表\n");
        sb.append("LIST_BANNED — 封禁用户列表\n");
        sb.append("BAN_USER <uuid> [reason] — 封禁用户\n");
        sb.append("UNBAN_USER <uuid> — 解封用户\n");
        sb.append("KICK_USER <uuid> — 踢用户下线\n");
        sb.append("CREATE_USER <name> — 创建用户\n");
        sb.append("DELETE_USER <uuid> — 删除用户\n");
        sb.append("MUTE_USER <uuid> <seconds> — 禁言（0=永久）\n");
        sb.append("UNMUTE_USER <uuid> — 解除禁言\n");
        sb.append("SET_RATE_LIMIT <rate> — 全局限速(消息/秒)\n");
        sb.append("SET_USER_RATE <rate> — 用户限速(消息/秒)\n");
        sb.append("SET_MAX_FILE_SIZE <mb> — 最大文件大小(MB)\n");
        sb.append("BROADCAST_MSG <text> — 广播通知\n");
        sb.append("STATS — 服务器统计\n");
        sb.append("RELOAD_CONFIG — 重载配置\n");
        sb.append("SHUTDOWN / FORCE_SHUTDOWN — 关机");
        return new CommandResult(true, sb.toString());
    }

    private CommandResult listOnline() {
        List<ServerUserManager.UserInfo> users = userManager.getOnlineUsers();
        if (users.isEmpty()) return new CommandResult(true, "当前无在线用户");
        StringBuilder sb = new StringBuilder("=== 在线用户 (" + users.size() + ") ===\n");
        for (ServerUserManager.UserInfo u : users) {
            sb.append(String.format("%s [%s] 消息:%d 节点:%s%n",
                    u.displayName, u.uuid.substring(0, 8), u.messageCount,
                    u.currentServer != null ? u.currentServer : "-"));
        }
        return new CommandResult(true, sb.toString());
    }

    private CommandResult listAllUsers() {
        List<ServerUserManager.UserInfo> users = userManager.getAllUsers();
        StringBuilder sb = new StringBuilder("=== 所有用户 (" + users.size() + ") ===\n");
        for (ServerUserManager.UserInfo u : users) {
            sb.append(String.format("%s [%s] %s 消息:%d%n",
                    u.displayName, u.uuid.substring(0, 8),
                    u.online ? "§a在线" : "§7离线", u.messageCount));
        }
        return new CommandResult(true, sb.toString());
    }

    private CommandResult listBanned() {
        List<String> banned = userManager.getBannedUsers();
        if (banned.isEmpty()) return new CommandResult(true, "无封禁用户");
        StringBuilder sb = new StringBuilder("=== 封禁用户 (" + banned.size() + ") ===\n");
        for (String uuid : banned) {
            sb.append(uuid, 0, Math.min(8, uuid.length()))
              .append(" 原因: ").append(userManager.getBanReason(uuid)).append("\n");
        }
        return new CommandResult(true, sb.toString());
    }

    private CommandResult banUser(String args) {
        String[] parts = args.split("\\s+", 2);
        if (parts.length < 1 || parts[0].isEmpty()) return new CommandResult(false, "用法: BAN_USER <uuid> [reason]");
        String uuid = parts[0];
        String reason = parts.length > 1 ? parts[1] : "管理员封禁";
        userManager.banUser(uuid, reason);
        return new CommandResult(true, "已封禁用户: " + uuid.substring(0, Math.min(8, uuid.length())));
    }

    private CommandResult unbanUser(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: UNBAN_USER <uuid>");
        userManager.unbanUser(args.trim());
        return new CommandResult(true, "已解封用户");
    }

    private CommandResult kickUser(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: KICK_USER <uuid>");
        userManager.kickUser(args.trim());
        return new CommandResult(true, "已踢用户下线");
    }

    private CommandResult createUser(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: CREATE_USER <name>");
        String uuid = UUID.randomUUID().toString();
        userManager.registerUser(uuid, args.trim());
        return new CommandResult(true, "已创建用户: " + args + " (uuid=" + uuid.substring(0, 8) + ")");
    }

    private CommandResult deleteUser(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: DELETE_USER <uuid>");
        userManager.deleteUser(args.trim());
        return new CommandResult(true, "已删除用户");
    }

    private CommandResult muteUser(String args) {
        String[] parts = args.split("\\s+");
        if (parts.length < 2) return new CommandResult(false, "用法: MUTE_USER <uuid> <seconds>");
        String uuid = parts[0];
        int seconds = Integer.parseInt(parts[1]);
        if (seconds <= 0) {
            rateLimiter.muteUserPermanent(uuid);
            return new CommandResult(true, "已永久禁言用户");
        }
        rateLimiter.muteUser(uuid, seconds);
        return new CommandResult(true, "已禁言用户 " + seconds + " 秒");
    }

    private CommandResult unmuteUser(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: UNMUTE_USER <uuid>");
        rateLimiter.unmuteUser(args.trim());
        return new CommandResult(true, "已解除禁言");
    }

    private CommandResult setRateLimit(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: SET_RATE_LIMIT <rate>");
        double rate = Double.parseDouble(args.trim());
        rateLimiter.setGlobalRate(rate);
        return new CommandResult(true, "全局限速已设置为 " + rate + " 消息/秒");
    }

    private CommandResult setUserRate(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: SET_USER_RATE <rate>");
        double rate = Double.parseDouble(args.trim());
        rateLimiter.setUserRate(rate);
        return new CommandResult(true, "用户限速已设置为 " + rate + " 消息/秒");
    }

    private CommandResult setMaxFileSize(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: SET_MAX_FILE_SIZE <mb>");
        maxFileSizeMb = Integer.parseInt(args.trim());
        return new CommandResult(true, "最大文件大小已设置为 " + maxFileSizeMb + " MB");
    }

    private CommandResult broadcastMsg(String args) {
        if (args.isEmpty()) return new CommandResult(false, "用法: BROADCAST_MSG <text>");
        if (serverCore != null) {
            serverCore.broadcastMessage(args);
        }
        return new CommandResult(true, "广播已发送: " + args);
    }

    private CommandResult shutdown(boolean force) {
        running = false;
        if (serverCore != null) {
            serverCore.shutdown(force);
        }
        return new CommandResult(true, force ? "强制关机中..." : "优雅关机中...");
    }

    private CommandResult reloadConfig() {
        if (serverCore != null) {
            serverCore.reloadConfig();
        }
        return new CommandResult(true, "配置已重载");
    }

    private CommandResult stats() {
        StringBuilder sb = new StringBuilder("=== 服务器统计 ===\n");
        sb.append("用户管理: ").append(userManager.getStatusSummary()).append("\n");
        sb.append("限速: ").append(rateLimiter.getStatusSummary()).append("\n");
        sb.append("最大文件: ").append(maxFileSizeMb).append(" MB\n");
        if (serverCore != null) {
            sb.append("运行时间: ").append(serverCore.getUptimeString()).append("\n");
            sb.append("连接数: ").append(serverCore.getConnectionCount());
        }
        return new CommandResult(true, sb.toString());
    }

    public boolean isRunning() { return running; }
    public int getMaxFileSizeMb() { return maxFileSizeMb; }
}
