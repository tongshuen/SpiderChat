package com.spider.minecraft.group;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.storage.DatabaseManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 群组管理器 — 替代原"房间"，对齐 Spider 的 Group 系统。
 *
 * <p>群组持久化到 SQLite，服务器重启不丢失。支持：
 * <ul>
 *   <li>创建/加入/离开群组</li>
 *   <li>群组成员管理（持久化）</li>
 *   <li>群组消息（加密信封，群内所有成员可解密）</li>
 *   <li>群组信息查询</li>
 * </ul>
 */
public class GroupManager {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);

    private final DatabaseManager dbManager;

    public GroupManager(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    /**
     * 创建群组。
     */
    public String createGroup(String name, String ownerUuid, String ownerName) {
        String groupId = UUID.randomUUID().toString();
        long createdAt = System.currentTimeMillis() / 1000;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "INSERT INTO groups (group_id, name, owner_uuid, created_at, max_members) VALUES (?, ?, ?, ?, ?)")) {
            stmt.setString(1, groupId);
            stmt.setString(2, name);
            stmt.setString(3, ownerUuid);
            stmt.setLong(4, createdAt);
            stmt.setInt(5, 256);
            stmt.executeUpdate();

            // 所有者自动加入
            addMember(groupId, ownerUuid, ownerName, "owner");
            LOGGER.info("[SpiderMinecraft] Group created: {} ({}) by {}", name, groupId, ownerUuid);
            return groupId;
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to create group: {}", e.getMessage());
            return null;
        }
    }

    /**
     * 加入群组。
     */
    public boolean joinGroup(String groupId, String userUuid, String displayName) {
        if (isMember(groupId, userUuid)) return true;
        return addMember(groupId, userUuid, displayName, "member");
    }

    private boolean addMember(String groupId, String userUuid, String displayName, String role) {
        long joinedAt = System.currentTimeMillis() / 1000;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "INSERT OR IGNORE INTO group_members (group_id, user_uuid, display_name, joined_at, role) VALUES (?, ?, ?, ?, ?)")) {
            stmt.setString(1, groupId);
            stmt.setString(2, userUuid);
            stmt.setString(3, displayName);
            stmt.setLong(4, joinedAt);
            stmt.setString(5, role);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to add member: {}", e.getMessage());
            return false;
        }
    }

    /**
     * 离开群组。
     */
    public void leaveGroup(String groupId, String userUuid) {
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "DELETE FROM group_members WHERE group_id = ? AND user_uuid = ?")) {
            stmt.setString(1, groupId);
            stmt.setString(2, userUuid);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to leave group: {}", e.getMessage());
        }
    }

    /**
     * 检查是否为群组成员。
     */
    public boolean isMember(String groupId, String userUuid) {
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT 1 FROM group_members WHERE group_id = ? AND user_uuid = ?")) {
            stmt.setString(1, groupId);
            stmt.setString(2, userUuid);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * 获取群组成员列表。
     */
    public List<GroupMember> getMembers(String groupId) {
        List<GroupMember> result = new ArrayList<>();
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT user_uuid, display_name, role, joined_at FROM group_members WHERE group_id = ? ORDER BY joined_at ASC")) {
            stmt.setString(1, groupId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    result.add(new GroupMember(
                            rs.getString("user_uuid"),
                            rs.getString("display_name"),
                            rs.getString("role"),
                            rs.getLong("joined_at")
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to get members: {}", e.getMessage());
        }
        return result;
    }

    /**
     * 获取群组信息。
     */
    public GroupInfo getGroupInfo(String groupId) {
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT group_id, name, owner_uuid, created_at, max_members FROM groups WHERE group_id = ?")) {
            stmt.setString(1, groupId);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new GroupInfo(
                            rs.getString("group_id"),
                            rs.getString("name"),
                            rs.getString("owner_uuid"),
                            rs.getLong("created_at"),
                            rs.getInt("max_members"),
                            getMembers(groupId).size()
                    );
                }
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to get group info: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 列出用户加入的所有群组。
     */
    public List<GroupInfo> listUserGroups(String userUuid) {
        List<GroupInfo> result = new ArrayList<>();
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT g.group_id, g.name, g.owner_uuid, g.created_at, g.max_members " +
                 "FROM groups g JOIN group_members gm ON g.group_id = gm.group_id " +
                 "WHERE gm.user_uuid = ? ORDER BY g.created_at DESC")) {
            stmt.setString(1, userUuid);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    result.add(new GroupInfo(
                            rs.getString("group_id"),
                            rs.getString("name"),
                            rs.getString("owner_uuid"),
                            rs.getLong("created_at"),
                            rs.getInt("max_members"),
                            getMembers(rs.getString("group_id")).size()
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to list user groups: {}", e.getMessage());
        }
        return result;
    }

    public static class GroupMember {
        public final String uuid;
        public final String displayName;
        public final String role;
        public final long joinedAt;

        public GroupMember(String uuid, String displayName, String role, long joinedAt) {
            this.uuid = uuid;
            this.displayName = displayName;
            this.role = role;
            this.joinedAt = joinedAt;
        }
    }

    public static class GroupInfo {
        public final String groupId;
        public final String name;
        public final String ownerUuid;
        public final long createdAt;
        public final int maxMembers;
        public final int memberCount;

        public GroupInfo(String groupId, String name, String ownerUuid, long createdAt, int maxMembers, int memberCount) {
            this.groupId = groupId;
            this.name = name;
            this.ownerUuid = ownerUuid;
            this.createdAt = createdAt;
            this.maxMembers = maxMembers;
            this.memberCount = memberCount;
        }
    }
}
