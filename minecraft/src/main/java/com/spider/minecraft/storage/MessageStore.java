package com.spider.minecraft.storage;

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
 * 消息存储 — 对齐 Spider 的 MessageStore。
 *
 * <p>消息以加密信封形式持久化到 SQLite，支持：
 * <ul>
 *   <li>保存/查询消息历史</li>
 *   <li>更新送达/已读状态</li>
 *   <li>按联系人搜索消息</li>
 *   <li>阅后即焚消息标记</li>
 * </ul>
 */
public class MessageStore {

    private static final Logger LOGGER = LogManager.getLogger("SpiderMinecraft");

    private final DatabaseManager dbManager;

    public MessageStore(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    /**
     * 保存一条消息。
     */
    public void saveMessage(String fromUuid, String toUuid, String groupId,
                            String encryptedEnvelope, boolean isFile,
                            boolean expireAfterRead) {
        String msgId = UUID.randomUUID().toString();
        long timestamp = System.currentTimeMillis() / 1000;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "INSERT OR IGNORE INTO messages (msg_id, from_uuid, to_uuid, group_id, " +
                 "encrypted_envelope, is_file, expire_after_read, delivery_status, timestamp) " +
                 "VALUES (?, ?, ?, ?, ?, ?, ?, 'sending', ?)")) {
            stmt.setString(1, msgId);
            stmt.setString(2, fromUuid);
            stmt.setString(3, toUuid);
            stmt.setString(4, groupId);
            stmt.setString(5, encryptedEnvelope);
            stmt.setInt(6, isFile ? 1 : 0);
            stmt.setInt(7, expireAfterRead ? 1 : 0);
            stmt.setLong(8, timestamp);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to save message: {}", e.getMessage());
        }
    }

    /**
     * 获取与指定用户的最近消息。
     */
    public List<StoredMessage> getMessages(String userUuid, String peerUuid, int limit) {
        List<StoredMessage> result = new ArrayList<>();
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT msg_id, from_uuid, to_uuid, encrypted_envelope, is_file, " +
                 "expire_after_read, delivery_status, timestamp FROM messages " +
                 "WHERE ((from_uuid = ? AND to_uuid = ?) OR (from_uuid = ? AND to_uuid = ?)) " +
                 "ORDER BY timestamp DESC LIMIT ?")) {
            stmt.setString(1, userUuid);
            stmt.setString(2, peerUuid);
            stmt.setString(3, peerUuid);
            stmt.setString(4, userUuid);
            stmt.setInt(5, limit);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    result.add(new StoredMessage(
                            rs.getString("msg_id"),
                            rs.getString("from_uuid"),
                            rs.getString("to_uuid"),
                            rs.getString("encrypted_envelope"),
                            rs.getInt("is_file") == 1,
                            rs.getInt("expire_after_read") == 1,
                            rs.getString("delivery_status"),
                            rs.getLong("timestamp")
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to get messages: {}", e.getMessage());
        }
        return result;
    }

    /**
     * 更新消息送达状态。
     */
    public void updateDeliveryStatus(String msgId, String status) {
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "UPDATE messages SET delivery_status = ? WHERE msg_id = ?")) {
            stmt.setString(1, status);
            stmt.setString(2, msgId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to update delivery status: {}", e.getMessage());
        }
    }

    /**
     * 删除一条消息（阅后即焚）。
     */
    public void deleteMessage(String msgId) {
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "DELETE FROM messages WHERE msg_id = ?")) {
            stmt.setString(1, msgId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to delete message: {}", e.getMessage());
        }
    }

    /**
     * 搜索消息。
     */
    public List<StoredMessage> searchMessages(String userUuid, String keyword) {
        List<StoredMessage> result = new ArrayList<>();
        // 注意：消息是加密的，搜索需要解密后匹配。此处仅返回所有消息供上层过滤。
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT msg_id, from_uuid, to_uuid, encrypted_envelope, is_file, " +
                 "expire_after_read, delivery_status, timestamp FROM messages " +
                 "WHERE from_uuid = ? OR to_uuid = ? ORDER BY timestamp DESC LIMIT 500")) {
            stmt.setString(1, userUuid);
            stmt.setString(2, userUuid);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    result.add(new StoredMessage(
                            rs.getString("msg_id"),
                            rs.getString("from_uuid"),
                            rs.getString("to_uuid"),
                            rs.getString("encrypted_envelope"),
                            rs.getInt("is_file") == 1,
                            rs.getInt("expire_after_read") == 1,
                            rs.getString("delivery_status"),
                            rs.getLong("timestamp")
                    ));
                }
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to search messages: {}", e.getMessage());
        }
        return result;
    }

    /**
     * 存储的消息记录。
     */
    public static class StoredMessage {
        public final String msgId;
        public final String fromUuid;
        public final String toUuid;
        public final String encryptedEnvelope;
        public final boolean isFile;
        public final boolean expireAfterRead;
        public final String deliveryStatus;
        public final long timestamp;

        public StoredMessage(String msgId, String fromUuid, String toUuid,
                             String encryptedEnvelope, boolean isFile,
                             boolean expireAfterRead, String deliveryStatus, long timestamp) {
            this.msgId = msgId;
            this.fromUuid = fromUuid;
            this.toUuid = toUuid;
            this.encryptedEnvelope = encryptedEnvelope;
            this.isFile = isFile;
            this.expireAfterRead = expireAfterRead;
            this.deliveryStatus = deliveryStatus;
            this.timestamp = timestamp;
        }
    }
}
