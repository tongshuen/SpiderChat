package com.spider.minecraft.storage;

import com.spider.minecraft.protocol.Protocol;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * 离线消息存储 — 对齐 Spider 的 OfflineStore。
 *
 * <p>当用户下线时，发给他的消息存入离线队列；用户上线时，
 * 通过 OFFLINE_QUEUE 信令批量推送。
 *
 * <p>支持的离线消息类型：
 * <ul>
 *   <li>RECV_MSG — 离线期间收到的消息</li>
 *   <li>GROUP_MSG — 离线期间的群组消息</li>
 *   <li>DELIVERY_RECEIPT — 离线期间的送达回执</li>
 * </ul>
 */
public class OfflineStore {

    private static final Logger LOGGER = LogManager.getLogger("SpiderMinecraft");

    private final DatabaseManager dbManager;

    public OfflineStore(DatabaseManager dbManager) {
        this.dbManager = dbManager;
    }

    /**
     * 将一条消息加入用户的离线队列。
     */
    public void enqueue(String userUuid, String msgType, String payload) {
        long timestamp = System.currentTimeMillis() / 1000;
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "INSERT INTO offline_queue (user_uuid, msg_type, payload, timestamp) " +
                 "VALUES (?, ?, ?, ?)")) {
            stmt.setString(1, userUuid);
            stmt.setString(2, msgType);
            stmt.setString(3, payload);
            stmt.setLong(4, timestamp);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to enqueue offline message: {}", e.getMessage());
        }
    }

    /**
     * 获取并清除用户的所有离线消息（上线时调用）。
     */
    public List<OfflineMessage> drainQueue(String userUuid) {
        List<OfflineMessage> result = new ArrayList<>();
        try (Connection conn = dbManager.getConnection()) {
            // 先查询
            try (PreparedStatement select = conn.prepareStatement(
                 "SELECT id, msg_type, payload, timestamp FROM offline_queue " +
                 "WHERE user_uuid = ? ORDER BY timestamp ASC")) {
                select.setString(1, userUuid);
                try (ResultSet rs = select.executeQuery()) {
                    while (rs.next()) {
                        result.add(new OfflineMessage(
                                rs.getInt("id"),
                                rs.getString("msg_type"),
                                rs.getString("payload"),
                                rs.getLong("timestamp")
                        ));
                    }
                }
            }
            // 再删除
            if (!result.isEmpty()) {
                try (PreparedStatement delete = conn.prepareStatement(
                     "DELETE FROM offline_queue WHERE user_uuid = ?")) {
                    delete.setString(1, userUuid);
                    delete.executeUpdate();
                }
                LOGGER.info("[SpiderMinecraft] Drained {} offline messages for {}",
                        result.size(), userUuid.substring(0, 8));
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to drain offline queue: {}", e.getMessage());
        }
        return result;
    }

    /**
     * 获取用户离线消息数量。
     */
    public int getQueueSize(String userUuid) {
        try (Connection conn = dbManager.getConnection();
             PreparedStatement stmt = conn.prepareStatement(
                 "SELECT COUNT(*) FROM offline_queue WHERE user_uuid = ?")) {
            stmt.setString(1, userUuid);
            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) return rs.getInt(1);
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to get queue size: {}", e.getMessage());
        }
        return 0;
    }

    /**
     * 离线消息记录。
     */
    public static class OfflineMessage {
        public final int id;
        public final String msgType;
        public final String payload;
        public final long timestamp;

        public OfflineMessage(int id, String msgType, String payload, long timestamp) {
            this.id = id;
            this.msgType = msgType;
            this.payload = payload;
            this.timestamp = timestamp;
        }

        /**
         * 转换为 OFFLINE_QUEUE 信令的 JSON 条目。
         */
        public String toJsonEntry() {
            return "{\"type\":\"" + msgType + "\",\"payload\":" + payload +
                    ",\"timestamp\":" + timestamp + "}";
        }
    }
}
