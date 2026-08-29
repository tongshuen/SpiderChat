package com.spider.minecraft.storage;

import com.spider.minecraft.SpiderMinecraft;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * SQLite 数据库管理器 — 对齐 Spider 的持久化存储。
 *
 * <p>在服务端创建 spider_data 文件夹，使用 SQLite JDBC 存储：
 * <ul>
 *   <li>messages — 消息历史（加密信封）</li>
 *   <li>users — 用户/联系人信息（UUID、公钥、昵称）</li>
 *   <li>offline_queue — 离线消息队列（用户下线时暂存，上线时推送）</li>
 *   <li>groups — 群组信息（替代原"房间"）</li>
 *   <li>group_members — 群组成员</li>
 * </ul>
 *
 * <p>服务器重启后数据不丢失。
 */
public class DatabaseManager {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);

    private final Path dbPath;
    private Connection connection;

    public DatabaseManager(Path dataDir) {
        this.dbPath = dataDir.resolve(SpiderMinecraft.DB_FILE);
    }

    /**
     * 初始化数据库连接并创建表。
     */
    public synchronized void initialize() {
        try {
            Class.forName("org.sqlite.JDBC");
            String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();
            connection = DriverManager.getConnection(url);
            connection.setAutoCommit(true);

            createTables();
            LOGGER.info("[SpiderMinecraft] Database initialized: {}", dbPath);
        } catch (ClassNotFoundException | SQLException e) {
            LOGGER.error("[SpiderMinecraft] Failed to initialize database: {}", e.getMessage());
        }
    }

    private void createTables() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            // 消息表
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id TEXT UNIQUE,
                    from_uuid TEXT NOT NULL,
                    to_uuid TEXT NOT NULL,
                    group_id TEXT,
                    encrypted_envelope TEXT NOT NULL,
                    is_file INTEGER DEFAULT 0,
                    expire_after_read INTEGER DEFAULT 0,
                    delivery_status TEXT DEFAULT 'sending',
                    timestamp INTEGER NOT NULL
                )
            """);

            // 用户表
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    uuid TEXT PRIMARY KEY,
                    display_name TEXT,
                    x25519_pub TEXT,
                    ed25519_pub TEXT,
                    node_type TEXT,
                    is_online INTEGER DEFAULT 0,
                    last_seen INTEGER,
                    burn_after_read INTEGER DEFAULT 0
                )
            """);

            // 离线消息队列
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS offline_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_uuid TEXT NOT NULL,
                    msg_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    timestamp INTEGER NOT NULL
                )
            """);

            // 群组表
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_uuid TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    max_members INTEGER DEFAULT 256
                )
            """);

            // 群组成员
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    user_uuid TEXT NOT NULL,
                    display_name TEXT,
                    joined_at INTEGER NOT NULL,
                    role TEXT DEFAULT 'member',
                    PRIMARY KEY (group_id, user_uuid)
                )
            """);

            // 索引
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_uuid)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_uuid)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_offline_user ON offline_queue(user_uuid)");
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id)");

            LOGGER.info("[SpiderMinecraft] Database tables created/verified");
        }
    }

    public synchronized Connection getConnection() {
        return connection;
    }

    public synchronized void close() {
        try {
            if (connection != null && !connection.isClosed()) {
                connection.close();
                LOGGER.info("[SpiderMinecraft] Database closed");
            }
        } catch (SQLException e) {
            LOGGER.error("[SpiderMinecraft] Error closing database: {}", e.getMessage());
        }
    }
}
