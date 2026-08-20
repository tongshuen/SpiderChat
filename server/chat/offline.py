"""
使用 SQLite 的离线消息存储。
为当前不在线的用户存储消息。
"""

import sqlite3
import os
import time
import json
from server.config.loader import get_data_dir


class OfflineStore:
    """每个用户的 SQLite 离线消息队列。"""

    def __init__(self, config: dict):
        data_dir = get_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "offline_messages.db")
        self.retention_days = config.get("file_transfer", {}).get("retention_days", DEFAULT_FILE_RETENTION_DAYS)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS offline_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL,
                message_json TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_uuid ON offline_messages(uuid)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_expires ON offline_messages(expires_at)")
        conn.commit()
        conn.close()

    def add_message(self, uuid: str, msg: dict):
        """存储离线消息待投递。"""
        now = int(time.time())
        expires = now + (self.retention_days * 86400)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT INTO offline_messages (uuid, message_json, timestamp, expires_at) VALUES (?, ?, ?, ?)",
            (uuid, json.dumps(msg), msg.get("timestamp", now), expires)
        )
        conn.commit()
        conn.close()

    def get_messages(self, uuid: str) -> list:
        """获取用户的所有离线消息。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT message_json FROM offline_messages WHERE uuid = ? ORDER BY timestamp ASC",
            (uuid,)
        )
        rows = c.fetchall()
        conn.close()
        return [json.loads(r[0]) for r in rows]

    def clear_messages(self, uuid: str):
        """移除用户的所有离线消息（投递后）。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM offline_messages WHERE uuid = ?", (uuid,))
        conn.commit()
        conn.close()

    def cleanup_expired(self):
        """移除过期消息。"""
        now = int(time.time())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM offline_messages WHERE expires_at < ?", (now,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            print(f"[OFFLINE] Cleaned {deleted} expired messages")
        return deleted

    def count_for_user(self, uuid: str) -> int:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM offline_messages WHERE uuid = ?", (uuid,))
        count = c.fetchone()[0]
        conn.close()
        return count

    def count_pending(self) -> int:
        """统计所有用户的待处理消息总数。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM offline_messages")
        count = c.fetchone()[0]
        conn.close()
        return count
