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
        # 死人开关警告消息表 — 每条用户最多一条，覆盖旧的
        c.execute("""
            CREATE TABLE IF NOT EXISTS deadman_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL UNIQUE,
                recipient_uuid TEXT NOT NULL,
                message_text TEXT NOT NULL,
                grace_period_sec INTEGER NOT NULL,
                stored_at INTEGER NOT NULL,
                last_checkin INTEGER NOT NULL,
                triggered INTEGER DEFAULT 0
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_deadman_uuid ON deadman_messages(uuid)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_deadman_triggered ON deadman_messages(triggered)")
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

    # ===== 死人开关（Dead Man's Switch）=====

    def store_deadman_message(self, uuid: str, recipient_uuid: str,
                               message_text: str, grace_period_sec: int) -> bool:
        """
        存储或更新用户的死人开关警告消息。
        每个用户最多一条，新的覆盖旧的。同时更新 last_checkin 为当前时间。
        """
        now = int(time.time())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT id FROM deadman_messages WHERE uuid = ?", (uuid,))
        if c.fetchone():
            c.execute("""
                UPDATE deadman_messages
                SET recipient_uuid=?, message_text=?, grace_period_sec=?,
                    stored_at=?, last_checkin=?, triggered=0
                WHERE uuid=?
            """, (recipient_uuid, message_text, grace_period_sec, now, now, uuid))
        else:
            c.execute("""
                INSERT INTO deadman_messages
                (uuid, recipient_uuid, message_text, grace_period_sec, stored_at, last_checkin)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uuid, recipient_uuid, message_text, grace_period_sec, now, now))
        conn.commit()
        conn.close()
        return True

    def get_deadman_message(self, uuid: str) -> dict | None:
        """获取用户的死人开关警告消息。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            SELECT uuid, recipient_uuid, message_text, grace_period_sec,
                   stored_at, last_checkin, triggered
            FROM deadman_messages WHERE uuid = ?
        """, (uuid,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "uuid": row[0],
            "recipient_uuid": row[1],
            "message_text": row[2],
            "grace_period_sec": row[3],
            "stored_at": row[4],
            "last_checkin": row[5],
            "triggered": bool(row[6]),
        }

    def delete_deadman_message(self, uuid: str) -> bool:
        """删除用户的死人开关警告消息。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM deadman_messages WHERE uuid = ?", (uuid,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def update_deadman_checkin(self, uuid: str) -> bool:
        """更新用户的最后签到时间（登录时调用）。"""
        now = int(time.time())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE deadman_messages SET last_checkin=?, triggered=0 WHERE uuid=?",
                  (now, uuid))
        affected = c.rowcount
        conn.commit()
        conn.close()
        return affected > 0

    def get_expired_deadman_messages(self) -> list:
        """
        获取所有已过期且未触发的死人开关消息。
        过期条件：当前时间 - last_checkin > grace_period_sec，且 triggered=0。
        """
        now = int(time.time())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            SELECT uuid, recipient_uuid, message_text, grace_period_sec,
                   stored_at, last_checkin
            FROM deadman_messages
            WHERE triggered = 0 AND (? - last_checkin) > grace_period_sec
        """, (now,))
        rows = c.fetchall()
        conn.close()
        return [{
            "uuid": r[0],
            "recipient_uuid": r[1],
            "message_text": r[2],
            "grace_period_sec": r[3],
            "stored_at": r[4],
            "last_checkin": r[5],
        } for r in rows]

    def mark_deadman_triggered(self, uuid: str) -> bool:
        """标记死人开关已触发（防止重复触发）。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE deadman_messages SET triggered=1 WHERE uuid=?", (uuid,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        return affected > 0
