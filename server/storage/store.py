"""
服务器端 DHT 键值存储 + 用户表。
使用 SQLite 持久化。
"""

import sqlite3
import os
import json
import time
from server.config.loader import get_data_dir


class ServerStore:
    """DHT 值和服务器状态的持久化存储。"""

    def __init__(self, config: dict):
        self.data_dir = get_data_dir()
        os.makedirs(self.data_dir, exist_ok=True)
        self.db_path = os.path.join(self.data_dir, "server_store.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS dht_kv (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                stored_at INTEGER NOT NULL
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS server_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_kv_exp ON dht_kv(expires_at)")
        conn.commit()
        conn.close()


    def dht_put(self, key: str, value: str, ttl: int = 3600):
        expires = int(time.time()) + ttl
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """INSERT OR REPLACE INTO dht_kv (key, value, expires_at, stored_at)
               VALUES (?, ?, ?, ?)""",
            (key, value, expires, int(time.time()))
        )
        conn.commit()
        conn.close()

    def dht_get(self, key: str) -> str | None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT value, expires_at FROM dht_kv WHERE key = ?", (key,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        value, expires = row
        if expires < time.time():
            return None
        return value

    def dht_delete(self, key: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM dht_kv WHERE key = ?", (key,))
        conn.commit()
        conn.close()

    def dht_cleanup(self):
        now = int(time.time())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM dht_kv WHERE expires_at < ?", (now,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        return deleted


    def state_get(self, key: str) -> str | None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT value FROM server_state WHERE key = ?", (key,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else None

    def state_set(self, key: str, value: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """INSERT OR REPLACE INTO server_state (key, value, updated_at)
               VALUES (?, ?, ?)""",
            (key, value, int(time.time()))
        )
        conn.commit()
        conn.close()


    def get_dht_stats(self) -> dict:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM dht_kv")
        total = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM dht_kv WHERE expires_at < ?", (int(time.time()),))
        expired = c.fetchone()[0]
        conn.close()
        return {"total_keys": total, "expired": expired}
