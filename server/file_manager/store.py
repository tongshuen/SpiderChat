"""
文件管理器 — 处理文件大小限制、保留期和清理。
"""

import os
import time
import sqlite3
from server.config.loader import get_data_dir


class FileManager:
    """管理文件传输限制和存储。"""

    def __init__(self, config: dict):
        self.config = config
        self.max_size_mb = config.get("file_transfer", {}).get("max_file_size_mb", DEFAULT_MAX_FILE_MB)
        self.retention_days = config.get("file_transfer", {}).get("retention_days", DEFAULT_FILE_RETENTION_DAYS)
        self.enabled = config.get("file_transfer", {}).get("enabled", True)

        self.data_dir = os.path.join(get_data_dir(), "files")
        os.makedirs(self.data_dir, exist_ok=True)

        self._init_db()

    def _init_db(self):
        db_path = os.path.join(self.data_dir, "file_index.db")
        self.db_path = db_path
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT NOT NULL,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_exp ON files(expires_at)")
        conn.commit()
        conn.close()

    def is_allowed_size(self, size_bytes: int) -> bool:
        """检查文件大小是否在限制范围内。"""
        if not self.enabled:
            return False
        return size_bytes <= (self.max_size_mb * 1024 * 1024)

    def store_file(self, uuid_str: str, filename: str, data: bytes) -> str | None:
        """存储文件。成功返回文件 ID，被拒返回 None。"""
        if not self.is_allowed_size(len(data)):
            return None


        safe_name = os.path.basename(filename)[:200]
        timestamp = int(time.time())
        stored_name = f"{uuid_str[:8]}_{timestamp}_{safe_name}"
        filepath = os.path.join(self.data_dir, stored_name)

        with open(filepath, "wb") as f:
            f.write(data)

        expires = timestamp + (self.retention_days * 86400)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT INTO files (uuid, filename, filepath, size, uploaded_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (uuid_str, safe_name, filepath, len(data), timestamp, expires)
        )
        file_id = c.lastrowid
        conn.commit()
        conn.close()

        return str(file_id)

    def get_file(self, file_id: str, uuid_str: str) -> bytes | None:
        """检索文件。未找到/过期返回 None。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT filepath, size, expires_at FROM files WHERE id=? AND uuid=?", (int(file_id), uuid_str))
        row = c.fetchone()
        conn.close()

        if not row:
            return None
        filepath, size, expires = row
        if expires < time.time():
            return None
        if not os.path.exists(filepath):
            return None
        with open(filepath, "rb") as f:
            return f.read()

    def get_stats(self) -> dict:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*), COALESCE(SUM(size), 0) FROM files")
        count, total_size = c.fetchone()
        c.execute("SELECT uuid, COUNT(*), COALESCE(SUM(size), 0) FROM files GROUP BY uuid")
        per_user = [{"uuid": r[0], "count": r[1], "size": r[2]} for r in c.fetchall()]
        conn.close()
        return {"count": count, "total_bytes": total_size, "per_user": per_user}

    def cleanup_expired(self) -> int:
        """删除过期文件。返回删除数量。"""
        now = time.time()
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT filepath FROM files WHERE expires_at < ?", (now,))
        files_to_delete = [r[0] for r in c.fetchall()]
        for fp in files_to_delete:
            try:
                os.remove(fp)
            except:
                pass
        c.execute("DELETE FROM files WHERE expires_at < ?", (now,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            print(f"[FILE] Cleaned {deleted} expired files")
        return deleted

    def set_max_size(self, mb: int):
        self.max_size_mb = mb
        self.config.setdefault("file_transfer", {})["max_file_size_mb"] = mb

    def set_retention(self, days: int):
        self.retention_days = days
        self.config.setdefault("file_transfer", {})["retention_days"] = days

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
        self.config.setdefault("file_transfer", {})["enabled"] = enabled
