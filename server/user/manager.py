"""
用户管理器 — 注册、封禁、用户信息、泄露追踪。
使用 SQLite 持久化。
"""

import sqlite3
import os
import json
import time
import uuid as uuid_module
from server.config.loader import get_data_dir
from server.utils import get_real_mac_for_server


class UserManager:
    """管理所有用户相关操作。"""

    def __init__(self, config: dict):
        self.config = config
        data_dir = get_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "users.db")
        self.strict_mac = config.get("user_management", {}).get("strict_uuid_mac", True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                name TEXT DEFAULT '',
                x25519_pub TEXT DEFAULT '',
                ed25519_pub TEXT DEFAULT '',
                mac_address TEXT DEFAULT '',
                registered_at INTEGER NOT NULL,
                last_seen INTEGER DEFAULT 0,
                last_ip TEXT DEFAULT '',
                is_banned INTEGER DEFAULT 0,
                compromised INTEGER DEFAULT 0,
                muted_until INTEGER DEFAULT 0,
                extra TEXT DEFAULT '{}'
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_banned ON users(is_banned)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_last_seen ON users(last_seen)")
        conn.commit()
        conn.close()


    def register_user(self, uuid_str: str, x25519_pub: str, ed25519_pub: str, ip: str = "") -> bool:
        """注册新用户或更新已有用户。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT uuid FROM users WHERE uuid = ?", (uuid_str,))
        if c.fetchone():

            c.execute(
                "UPDATE users SET x25519_pub=?, ed25519_pub=?, last_seen=?, last_ip=? WHERE uuid=?",
                (x25519_pub, ed25519_pub, int(time.time()), ip, uuid_str)
            )
        else:
            c.execute(
                """INSERT INTO users (uuid, x25519_pub, ed25519_pub, registered_at, last_seen, last_ip)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (uuid_str, x25519_pub, ed25519_pub, int(time.time()), int(time.time()), ip)
            )
        conn.commit()
        conn.close()
        return True

    def create_user_for_admin(self, name: str) -> dict | None:
        """
        管理员在服务器端创建用户。
        强制 UUIDv1 + 真实 MAC。无回退。
        Returns dict with uuid + keypairs, or None on failure.
        """
        try:
            mac_int = get_real_mac_for_server()
        except RuntimeError as e:
            print(f"[USER] Cannot create user — MAC unavailable: {e}")
            return None


        u = uuid_module.uuid1(node=mac_int)
        uuid_str = str(u)


        from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
        import base64

        x_priv = x25519.X25519PrivateKey.generate()
        x_pub = x_priv.public_key()
        e_priv = ed25519.Ed25519PrivateKey.generate()
        e_pub = e_priv.public_key()

        keys = {
            "x25519_private": base64.b64encode(x_priv.private_bytes(
                encoding=Encoding.Raw, format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption()
            )).decode(),
            "x25519_public": base64.b64encode(x_pub.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )).decode(),
            "ed25519_private": base64.b64encode(e_priv.private_bytes(
                encoding=Encoding.Raw, format=PrivateFormat.Raw,
                encryption_algorithm=NoEncryption()
            )).decode(),
            "ed25519_public": base64.b64encode(e_pub.public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw
            )).decode(),
        }


        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """INSERT INTO users (uuid, name, x25519_pub, ed25519_pub, mac_address, registered_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (uuid_str, name, keys["x25519_public"], keys["ed25519_public"],
             ":".join(f"{(mac_int >> (i*8)) & 0xff:02x}" for i in range(5, -1, -1)),
             int(time.time()))
        )
        conn.commit()
        conn.close()

        result = {"uuid": uuid_str, "name": name}
        result.update(keys)
        print(f"[USER] Created user '{name}' with UUID {uuid_str[:16]}...")
        return result


    def get_user(self, uuid_str: str) -> dict | None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT uuid, name, x25519_pub, ed25519_pub, registered_at, last_seen, last_ip, is_banned, compromised FROM users WHERE uuid = ?", (uuid_str,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "uuid": row[0], "name": row[1], "x25519_pub": row[2],
            "ed25519_pub": row[3], "registered_at": row[4],
            "last_seen": row[5], "last_ip": row[6],
            "is_banned": bool(row[7]), "compromised": bool(row[8]),
        }

    def update_last_seen(self, uuid_str: str, ip: str = ""):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET last_seen=?, last_ip=? WHERE uuid=?",
                  (int(time.time()), ip, uuid_str))
        conn.commit()
        conn.close()

    def list_online_users(self, timeout_sec: int = 300) -> list:
        """列出在超时窗口内活跃的用户。"""
        cutoff = int(time.time()) - timeout_sec
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT uuid, last_ip, last_seen FROM users WHERE last_seen > ? AND is_banned=0", (cutoff,))
        rows = c.fetchall()
        conn.close()
        return [{"uuid": r[0], "ip": r[1], "last_seen": r[2]} for r in rows]

    def list_all_users(self) -> list:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT uuid, name, registered_at, last_seen, is_banned FROM users ORDER BY registered_at DESC")
        rows = c.fetchall()
        conn.close()
        return [{"uuid": r[0], "name": r[1], "registered_at": r[2], "last_seen": r[3], "banned": bool(r[4])} for r in rows]

    def search_users(self, query: str) -> list:
        """按名称或 UUID 搜索用户（本地数据库）。"""
        q = f"%{query}%"
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT uuid, name FROM users WHERE name LIKE ? OR uuid LIKE ?", (q, q))
        rows = c.fetchall()
        conn.close()
        return [{"uuid": r[0], "name": r[1]} for r in rows]

    def get_user_count(self) -> int:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]
        conn.close()
        return count


    def ban_user(self, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned=1 WHERE uuid=?", (uuid_str,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        if affected:
            print(f"[USER] Banned: {uuid_str[:16]}...")
        return affected > 0

    def unban_user(self, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET is_banned=0 WHERE uuid=?", (uuid_str,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        if affected:
            print(f"[USER] Unbanned: {uuid_str[:16]}...")
        return affected > 0

    def is_banned(self, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT is_banned FROM users WHERE uuid=?", (uuid_str,))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0])


    def mute_user(self, uuid_str: str, duration_sec: int):
        until = int(time.time()) + duration_sec
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET muted_until=? WHERE uuid=?", (until, uuid_str))
        conn.commit()
        conn.close()

    def is_muted(self, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT muted_until FROM users WHERE uuid=?", (uuid_str,))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0] > time.time())


    def mark_compromised(self, uuid_str: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET compromised=1, is_banned=1 WHERE uuid=?", (uuid_str,))
        conn.commit()
        conn.close()
        print(f"[USER] ⚠️ Marked COMPROMISED: {uuid_str[:16]}...")

    def is_compromised(self, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT compromised FROM users WHERE uuid=?", (uuid_str,))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0])


    def delete_user(self, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM users WHERE uuid=?", (uuid_str,))
        affected = c.rowcount
        conn.commit()
        conn.close()
        if affected:
            print(f"[USER] Deleted: {uuid_str[:16]}...")
        return affected > 0


    def block_user(self, uuid_str: str, block_uuid: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT extra FROM users WHERE uuid=?", (uuid_str,))
        row = c.fetchone()
        if row:
            extra = json.loads(row[0] or "{}")
            blocked = extra.get("blocked", [])
            if block_uuid not in blocked:
                blocked.append(block_uuid)
                extra["blocked"] = blocked
            c.execute("UPDATE users SET extra=? WHERE uuid=?", (json.dumps(extra), uuid_str))
            conn.commit()
        conn.close()

    def unblock_user(self, uuid_str: str, block_uuid: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT extra FROM users WHERE uuid=?", (uuid_str,))
        row = c.fetchone()
        if row:
            extra = json.loads(row[0] or "{}")
            blocked = extra.get("blocked", [])
            extra["blocked"] = [u for u in blocked if u != block_uuid]
            c.execute("UPDATE users SET extra=? WHERE uuid=?", (json.dumps(extra), uuid_str))
            conn.commit()
        conn.close()

    def is_blocked(self, uuid_str: str, target_uuid: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT extra FROM users WHERE uuid=?", (uuid_str,))
        row = c.fetchone()
        conn.close()
        if not row:
            return False
        extra = json.loads(row[0] or "{}")
        return target_uuid in extra.get("blocked", [])
