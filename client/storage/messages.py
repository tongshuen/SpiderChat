"""
使用 SQLite 的本地消息存储。
存储发送和接收的消息及其元数据，包括送达/已读回执状态。
"""

import sqlite3
import os
import json
import time
import uuid as uuid_module
from client.utils.config import chat_db_path

# 消息送达状态常量
STATUS_SENDING = "sending"      # 已发送，等待服务器确认（发送中）
STATUS_DELIVERED = "delivered"  # 服务器已确认送达对方
STATUS_READ = "read"            # 对方已读
STATUS_FAILED = "failed"        # 发送失败


def generate_msg_id() -> str:
    """生成唯一的客户端消息 ID（UUID4），用于追踪回执。"""
    return str(uuid_module.uuid4())


class MessageStore:
    """每个联系人的 SQLite 消息历史记录。"""

    def __init__(self, db_path: str = None):
        self.db_path = db_path or chat_db_path()
        self._init_db()

    def _init_db(self):
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT UNIQUE,
                contact_uuid TEXT NOT NULL,
                direction TEXT NOT NULL,
                ciphertext BLOB,
                plaintext TEXT,
                nonce TEXT,
                signature TEXT,
                filename TEXT DEFAULT NULL,
                filesize INTEGER DEFAULT 0,
                timestamp INTEGER NOT NULL,
                is_file INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                delivery_status TEXT DEFAULT 'sending',
                server_msg_id TEXT DEFAULT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_contact ON messages(contact_uuid)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_status ON messages(delivery_status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(msg_id)")
        conn.commit()
        conn.close()

    def _orig_add_message(self, contact_uuid: str, direction: str, plaintext: str,
                          nonce: str = "", signature: str = "", timestamp: int = None,
                          is_file: bool = False, filename: str = "", filesize: int = 0,
                          delivery_status: str = None, server_msg_id: str = None,
                          msg_id: str = None) -> int:
        """原始（非加密）添加实现，供保险库 hook 调用。"""
        if timestamp is None:
            timestamp = int(time.time())
        if delivery_status is None:
            delivery_status = "sending" if direction == "sent" else "delivered"
        if msg_id is None:
            msg_id = generate_msg_id()
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """INSERT INTO messages
               (msg_id, contact_uuid, direction, plaintext, nonce, signature,
                filename, filesize, timestamp, is_file, is_read, delivery_status, server_msg_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (msg_id, contact_uuid, direction, plaintext, nonce, signature,
             filename, filesize, timestamp,
             1 if is_file else 0,
             1 if (direction == "recv" and delivery_status == "delivered") else 0,
             delivery_status,
             server_msg_id)
        )
        conn.commit()
        row_id = c.lastrowid
        conn.close()
        return row_id

    def add_message(self, contact_uuid, direction, plaintext, **kw):
        """对外 API：写入前若保险库启用则加密 plaintext。"""
        v = self._vault()
        if v and v.unlocked and plaintext and not kw.get("is_file"):
            try:
                msg_id = kw.get("msg_id") or generate_msg_id()
                enc = v.encrypt(plaintext, msg_id)
                plaintext = json.dumps(enc, ensure_ascii=False)
            except Exception:
                pass
        return self._orig_add_message(contact_uuid, direction, plaintext, **kw)

    def update_delivery_status(self, msg_id: int, status: str):
        """通过数据库行 ID 更新送达状态。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "UPDATE messages SET delivery_status = ? WHERE id = ?",
            (status, msg_id)
        )
        conn.commit()
        conn.close()

    def update_delivery_status_by_msg_id(self, msg_id: str, status: str):
        """通过客户端消息 ID 更新送达状态。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "UPDATE messages SET delivery_status = ? WHERE msg_id = ?",
            (status, msg_id)
        )
        affected = c.rowcount
        conn.commit()
        conn.close()
        return affected

    def update_delivery_status_by_server_id(self, server_msg_id: str, status: str):
        """通过服务器消息 ID 更新送达状态。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "UPDATE messages SET delivery_status = ? WHERE server_msg_id = ?",
            (status, server_msg_id)
        )
        affected = c.rowcount
        conn.commit()
        conn.close()
        return affected

    def mark_read(self, contact_uuid: str):
        """将某联系人的所有接收消息标记为已读。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "UPDATE messages SET is_read=1, delivery_status='read' "
            "WHERE contact_uuid=? AND direction='recv'",
            (contact_uuid,)
        )
        conn.commit()
        conn.close()

    def _orig_get_messages(self, contact_uuid: str, limit: int = 200) -> list:
        """原始（非解密）读取实现。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """SELECT id, direction, plaintext, filename, filesize, timestamp, is_file,
                      nonce, signature, delivery_status, is_read, msg_id
               FROM messages WHERE contact_uuid = ?
               ORDER BY timestamp ASC LIMIT ?""",
            (contact_uuid, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [
            {
                "id": r[0], "direction": r[1], "text": r[2],
                "filename": r[3], "filesize": r[4], "timestamp": r[5],
                "is_file": bool(r[6]), "nonce": r[7], "signature": r[8],
                "delivery_status": r[9] or "sending", "is_read": bool(r[10]),
                "msg_id": r[11],
            }
            for r in rows
        ]

    def get_messages(self, contact_uuid, limit=200):
        """对外 API：读取时若保险库启用则逐条解密。"""
        rows = self._orig_get_messages(contact_uuid, limit=limit)
        v = self._vault()
        if not v or not v.unlocked:
            return rows
        out = []
        for r in rows:
            txt = r.get("text", "")
            if txt:
                try:
                    obj = json.loads(txt)
                    if isinstance(obj, dict) and "kid" in obj and "ct" in obj:
                        txt = v.decrypt(obj)
                except Exception:
                    pass
                r = dict(r); r["text"] = txt
            out.append(r)
        return out

    def _orig_search_messages(self, contact_uuid: str, keyword: str) -> list:
        """原始（非解密）搜索实现。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """SELECT id, direction, plaintext, filename, filesize, timestamp, is_file
               FROM messages WHERE contact_uuid = ? AND plaintext LIKE ?
               ORDER BY timestamp DESC""",
            (contact_uuid, f"%{keyword}%")
        )
        rows = c.fetchall()
        conn.close()
        return [
            {
                "id": r[0], "direction": r[1], "text": r[2],
                "filename": r[3], "filesize": r[4], "timestamp": r[5],
                "is_file": bool(r[6]),
            }
            for r in rows
        ]

    def search_messages(self, contact_uuid, keyword):
        """对外 API：保险库启用时分片逐条解密后匹配。"""
        v = self._vault()
        rows = self._orig_search_messages(contact_uuid, keyword)
        if not v or not v.unlocked:
            return rows
        out = []
        for r in rows:
            txt = r.get("text", "")
            if txt:
                try:
                    obj = json.loads(txt)
                    if isinstance(obj, dict) and "kid" in obj and "ct" in obj:
                        txt = v.decrypt(obj)
                except Exception:
                    pass
                r = dict(r); r["text"] = txt
            if keyword.lower() in txt.lower():
                out.append(r)
        return out

    def delete_messages(self, contact_uuid: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM messages WHERE contact_uuid = ?", (contact_uuid,))
        conn.commit()
        conn.close()

    def get_all_sent_pending(self, contact_uuid: str) -> list:
        """获取某联系人的所有尚未确认送达的发送消息。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """SELECT id, plaintext, timestamp, msg_id FROM messages
               WHERE contact_uuid = ? AND direction = 'sent'
               AND delivery_status = 'sending'
               ORDER BY timestamp ASC""",
            (contact_uuid,)
        )
        rows = c.fetchall()
        conn.close()
        return [{"id": r[0], "text": r[1], "timestamp": r[2], "msg_id": r[3]} for r in rows]

    def get_msg_id_by_db_id(self, db_id: int) -> str:
        """通过数据库行 ID 获取客户端消息 ID。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT msg_id FROM messages WHERE id = ?", (db_id,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else ""

    def get_msg_id_by_server_id(self, server_msg_id: str) -> str:
        """通过服务器消息 ID 获取客户端消息 ID。"""
        if not server_msg_id:
            return ""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT msg_id FROM messages WHERE server_msg_id = ? LIMIT 1",
                  (server_msg_id,))
        row = c.fetchone()
        conn.close()
        return row[0] if row else ""

    # ===== 保险库加解密钩子（vault 未启用时透明 passthrough）=====
    def _vault(self):
        try:
            from client.security.vault import MessageVault
        except Exception:
            return None
        cfg = {}
        try:
            from client.utils.config import load_config
            cfg = load_config() or {}
        except Exception:
            pass
        if not cfg.get("vault_enabled"):
            return None
        return MessageVault(self.db_path, cfg.get("vault_pin", ""))

    def add_message(self, contact_uuid, direction, plaintext, **kw):
        """覆写：写入前若保险库启用则加密 plaintext。"""
        v = self._vault()
        if v and v.unlocked and plaintext and not kw.get("is_file"):
            try:
                msg_id = kw.get("msg_id") or generate_msg_id()
                enc = v.encrypt(plaintext, msg_id)
                plaintext = json.dumps(enc, ensure_ascii=False)
            except Exception:
                pass
        return self._orig_add_message(contact_uuid, direction, plaintext, **kw)

    def get_messages(self, contact_uuid, limit=200):
        """覆写：读取时若保险库启用则逐条解密。"""
        rows = self._orig_get_messages(contact_uuid, limit=limit)
        v = self._vault()
        if not v or not v.unlocked:
            return rows
        out = []
        for r in rows:
            txt = r.get("text", "")
            if txt and r.get("direction") == "recv":
                try:
                    obj = json.loads(txt)
                    if isinstance(obj, dict) and "kid" in obj and "ct" in obj:
                        txt = v.decrypt(obj)
                except Exception:
                    pass
                r = dict(r); r["text"] = txt
            out.append(r)
        return out

    def search_messages(self, contact_uuid, keyword):
        """覆写：保险库启用时分片逐条解密后匹配。"""
        v = self._vault()
        rows = self._orig_search_messages(contact_uuid, keyword)
        if not v or not v.unlocked:
            return rows
        out = []
        for r in rows:
            txt = r.get("text", "")
            if txt:
                try:
                    obj = json.loads(txt)
                    if isinstance(obj, dict) and "kid" in obj and "ct" in obj:
                        txt = v.decrypt(obj)
                except Exception:
                    pass
                r = dict(r); r["text"] = txt
            if keyword.lower() in txt.lower():
                out.append(r)
        return out

    # ===== 批量迁移（启用/关闭保险库时转换历史记录）=====
    def migrate_to_vault(self, pin: str) -> int:
        """明文 -> 密文。返回迁移条数。"""
        from client.security.vault import MessageVault
        v = MessageVault(self.db_path, pin); v.unlock(pin)
        return v.re_encrypt_store(self.db_path, pin)

    def migrate_from_vault(self) -> int:
        """密文 -> 明文。返回迁移条数。"""
        from client.security.vault import MessageVault
        v = MessageVault(self.db_path, "")
        return v.decrypt_store_to_plain(self.db_path)

    def get_visible_messages(self, contact_uuid: str, limit: int = 50) -> list:
        """
        获取当前可见窗口范围内的消息（最近的 N 条）。
        用于判断哪些消息需要发送已读回执。
        """
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            """SELECT id, msg_id, direction, plaintext, timestamp, is_file,
                      filename, filesize, delivery_status
               FROM messages WHERE contact_uuid = ?
               ORDER BY timestamp DESC LIMIT ?""",
            (contact_uuid, limit)
        )
        rows = c.fetchall()
        conn.close()
        rows.reverse()  # 按时间正序返回
        return [
            {
                "id": r[0], "msg_id": r[1], "direction": r[2],
                "text": r[3], "timestamp": r[4], "is_file": bool(r[5]),
                "filename": r[6], "filesize": r[7],
                "delivery_status": r[8] or "sending",
            }
            for r in rows
        ]

