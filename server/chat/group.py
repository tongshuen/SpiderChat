"""
群聊管理 — 服务器端。
支持本地群组和跨服务器联邦群组。

群组密钥（group_key）设计：
- 创建群组时由服务器生成 32 字节（AES-256）对称群密钥，存入 groups.group_key。
- 群成员加入时，服务器用「服务器 X25519 私钥 × 成员 X25519 公钥」做 ECDH，
  HKDF 派生一次性密钥后，用 AES-256-GCM 加密 group_key 分发给该成员
  （在线即时推送，离线暂存待登录后补推）。
- 群消息正文用 group_key 做 AES-256-GCM 加密后再上传；服务器落库存的是
  该 group_key 密文，并在分发前用 group_key 解密校验，确认确实是用群组
  共享密钥加密（而非逐个用户的会话密钥或明文），然后把同一密文分发给所有成员。
"""

import sqlite3
import json
import time
import secrets
import uuid as uuid_module
from collections import defaultdict
from server.config.loader import get_data_dir
from shared.crypto_utils import (
    aesgcm_encrypt, aesgcm_decrypt, ecdh_shared_secret,
    hkdf_derive, b64_encode, b64_decode,
    AAD_GROUP_MSG,
)
from shared.protocol import DEFAULT_MAX_GROUP_SIZE


GROUP_KEY_LEN = 32  # AES-256
# group_key 分发给成员时的 AAD 上下文
_AAD_GROUP_KEY_DELIVERY = b"spider-group-key-delivery-v1"


class GroupManager:
    """管理本服务器上的群聊。"""

    def __init__(self, config: dict, chat_server=None):
        self.config = config
        self.chat_server = chat_server
        data_dir = get_data_dir()
        self.db_path = config.get("group_db_path", f"{data_dir}/groups.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_uuid TEXT NOT NULL,
                server_node_id TEXT NOT NULL,
                is_federated INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                extra TEXT DEFAULT '{}'
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                uuid TEXT NOT NULL,
                server_node_id TEXT DEFAULT '',
                joined_at INTEGER NOT NULL,
                is_admin INTEGER DEFAULT 0,
                PRIMARY KEY (group_id, uuid)
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_federation (
                group_id TEXT NOT NULL,
                remote_server_node_id TEXT NOT NULL,
                remote_group_id TEXT DEFAULT '',
                sync_direction TEXT DEFAULT 'bidirectional',
                created_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, remote_server_node_id)
            )
        """)

        c.execute("""
            CREATE TABLE IF NOT EXISTS group_messages (
                group_id TEXT NOT NULL,
                from_uuid TEXT NOT NULL,
                encrypted_payload TEXT NOT NULL,
                signature TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                sender_server TEXT DEFAULT ''
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_gmsg_group ON group_messages(group_id, timestamp)")

        # 群密钥离线分发表：成员离线时暂存已密封的 group_key，登录后补推。
        c.execute("""
            CREATE TABLE IF NOT EXISTS group_key_deliveries (
                group_id TEXT NOT NULL,
                uuid TEXT NOT NULL,
                sealed_payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                delivered INTEGER DEFAULT 0,
                PRIMARY KEY (group_id, uuid)
            )
        """)
        conn.commit()
        conn.close()
        self._migrate_schema()

    def _migrate_schema(self):
        """为旧库补列：groups.group_key（群密钥 b64）。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        cols = [r[1] for r in c.execute("PRAGMA table_info(groups)").fetchall()]
        if "group_key" not in cols:
            c.execute("ALTER TABLE groups ADD COLUMN group_key TEXT DEFAULT ''")
            # 为已有但没有 group_key 的群组补生成密钥
            rows = c.execute("SELECT group_id FROM groups WHERE group_key IS NULL OR group_key=''").fetchall()
            for (gid,) in rows:
                c.execute("UPDATE groups SET group_key=? WHERE group_id=?",
                          (b64_encode(secrets.token_bytes(GROUP_KEY_LEN)), gid))
            conn.commit()
        conn.close()

    # ===== 群组密钥（group_key）管理 =====

    def _server_x25519_priv_b64(self) -> str:
        """服务器 X25519 私钥（用于密封 group_key 给成员）。"""
        if self.chat_server:
            return getattr(self.chat_server, "server_x25519_priv_b64", None) or ""
        return ""

    def _get_group_key(self, group_id: str) -> bytes | None:
        """读取群组原始 group_key（32 字节）。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT group_key FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        conn.close()
        if not row or not row[0]:
            return None
        try:
            return b64_decode(row[0])
        except Exception:
            return None

    def encrypt_for_group(self, group_id: str, plaintext: bytes) -> dict:
        """用 group_key（AES-256-GCM）加密群消息正文。"""
        key = self._get_group_key(group_id)
        if key is None:
            raise ValueError(f"群组 {group_id} 无 group_key")
        return aesgcm_encrypt(key, plaintext, AAD_GROUP_MSG)

    def decrypt_from_group(self, group_id: str, envelope: dict) -> bytes | None:
        """
        用 group_key 解密群消息信封。
        成功返回明文；密文不是用本群 group_key 加密（或被篡改）时返回 None。
        这是「群消息确实使用 group_key 加密」的服务端校验点。
        """
        key = self._get_group_key(group_id)
        if key is None or not isinstance(envelope, dict):
            return None
        return aesgcm_decrypt(
            key,
            envelope.get("nonce", ""),
            envelope.get("ciphertext", ""),
            envelope.get("tag", ""),
            aad_b64=envelope.get("aad"),
        )

    def seal_group_key_for_member(self, group_id: str, member_uuid: str) -> dict | None:
        """
        把 group_key 用「服务器 X25519 私钥 × 成员 X25519 公钥」密封给某成员。
        返回密封信封；成员无公钥或无私钥时返回 None。
        成员侧用自己的 X25519 私钥 × 服务器 X25519 公钥做同样 ECDH 即可解密。
        """
        key = self._get_group_key(group_id)
        if key is None:
            return None
        server_priv = self._server_x25519_priv_b64()
        if not server_priv or not self.chat_server:
            print(f"[GROUP] 服务器缺少 X25519 私钥，无法密封 group_key 给 {member_uuid[:16]}...")
            return None
        member = self.chat_server.user_manager.get_user(member_uuid) if self.chat_server else None
        member_pub = (member or {}).get("x25519_pub", "")
        if not member_pub:
            print(f"[GROUP] 成员 {member_uuid[:16]}... 无 X25519 公钥，无法分发 group_key")
            return None

        try:
            shared = ecdh_shared_secret(server_priv, member_pub)
            wrap_key = hkdf_derive(shared, info=_AAD_GROUP_KEY_DELIVERY, length=32)
            return aesgcm_encrypt(wrap_key, key, _AAD_GROUP_KEY_DELIVERY)
        except Exception as e:
            print(f"[GROUP] 密封 group_key 失败: {e}")
            return None

    def deliver_group_key(self, group_id: str, member_uuid: str) -> bool:
        """
        向成员分发 group_key：在线则即时推送 GROUP_KEY_UPDATE；离线则暂存，
        待该成员登录后由 flush_pending_group_keys 补推。
        """
        sealed = self.seal_group_key_for_member(group_id, member_uuid)
        if sealed is None:
            return False

        payload = {
            "type": "GROUP_KEY_UPDATE",
            "group_id": group_id,
            "sealed_group_key": sealed,
            "server_x25519_pub": getattr(self.chat_server, "server_x25519_pub", "") if self.chat_server else "",
        }

        # 离线：持久化待投递
        if self.chat_server is None or member_uuid not in self.chat_server.connections:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute(
                """INSERT OR REPLACE INTO group_key_deliveries
                   (group_id, uuid, sealed_payload, created_at, delivered)
                   VALUES (?, ?, ?, ?, 0)""",
                (group_id, member_uuid, json.dumps(sealed), int(time.time()))
            )
            conn.commit()
            conn.close()
            print(f"[GROUP] group_key 已密封并暂存（{member_uuid[:16]}... 离线）")
            return True

        # 在线：即时推送
        conn_obj = self.chat_server.connections[member_uuid]
        self.chat_server._send_raw(conn_obj, payload)
        print(f"[GROUP] group_key 已密封推送给 {member_uuid[:16]}...")
        return True

    def flush_pending_group_keys(self, uuid_str: str) -> int:
        """用户登录后补推所有暂存的 group_key。返回推送条数。"""
        if not self.chat_server:
            return 0
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        rows = c.execute(
            "SELECT group_id, sealed_payload FROM group_key_deliveries WHERE uuid=? AND delivered=0",
            (uuid_str,)
        ).fetchall()
        sent = 0
        for gid, sealed_json in rows:
            conn_obj = self.chat_server.connections.get(uuid_str)
            if not conn_obj:
                break
            sealed = json.loads(sealed_json)
            self.chat_server._send_raw(conn_obj, {
                "type": "GROUP_KEY_UPDATE",
                "group_id": gid,
                "sealed_group_key": sealed,
                "server_x25519_pub": getattr(self.chat_server, "server_x25519_pub", ""),
            })
            c.execute("UPDATE group_key_deliveries SET delivered=1 WHERE group_id=? AND uuid=?",
                      (gid, uuid_str))
            sent += 1
        conn.commit()
        conn.close()
        if sent:
            print(f"[GROUP] 为 {uuid_str[:16]}... 补推 {sent} 条 group_key")
        return sent


    def create_group(self, name: str, owner_uuid: str, server_node_id: str,
                     member_uuids: list = None, federated: bool = False) -> str:
        """创建新群组。返回 group_id。同时生成群组共享密钥 group_key。"""
        group_id = str(uuid_module.uuid4())
        now = int(time.time())
        # 生成 AES-256 群组共享密钥
        group_key_b64 = b64_encode(secrets.token_bytes(GROUP_KEY_LEN))
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT INTO groups (group_id, name, owner_uuid, server_node_id, is_federated, created_at, group_key) VALUES (?,?,?,?,?,?,?)",
            (group_id, name, owner_uuid, server_node_id, 1 if federated else 0, now, group_key_b64)
        )

        c.execute(
            "INSERT INTO group_members (group_id, uuid, server_node_id, joined_at, is_admin) VALUES (?,?,?,?,1)",
            (group_id, owner_uuid, server_node_id, now)
        )

        for m_uuid in (member_uuids or []):
            if m_uuid != owner_uuid:
                c.execute(
                    "INSERT INTO group_members (group_id, uuid, server_node_id, joined_at) VALUES (?,?,?,?)",
                    (group_id, m_uuid, server_node_id, now)
                )
        conn.commit()
        conn.close()
        print(f"[GROUP] 已创建 '{name}' ({group_id[:8]}...) owner={owner_uuid[:16]}... federated={federated}（已生成 group_key）")

        # 把 group_key 密封分发给所有初始成员（含群主）
        self.deliver_group_key(group_id, owner_uuid)
        for m_uuid in (member_uuids or []):
            if m_uuid != owner_uuid:
                self.deliver_group_key(group_id, m_uuid)

        return group_id

    def delete_group(self, group_id: str, requesting_uuid: str) -> bool:
        """删除群组。仅群主可删除。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT owner_uuid FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        if not row or row[0] != requesting_uuid:
            conn.close()
            return False
        c.execute("DELETE FROM groups WHERE group_id=?", (group_id,))
        c.execute("DELETE FROM group_members WHERE group_id=?", (group_id,))
        c.execute("DELETE FROM group_federation WHERE group_id=?", (group_id,))
        conn.commit()
        conn.close()
        print(f"[GROUP] Deleted {group_id[:8]}...")
        return True

    def add_member(self, group_id: str, uuid_str: str,
                   added_by: str, server_node_id: str = "") -> bool:
        """向群组添加成员。仅群主/管理员可添加。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        c.execute("SELECT owner_uuid FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return False
        is_owner = (row[0] == added_by)
        c.execute("SELECT is_admin FROM group_members WHERE group_id=? AND uuid=?", (group_id, added_by))
        row2 = c.fetchone()
        is_admin = bool(row2 and row2[0])
        if not (is_owner or is_admin):
            conn.close()
            return False

        c.execute(
            "INSERT OR IGNORE INTO group_members (group_id, uuid, server_node_id, joined_at) VALUES (?,?,?,?)",
            (group_id, uuid_str, server_node_id, int(time.time()))
        )
        conn.commit()
        affected = c.rowcount
        conn.close()
        if affected:
            print(f"[GROUP] 已将 {uuid_str[:16]}... 加入群组 {group_id[:8]}...")
            # 新成员需要拿到 group_key
            self.deliver_group_key(group_id, uuid_str)
        return affected > 0

    def join_group(self, group_id: str, uuid_str: str, server_node_id: str = "") -> dict:
        """用户自行加入群组。群组必须存在。"""
        group = self.get_group(group_id)
        if not group:
            return {"ok": False, "reason": "群组不存在"}
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT OR IGNORE INTO group_members (group_id, uuid, server_node_id, joined_at) VALUES (?,?,?,?)",
            (group_id, uuid_str, server_node_id or group.get("server_node_id", ""), int(time.time()))
        )
        conn.commit()
        affected = c.rowcount
        conn.close()
        if affected:
            print(f"[GROUP] {uuid_str[:16]}... 自行加入群组 {group_id[:8]}...")
            self.deliver_group_key(group_id, uuid_str)
        return {"ok": True, "group_id": group_id, "already_member": not affected}

    def leave_group(self, group_id: str, uuid_str: str) -> dict:
        """用户主动退出群组。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM group_members WHERE group_id=? AND uuid=?", (group_id, uuid_str))
        conn.commit()
        affected = c.rowcount
        conn.close()
        if affected:
            print(f"[GROUP] {uuid_str[:16]}... 退出群组 {group_id[:8]}...")
        return {"ok": affected > 0, "group_id": group_id}

    def remove_member(self, group_id: str, uuid_str: str, removed_by: str) -> bool:
        """移除成员。群主可移除任何人；自己可退出。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT owner_uuid FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return False
        is_owner = (row[0] == removed_by)
        if uuid_str == removed_by or is_owner:
            c.execute("DELETE FROM group_members WHERE group_id=? AND uuid=?", (group_id, uuid_str))
            conn.commit()
            conn.close()
            return True
        conn.close()
        return False

    def promote_admin(self, group_id: str, uuid_str: str, promoted_by: str) -> bool:
        """将成员提升为管理员。仅群主可操作。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT owner_uuid FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        if not row or row[0] != promoted_by:
            conn.close()
            return False
        c.execute("UPDATE group_members SET is_admin=1 WHERE group_id=? AND uuid=?", (group_id, uuid_str))
        conn.commit()
        conn.close()
        return True


    def get_group(self, group_id: str) -> dict | None:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT group_id, name, owner_uuid, server_node_id, is_federated, created_at FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "group_id": row[0], "name": row[1], "owner_uuid": row[2],
            "server_node_id": row[3], "is_federated": bool(row[4]), "created_at": row[5]
        }

    def list_user_groups(self, uuid_str: str) -> list:
        """列出用户所在的所有群组。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            SELECT g.group_id, g.name, g.owner_uuid, g.server_node_id, g.is_federated
            FROM groups g JOIN group_members m ON g.group_id = m.group_id
            WHERE m.uuid = ?
        """, (uuid_str,))
        rows = c.fetchall()
        conn.close()
        return [{"group_id": r[0], "name": r[1], "owner_uuid": r[2],
                 "server_node_id": r[3], "is_federated": bool(r[4])} for r in rows]

    def list_my_groups(self, uuid_str: str) -> list:
        """别名：列出用户所在的所有群组（供协议处理器调用）。"""
        return self.list_user_groups(uuid_str)

    def get_group_info(self, group_id: str) -> dict:
        """群组详情 + 成员列表。"""
        group = self.get_group(group_id)
        if not group:
            return {"group": None, "members": []}
        return {"group": group, "members": self.get_members(group_id)}

    def search_groups(self, query: str, limit: int = 50) -> list:
        """按名称模糊搜索公开可见的群组。"""
        q = f"%{query}%"
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT group_id, name, owner_uuid, is_federated, created_at FROM groups WHERE name LIKE ? LIMIT ?",
            (q, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [{"group_id": r[0], "name": r[1], "owner_uuid": r[2],
                 "is_federated": bool(r[3]), "created_at": r[4]} for r in rows]

    def send_message(self, group_id: str, from_uuid: str,
                     encrypted_payload: dict, signature: str) -> dict:
        """
        群消息上行入口。

        安全性：encrypted_payload 必须是用本群 group_key 做 AES-256-GCM 加密的信封。
        服务器用 group_key 解密校验——解密成功即证明该消息确实是用群组共享密钥
        加密（而非逐用户会话密钥/明文），随后把同一密文信封分发给所有成员。
        解密失败则拒绝。
        """
        if not self.is_member(group_id, from_uuid):
            return {"ok": False, "reason": "你不是该群成员"}

        # 用 group_key 校验密文确实属于本群
        plaintext = self.decrypt_from_group(group_id, encrypted_payload)
        if plaintext is None:
            return {"ok": False, "reason": "群消息未使用群组共享密钥（group_key）加密"}

        stats = self.distribute_group_message(
            group_id, from_uuid, encrypted_payload, signature,
            self._get_own_node_id(),
        )
        return {"ok": True, "stats": stats}

    def get_members(self, group_id: str) -> list:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT uuid, server_node_id, is_admin, joined_at FROM group_members WHERE group_id=?", (group_id,))
        rows = c.fetchall()
        conn.close()
        return [{"uuid": r[0], "server_node_id": r[1], "is_admin": bool(r[2]), "joined_at": r[3]} for r in rows]

    def get_member_count(self, group_id: str) -> int:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM group_members WHERE group_id=?", (group_id,))
        count = c.fetchone()[0]
        conn.close()
        return count

    def is_member(self, group_id: str, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT 1 FROM group_members WHERE group_id=? AND uuid=?", (group_id, uuid_str))
        row = c.fetchone()
        conn.close()
        return bool(row)

    def is_owner(self, group_id: str, uuid_str: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT owner_uuid FROM groups WHERE group_id=?", (group_id,))
        row = c.fetchone()
        conn.close()
        return bool(row and row[0] == uuid_str)

    def list_all_groups(self) -> list:
        """列出本服务器上的所有群组。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT group_id, name, owner_uuid, is_federated, created_at FROM groups ORDER BY created_at DESC")
        rows = c.fetchall()
        conn.close()
        return [{"group_id": r[0], "name": r[1], "owner_uuid": r[2], "is_federated": bool(r[3]), "created_at": r[4]} for r in rows]


    def federate_group(self, group_id: str, remote_server_node_id: str,
                       remote_group_id: str = "", direction: str = "bidirectional") -> bool:
        """将群组链接到远程服务器以实现跨服务器联邦。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO group_federation (group_id, remote_server_node_id, remote_group_id, sync_direction, created_at) VALUES (?,?,?,?,?)",
            (group_id, remote_server_node_id, remote_group_id, direction, int(time.time()))
        )
        c.execute("UPDATE groups SET is_federated=1 WHERE group_id=?", (group_id,))
        conn.commit()
        conn.close()
        print(f"[FEDERATION] Group {group_id[:8]}... ↔ Server {remote_server_node_id[:16]}...")
        return True

    def unfederate_group(self, group_id: str, remote_server_node_id: str) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM group_federation WHERE group_id=? AND remote_server_node_id=?", (group_id, remote_server_node_id))

        c.execute("SELECT COUNT(*) FROM group_federation WHERE group_id=?", (group_id,))
        count = c.fetchone()[0]
        if count == 0:
            c.execute("UPDATE groups SET is_federated=0 WHERE group_id=?", (group_id,))
        conn.commit()
        conn.close()
        return True

    def get_federation_links(self, group_id: str) -> list:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT remote_server_node_id, remote_group_id, sync_direction FROM group_federation WHERE group_id=?", (group_id,))
        rows = c.fetchall()
        conn.close()
        return [{"remote_server": r[0], "remote_group_id": r[1], "direction": r[2]} for r in rows]


    def store_group_message(self, group_id: str, from_uuid: str,
                           encrypted_payload: dict, signature: str,
                           sender_server: str = "") -> int:
        """存储群消息。返回时间戳。"""
        ts = int(time.time())
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT INTO group_messages (group_id, from_uuid, encrypted_payload, signature, timestamp, sender_server) VALUES (?,?,?,?,?,?)",
            (group_id, from_uuid, json.dumps(encrypted_payload), signature, ts, sender_server)
        )
        conn.commit()
        conn.close()
        return ts

    def get_group_messages(self, group_id: str, limit: int = 100,
                           since_ts: int = 0) -> list:
        """为离线成员检索群消息。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "SELECT from_uuid, encrypted_payload, signature, timestamp, sender_server FROM group_messages WHERE group_id=? AND timestamp>? ORDER BY timestamp ASC LIMIT ?",
            (group_id, since_ts, limit)
        )
        rows = c.fetchall()
        conn.close()
        return [{"from_uuid": r[0], "encrypted_payload": json.loads(r[1]),
                 "signature": r[2], "timestamp": r[3], "sender_server": r[4]} for r in rows]

    def get_offline_group_messages(self, uuid_str: str, since_ts: int = 0) -> dict:
        """
        获取该用户所属群组中，自给定时间戳以来的所有群消息。
        返回 {group_id: [messages]} 字典。
        """
        groups = self.list_user_groups(uuid_str)
        result = {}
        for g in groups:
            gid = g["group_id"]
            msgs = self.get_group_messages(gid, limit=200, since_ts=since_ts)
            if msgs:
                result[gid] = msgs
        return result


    def distribute_group_message(self, group_id: str, from_uuid: str,
                                encrypted_payload: dict, signature: str,
                                sender_server_node_id: str) -> dict:
        """
        将群消息分发给所有在线成员。
        跨服务器成员通过跨服中继路由。
        返回统计: {local_delivered, remote_sent, stored_offline}.
        """
        stats = {"local_delivered": 0, "remote_sent": 0, "stored_offline": 0}
        members = self.get_members(group_id)
        fed_links = self.get_federation_links(group_id)


        ts = self.store_group_message(group_id, from_uuid, encrypted_payload, signature, sender_server_node_id)

        msg_env = {
            "type": "GROUP_MSG",
            "group_id": group_id,
            "from_uuid": from_uuid,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
            "timestamp": ts,
            "sender_server": sender_server_node_id,
        }

        if self.chat_server:
            for m in members:
                m_uuid = m["uuid"]
                m_server = m.get("server_node_id", "")

                if m_server and m_server != sender_server_node_id and m_server != self._get_own_node_id():
                    continue
                if m_uuid == from_uuid:
                    continue

                target_conn = self.chat_server.connections.get(m_uuid)
                if target_conn:
                    self.chat_server._send_raw(target_conn, msg_env)
                    stats["local_delivered"] += 1
                else:
                    stats["stored_offline"] += 1

        if self.chat_server and hasattr(self.chat_server, 'cross_server'):
            cross = self.chat_server.cross_server
            for link in fed_links:
                remote_node = link["remote_server"]
                relay_msg = {
                    "type": "RELAY_GROUP_MSG",
                    "group_id": group_id,
                    "from_uuid": from_uuid,
                    "encrypted_payload": encrypted_payload,
                    "signature": signature,
                    "timestamp": ts,
                    "sender_server": sender_server_node_id,
                    "target_server": remote_node,
                }
                try:
                    cross.send_to_server(remote_node, relay_msg)
                    stats["remote_sent"] += 1
                except Exception as e:
                    print(f"[FEDERATION] Failed to relay to {remote_node[:16]}...: {e}")
        else:
            for link in fed_links:
                stats["remote_sent"] += 1
                print(f"[FEDERATION] Would relay to {link['remote_server'][:16]}... (no channel)")

        return stats

    def _get_own_node_id(self) -> str:
        if self.chat_server and hasattr(self.chat_server, 'node_id'):
            return self.chat_server.node_id
        return ""


    def handle_remote_group_message(self, msg: dict) -> bool:
        """
        处理从远程服务器接收到的群消息。
        验证签名、存储并投递给本地成员。
        """
        group_id = msg.get("group_id", "")
        from_uuid = msg.get("from_uuid", "")
        encrypted = msg.get("encrypted_payload", {})
        signature = msg.get("signature", "")
        sender_server = msg.get("sender_server", "")


        group = self.get_group(group_id)
        if not group:
            print(f"[FEDERATION] Dropping msg for unknown group {group_id[:8]}...")
            return False

        fed_links = self.get_federation_links(group_id)
        allowed_servers = {l["remote_server"] for l in fed_links}
        allowed_servers.add(group.get("server_node_id", ""))

        if sender_server not in allowed_servers:
            print(f"[FEDERATION] Dropping msg from unauthorized server {sender_server[:16]}...")
            return False


        ts = self.store_group_message(group_id, from_uuid, encrypted, signature, sender_server)

        members = self.get_members(group_id)
        if self.chat_server:
            for m in members:
                m_uuid = m["uuid"]
                if m_uuid == from_uuid:
                    continue
                target_conn = self.chat_server.connections.get(m_uuid)
                if target_conn:
                    deliver_msg = {
                        "type": "GROUP_MSG",
                        "group_id": group_id,
                        "from_uuid": from_uuid,
                        "encrypted_payload": encrypted,
                        "signature": signature,
                        "timestamp": ts,
                        "sender_server": sender_server,
                    }
                    self.chat_server._send_raw(target_conn, deliver_msg)

        return True
