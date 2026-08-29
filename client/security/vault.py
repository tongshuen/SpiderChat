"""
Spider — 聊天记录加密保险库 (Message Vault)

设计：
- 主密钥由 vault_pin 经 PBKDF2-HMAC-SHA256 派生（盐值随机，存于库内 meta 表）。
- 每条消息独立派生密钥：key = HKDF(master_key, info="spider-vault|" + msg_id)
  -> 不同消息密文互不关联，单条泄露不影响其他消息。
- 密文格式（JSON 可序列化，存入 plaintext 字段）：
    {"kid": base64(msg_id), "ct": base64(ciphertext),
     "nonce": base64(nonce), "tag": base64(tag)}
  kid 使用 msg_id 的 base64 编码（非哈希），解密时可原样还原 msg_id 派生密钥。
- 搜索：逐条（分片）读取 -> 解密 -> 内存匹配，避免整库一次性加载/解密。
- 迁移：re_encrypt_store 将明文批量转密文；decrypt_store_to_plain 反向。

依赖：cryptography (AES-256-GCM)。
"""

import os
import json
import base64
import sqlite3
import hashlib

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 200_000
META_TABLE = "_vault_meta"


class MessageVault:
    """聊天记录分片加密保险库。"""

    def __init__(self, db_path: str, pin: str = ""):
        self.db_path = db_path
        self._pin = pin
        self._master = b""  # 派生主密钥
        self.unlocked = False
        self._ensure_meta()

    # ---------- 初始化 ----------

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def _ensure_meta(self):
        try:
            conn = self._conn()
            c = conn.cursor()
            c.execute(f"CREATE TABLE IF NOT EXISTS {META_TABLE} ("
                      "k TEXT PRIMARY KEY, v TEXT)")
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _get_meta(self, key: str, default: str = "") -> str:
        try:
            conn = self._conn()
            c = conn.cursor()
            c.execute(f"SELECT v FROM {META_TABLE} WHERE k=?", (key,))
            row = c.fetchone()
            conn.close()
            return row[0] if row else default
        except Exception:
            return default

    def _set_meta(self, key: str, value: str):
        conn = self._conn()
        c = conn.cursor()
        c.execute(f"INSERT OR REPLACE INTO {META_TABLE} (k, v) VALUES (?, ?)",
                  (key, value))
        conn.commit()
        conn.close()

    # ---------- 加解锁 ----------

    def is_initialized(self) -> bool:
        return bool(self._get_meta("salt_b64"))

    def initialize(self, pin: str):
        """首次启用：生成盐值并派生主密钥。"""
        if not _HAS_CRYPTO:
            raise RuntimeError("cryptography 库未安装，无法启用保险库")
        salt = os.urandom(SALT_SIZE)
        self._set_meta("salt_b64", base64.b64encode(salt).decode())
        self._derive_master(pin, salt)
        self.unlocked = True

    def unlock(self, pin: str) -> bool:
        """用 PIN 派生主密钥并尝试自测解密验证。"""
        if not _HAS_CRYPTO:
            return False
        salt_b64 = self._get_meta("salt_b64")
        if not salt_b64:
            return False
        salt = base64.b64decode(salt_b64)
        self._derive_master(pin, salt)
        # 自测：用主密钥加密一段再解密，验证 PIN 正确
        try:
            self.unlocked = self._smoke_test()
        except Exception:
            self.unlocked = False
        return self.unlocked

    def lock(self):
        self._master = b""
        self.unlocked = False

    def _derive_master(self, pin: str, salt: bytes):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=KEY_SIZE,
            salt=salt, iterations=PBKDF2_ITERATIONS,
            backend=default_backend())
        self._master = kdf.derive(pin.encode("utf-8"))

    def _msg_key(self, msg_id: str) -> bytes:
        """每条消息独立派生密钥（info 绑定 msg_id）。"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE,
            salt=None, info=f"spider-vault|{msg_id}".encode(),
            backend=default_backend())
        return hkdf.derive(self._master)

    def _smoke_test(self) -> bool:
        """用库内自测密文验证主密钥正确性。"""
        probe = self._get_meta("probe_ct")
        probe_nonce = self._get_meta("probe_nonce")
        if not probe or not probe_nonce:
            # 首次 unlock：生成一个自测样本
            ct_b64, nonce_b64 = self._raw_encrypt("spider-vault-probe", "probe")
            self._set_meta("probe_ct", ct_b64)
            self._set_meta("probe_nonce", nonce_b64)
            return True
        pt = self._raw_decrypt(probe, probe_nonce)
        return pt == "spider-vault-probe"

    # ---------- 底层加解密 ----------

    def _raw_encrypt(self, plaintext: str, msg_id: str) -> tuple:
        key = self._msg_key(msg_id)
        aes = AESGCM(key)
        nonce = os.urandom(NONCE_SIZE)
        ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
        return (base64.b64encode(ct).decode(), base64.b64encode(nonce).decode())

    def _raw_decrypt(self, ct_b64: str, nonce_b64: str) -> str:
        key = self._msg_key(self._current_msg_id or "")
        aes = AESGCM(key)
        ct = base64.b64decode(ct_b64)
        nonce = base64.b64decode(nonce_b64)
        pt = aes.decrypt(nonce, ct, None)
        return pt.decode("utf-8")

    # 当前正在解密的消息 id（供 _raw_decrypt 派生密钥使用）
    _current_msg_id = ""

    # ---------- 对外 API ----------

    def encrypt(self, plaintext: str, msg_id: str) -> dict:
        """加密一条消息文本，返回可 JSON 序列化的密文对象。"""
        if not self.unlocked or not plaintext:
            raise RuntimeError("保险库未解锁或无明文")
        ct_b64, nonce_b64 = self._raw_encrypt(plaintext, msg_id)
        return {
            "kid": base64.b64encode(msg_id.encode("utf-8")).decode(),
            "ct": ct_b64,
            "nonce": nonce_b64,
        }

    def decrypt(self, obj: dict) -> str:
        """解密一个密文对象，返回明文。"""
        if not self.unlocked or not isinstance(obj, dict):
            raise RuntimeError("保险库未解锁或对象无效")
        kid = obj.get("kid", "")
        try:
            msg_id = base64.b64decode(kid).decode("utf-8")
        except Exception:
            msg_id = ""
        self._current_msg_id = msg_id
        return self._raw_decrypt(obj.get("ct", ""), obj.get("nonce", ""))

    # ---------- 批量迁移 ----------

    def re_encrypt_store(self, db_path: str, pin: str) -> int:
        """将 messages 表中明文 plaintext 批量转为密文对象。返回处理条数。"""
        if not self.unlocked:
            self.unlock(pin)
        if not self.unlocked:
            raise RuntimeError("保险库解锁失败")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT msg_id, plaintext FROM messages WHERE plaintext IS NOT NULL")
        rows = c.fetchall()
        count = 0
        for msg_id, plaintext in rows:
            if not plaintext:
                continue
            try:
                json.loads(plaintext)  # 已是密文对象则跳过
                continue
            except Exception:
                pass
            try:
                enc = self.encrypt(plaintext, msg_id)
                c.execute("UPDATE messages SET plaintext=? WHERE msg_id=?",
                          (json.dumps(enc, ensure_ascii=False), msg_id))
                count += 1
            except Exception:
                continue
        conn.commit()
        conn.close()
        return count

    def decrypt_store_to_plain(self, db_path: str) -> int:
        """将密文对象批量还原为明文（关闭保险库时调用）。返回处理条数。"""
        if not self.unlocked:
            raise RuntimeError("解密迁移需先解锁保险库")
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT msg_id, plaintext FROM messages WHERE plaintext IS NOT NULL")
        rows = c.fetchall()
        count = 0
        for msg_id, plaintext in rows:
            if not plaintext:
                continue
            try:
                obj = json.loads(plaintext)
            except Exception:
                continue
            if not isinstance(obj, dict) or "kid" not in obj or "ct" not in obj:
                continue
            try:
                self._current_msg_id = msg_id
                pt = self.decrypt(obj)
                c.execute("UPDATE messages SET plaintext=? WHERE msg_id=?",
                          (pt, msg_id))
                count += 1
            except Exception:
                continue
        conn.commit()
        conn.close()
        return count
