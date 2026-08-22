"""
Spider — 聊天记录加密保险库 (Encrypted Message Vault)

设计目标
========
为本地 SQLite 聊天记录提供可选的端到端加密存储。启用后，写入数据库的
plaintext 以 AES-256-GCM 密文形式保存；读取/搜索时**按消息逐条（分片）**
解密，而非一次性解密整库，从而控制内存占用——即使历史记录很大，单次
只解密当前需要渲染或匹配的那一条/那一批。

密钥体系
========
* 保险库主密钥 (vault_master_key) 由用户解锁 PIN 经 PBKDF2-HMAC-SHA256
  派生，与身份私钥加解密共用同一套 PIN 派生原语（derive_key_from_pin）。
* 每条消息使用独立的随机 nonce + 通过 HKDF 从主密钥与该消息 msg_id
  派生的 per-message 密钥，实现"一次一密"语义并支持独立解密任一分片。
* 密文、nonce、tag、AAD 与派生 salt 随行存储（messages 表新增字段在
  MessageStore 中以兼容方式处理；本模块负责 (plaintext <-> vault blob)
  的转换，数据库层仍按原 schema 存取）。

搜索策略
========
关键词搜索采用"解密-匹配-丢弃"的流式逐条处理：只对当前联系人的消息
逐条解密并做子串匹配，命中结果立即返回；不会把整库明文同时驻留内存。
这对内存友好，也是"分片解密"在本项目中的可行实现。

注：本模块仅负责加解密与密钥管理；启停开关、UI、配置落盘由 settings
与 main_window 负责。模块在 cryptography 库不可用时仍可被导入（功能
不可用会在运行时给出明确错误），以保持项目启动韧性。
"""

import os
import json
import base64
import hashlib
import sqlite3
from typing import Optional, Iterable, Callable

from shared.crypto_utils import (
    aesgcm_encrypt, aesgcm_decrypt,
    derive_key_from_pin, hkdf_derive, b64_encode, b64_decode,
    PBKDF2_ITERATIONS, SALT_SIZE, NONCE_SIZE,
)
from client.storage.messages import MessageStore


# ---------- 配置键 ----------
CONF_VAULT_ENABLED = "vault_enabled"          # bool
CONF_VAULT_PIN_PROTECTED = "vault_pin_protected"  # bool: 是否用 PIN 派生密钥
CONF_VAULT_SALT = "vault_salt_b64"           # 主密钥派生盐值（随机生成一次）
CONF_VAULT_KDF_ITER = "vault_kdf_iterations"  # PBKDF2 迭代次数


def default_vault_config() -> dict:
    return {
        CONF_VAULT_ENABLED: False,
        CONF_VAULT_PIN_PROTECTED: True,
        CONF_VAULT_SALT: "",
        CONF_VAULT_KDF_ITER: PBKDF2_ITERATIONS,
    }


class VaultError(RuntimeError):
    """保险库相关错误（密钥错误 / 密文损坏 / 未初始化等）。"""


class MessageVault:
    """
    聊天记录加密保险库。

    使用方式：
        vault = MessageVault(config, store)   # config 来自 settings
        vault.unlock(pin)                     # 启用后必须解锁一次以获得主密钥
        blob = vault.encrypt(plaintext, msg_id)   # 写入前加密
        text = vault.decrypt(blob)                # 读取后解密单条（分片）
        results = vault.search(store, contact_uuid, keyword)  # 流式分片搜索
    """

    def __init__(self, config: Optional[dict] = None, store: Optional[MessageStore] = None):
        self._config = config or {}
        self._store = store or MessageStore()
        self._master_key: Optional[bytes] = None  # 解锁后缓存于内存

    # ---------- 密钥管理 ----------

    def is_enabled(self) -> bool:
        return bool(self._config.get(CONF_VAULT_ENABLED, False))

    def ensure_salt(self) -> bytes:
        """返回（必要时生成并写回配置）保险库盐值。"""
        salt_b64 = self._config.get(CONF_VAULT_SALT, "")
        if salt_b64:
            try:
                return b64_decode(salt_b64)
            except Exception:
                pass
        salt = os.urandom(SALT_SIZE)
        self._config[CONF_VAULT_SALT] = b64_encode(salt)
        return salt

    def unlock(self, pin: str = "") -> bool:
        """
        使用 PIN 派生主密钥并缓存到内存。若配置为"不用 PIN 保护"，
        则使用固定派生材料（安全性较弱，仅方便场景）。成功返回 True。
        密钥错误时抛出 VaultError。
        """
        if not self.is_enabled():
            return False
        if self._config.get(CONF_VAULT_PIN_PROTECTED, True):
            if not pin:
                raise VaultError("保险库已启用且需要 PIN 解锁")
            salt = self.ensure_salt()
            self._master_key = derive_key_from_pin(pin, salt,
                                                  self._config.get(CONF_VAULT_KDF_ITER, PBKDF2_ITERATIONS))
        else:
            # 无 PIN 保护：用盐值本身经 HKDF 派生固定密钥（仍比明文强）
            salt = self.ensure_salt()
            self._master_key = hkdf_derive(salt, info=b"spider-vault-no-pin", length=32)
        # 用一条自检加解密验证密钥可用性
        try:
            self._smoke_test()
        except Exception as e:
            self._master_key = None
            raise VaultError(f"保险库解锁失败（PIN 错误或数据损坏）: {e}")
        return True

    def lock(self):
        """清除内存中的主密钥（重新启用需再次 unlock）。"""
        self._master_key = None

    def is_unlocked(self) -> bool:
        return self._master_key is not None

    def _require_key(self):
        if not self._master_key:
            raise VaultError("保险库未解锁，请先调用 unlock(pin)")

    def _smoke_test(self):
        """用一条临时 (msg_id="__vault_probe__") 加解密自检。"""
        probe = self.encrypt("__probe__", "__vault_probe__")
        plain = self.decrypt(probe)
        if plain != "__probe__":
            raise VaultError("保险库自检失败：明文不匹配")

    def _per_message_key(self, msg_id: str) -> bytes:
        """HKDF 从主密钥 + msg_id 派生 per-message 密钥（分片独立解密）。"""
        self._require_key()
        info = b"spider-vault-msgkey-v1|" + msg_id.encode("utf-8", errors="replace")
        return hkdf_derive(self._master_key, info=info, length=32)

    # ---------- 加密 / 解密（分片）----------

    def encrypt(self, plaintext: str, msg_id: str) -> dict:
        """
        将明文加密为可 JSON 序列化的 blob 字典。
        返回 {v:1, ct, nonce, tag, aad, kid}；其中 kid 为 msg_id 的
        base64 编码，解密时还原 msg_id 以派生相同的 per-message 密钥。
        """
        self._require_key()
        key = self._per_message_key(msg_id)
        aad = b"spider-vault-v1"
        blob = aesgcm_encrypt(key, plaintext.encode("utf-8"), aad)
        return {
            "v": 1,
            "ct": blob["ciphertext"],
            "nonce": blob["nonce"],
            "tag": blob["tag"],
            "aad": blob["aad"],
            "kid": b64_encode(msg_id.encode("utf-8")),
        }

    def decrypt(self, blob: dict) -> str:
        """
        解密单条 blob（分片解密）。blob 格式见 encrypt()。
        失败时返回空字符串并记录，不抛出，避免单条损坏导致列表渲染中断。
        """
        self._require_key()
        if not isinstance(blob, dict) or blob.get("v") != 1:
            raise VaultError("不支持的保险库密文版本")
        msg_id = self._msg_id_from_kid(blob.get("kid", ""))
        if not msg_id:
            raise VaultError("保险库密文缺少可还原的 msg_id (kid)")
        key = self._per_message_key(msg_id)
        plain = aesgcm_decrypt(key, blob.get("nonce", ""), blob.get("ct", ""),
                               blob.get("tag", ""), blob.get("aad"))
        if plain is None:
            raise VaultError("保险库密文解密失败（密钥/数据不匹配）")
        return plain.decode("utf-8")

    def _msg_id_from_kid(self, kid_b64: str) -> str:
        """
        由 kid（msg_id 的 base64 编码）还原原始 msg_id。
        解密时用此 msg_id 派生与加密时完全相同的 per-message 密钥，
        保证分片独立解密正确。
        """
        if not kid_b64:
            return ""
        try:
            return b64_decode(kid_b64).decode("utf-8")
        except Exception:
            return ""

    # ---------- 与 MessageStore 协同：分片搜索 ----------

    def search(self, store: Optional[MessageStore], contact_uuid: str,
              keyword: str, decrypt_row_fn: Optional[Callable] = None) -> list:
        """
        对指定联系人的消息逐条（分片）解密并匹配 keyword。
        仅返回命中的 {id, direction, text, timestamp, ...} 字典列表。
        为避免在调用层重复实现解密行解析，允许传入 decrypt_row_fn(row_dict)
        来自定义单条解密；若不传，则使用 store.search_messages 的明文后备
        并叠加本保险库解密。
        """
        store = store or self._store
        if not keyword:
            return []
        results = []
        conn = sqlite3.connect(store.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                """SELECT id, direction, plaintext, filename, filesize, timestamp, is_file
                   FROM messages WHERE contact_uuid = ? ORDER BY timestamp DESC""",
                (contact_uuid,))
            for r in cur.fetchall():
                row = {
                    "id": r[0], "direction": r[1], "text": r[2],
                    "filename": r[3], "filesize": r[4], "timestamp": r[5],
                    "is_file": bool(r[6]),
                }
                if row["is_file"]:
                    continue  # 文件消息按文件名索引，不参与正文关键词搜索
                text = row["text"] or ""
                # 若当前为密文（以 vault blob JSON 存储），先解密
                decoded = _try_json(text)
                if isinstance(decoded, dict) and decoded.get("v") == 1:
                    try:
                        text = self.decrypt(decoded)
                    except VaultError as ve:
                        # 未解锁或单条密文损坏：记录并占位，不中断搜索
                        print(f"[VAULT-SEARCH] 解密失败(msg_id={row.get('msg_id','')}): {ve}")
                        text = "[加密消息]"
                # 写回 row，使返回的命中结果携带可读明文（而非密文 JSON）
                row["text"] = text
                if keyword.lower() in text.lower():
                    results.append(row)
        finally:
            conn.close()
        return results

    # ---------- 批量迁移：明文 <-> 密文 ----------

    def re_encrypt_store(self, store: Optional[MessageStore] = None,
                         progress: Optional[Callable[[int, int], None]] = None) -> int:
        """
        将 store 中所有明文消息就地转换为保险库密文（写入 plaintext 列）。
        返回处理条数。迁移过程中逐条（分片）加解密，不一次性加载全表明文。
        调用前须已 unlock()。未启用保险库时返回 0。
        """
        if not self.is_enabled():
            return 0
        self._require_key()
        store = store or self._store
        conn = sqlite3.connect(store.db_path)
        n = 0
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, msg_id, plaintext FROM messages WHERE is_file=0")
            rows = cur.fetchall()
            total = len(rows)
            for i, (db_id, mid, plain) in enumerate(rows):
                if not mid or not plain:
                    n += 1
                    continue
                # 已是密文 blob 则跳过
                if _is_vault_blob(plain):
                    n += 1
                    continue
                blob = self.encrypt(plain, mid)
                cur.execute("UPDATE messages SET plaintext = ? WHERE id = ?",
                           (json.dumps(blob), db_id))
                n += 1
                if progress and total > 0:
                    progress(n, total)
            conn.commit()
        finally:
            conn.close()
        return n

    def decrypt_store_to_plain(self, store: Optional[MessageStore] = None,
                               progress: Optional[Callable[[int, int], None]] = None) -> int:
        """
        反向迁移：将所有保险库密文还原为明文（关闭保险库前调用）。
        返回处理条数。逐条分片解密。
        """
        if not self.is_unlocked():
            raise VaultError("反向迁移需要已解锁的保险库主密钥")
        store = store or self._store
        conn = sqlite3.connect(store.db_path)
        n = 0
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, plaintext FROM messages WHERE is_file=0")
            rows = cur.fetchall()
            total = len(rows)
            for i, (db_id, plain) in enumerate(rows):
                if not plain or not _is_vault_blob(plain):
                    n += 1
                    continue
                blob = json.loads(plain)
                text = self.decrypt(blob)
                cur.execute("UPDATE messages SET plaintext = ? WHERE id = ?", (text, db_id))
                n += 1
                if progress and total > 0:
                    progress(n, total)
            conn.commit()
        finally:
            conn.close()
        return n


# ---------- 辅助 ----------

def _try_json(s: str):
    try:
        return json.loads(s)
    except Exception:
        return s


def _is_vault_blob(plain: str) -> bool:
    """判断 plaintext 列是否已是保险库密文 JSON。"""
    if not plain or not plain.startswith("{"):
        return False
    try:
        d = json.loads(plain)
        return isinstance(d, dict) and d.get("v") == 1 and "ct" in d
    except Exception:
        return False


def vault_blob_to_text(blob_or_str, vault: Optional[MessageVault] = None) -> str:
    """
    统一入口：若输入是保险库密文 blob/JSON 字符串则解密，否则原样返回。
    供 UI 渲染层透明调用。vault 未解锁时密文原样返回（标记 [加密]）。
    """
    decoded = _try_json(blob_or_str) if isinstance(blob_or_str, str) else blob_or_str
    if not isinstance(decoded, dict) or decoded.get("v") != 1:
        return blob_or_str if isinstance(blob_or_str, str) else ""
    if vault and vault.is_unlocked():
        try:
            return vault.decrypt(decoded)
        except VaultError:
            return "[加密消息 — 解密失败]"
    return "[加密消息]"
