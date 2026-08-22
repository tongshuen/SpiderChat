"""
Spider — 阅后即焚引擎 (Ephemeral / Burn-after-reading)

设计原则
========
* "阅后即焚" 的触发点：客户端**发出已读回执**（READ_RECEIPT）的那一刻。
  此时消息明文仍缓存在当前 MainWindow 的内存里，屏幕上的气泡不会立即消失；
  对应的数据库行在本次会话关闭、或下一次打开该联系人时已被删除，因而"下次打开消失"。
* 支持三种命中规则（可叠加）：
    1) global        —— 所有消息一律阅后即焚
    2) per_contact   —— 对指定联系人 UUID 列表阅后即焚
    3) regex         —— 消息明文命中任一正则表达式时阅后即焚
* 两种删除模式：
    - quick   : 直接 DELETE（SQLite 立即移除行；文件块可能被 OS 回收）
    - secure  : 先读取行并用随机数据覆写关键字段（plaintext/nonce/signature/
                filename/filesize），再 DELETE；对文件消息还会用随机字节覆写
                落盘文件后再删除。代价更高，但降低明文在 DB 页面/下载目录
                中残留的概率。
* 本模块只负责"判断 + 删除"，不修改 UI；UI 层在发出已读回执前后调用
  `maybe_burn_after_read(...)` 即可。

线程安全
========
MessageStore 每次操作都打开独立连接，本模块的删除操作亦是短事务，
可在 GUI 线程与网络回调线程中安全调用（GUI 侧避免同时刷新即可）。
"""

import os
import re
import sqlite3
import base64
import time
from typing import Iterable, Optional

# 不导入 client.utils.config：避免 config <-> storage 循环导入。
# get_data_dir 在首次使用时局部导入（此时 config 模块已完全初始化）。
def _get_data_dir():
    from client.utils.config import get_data_dir
    return get_data_dir()  # noqa: E402


# ---------- 配置键（写入 settings.json）----------
CONF_EPHEMERAL_ENABLED = "ephemeral_enabled"          # 总开关
CONF_EPHEMERAL_MODE = "ephemeral_delete_mode"         # "quick" | "secure"
CONF_EPHEMERAL_GLOBAL = "ephemeral_global"            # bool: 是否全部消息焚毁
CONF_EPHEMERAL_CONTACTS = "ephemeral_contacts"        # list[str]: UUID 列表
CONF_EPHEMERAL_REGEX = "ephemeral_regex"              # list[str]: 正则模式
CONF_EPHEMERAL_FILES_SECURE_WIPE = "ephemeral_secure_wipe_files"  # bool


def default_ephemeral_config() -> dict:
    """返回阅后即焚功能的默认配置片段，供 config.py 合并。"""
    return {
        CONF_EPHEMERAL_ENABLED: False,
        CONF_EPHEMERAL_MODE: "quick",
        CONF_EPHEMERAL_GLOBAL: False,
        CONF_EPHEMERAL_CONTACTS: [],
        CONF_EPHEMERAL_REGEX: [],
        CONF_EPHEMERAL_FILES_SECURE_WIPE: True,
    }


class EphemeralEngine:
    """判断一条已读回执对应的消息是否应焚毁，并执行删除。"""

    def __init__(self, config: Optional[dict] = None, store=None):
        self._config = config or {}
        if store is None:
            from client.storage.messages import MessageStore
            store = MessageStore()
        self._store = store

    # ---------- 规则判断 ----------

    def should_burn(self, contact_uuid: str, plaintext: str = "") -> bool:
        """根据当前配置判断 (contact_uuid, plaintext) 是否应焚毁。"""
        if not self._config.get(CONF_EPHEMERAL_ENABLED, False):
            return False
        if self._config.get(CONF_EPHEMERAL_GLOBAL, False):
            return True
        contacts = self._config.get(CONF_EPHEMERAL_CONTACTS, []) or []
        if contact_uuid in contacts:
            return True
        patterns = self._config.get(CONF_EPHEMERAL_REGEX, []) or []
        if patterns and plaintext:
            for pat in patterns:
                try:
                    if re.search(pat, plaintext):
                        return True
                except re.error:
                    # 单个非法正则不影响其它规则
                    continue
        return False

    # ---------- 删除执行 ----------

    def burn_message(self, msg_id: str) -> bool:
        """
        按当前删除模式销毁一条消息（按客户端 msg_id）。
        返回 True 表示已删除（或行已不存在）。
        """
        mode = self._config.get(CONF_EPHEMERAL_MODE, "quick")
        if mode == "secure":
            return self._secure_delete(msg_id)
        return self._quick_delete(msg_id)

    def burn_contact(self, contact_uuid: str) -> int:
        """销毁某联系人的全部消息，返回删除条数（用于"全部焚毁"入口）。"""
        mode = self._config.get(CONF_EPHEMERAL_MODE, "quick")
        if mode == "secure":
            # 逐条覆写再删，保证每行的明文都被打乱
            ids = self._list_msg_ids(contact_uuid)
            for mid in ids:
                self._secure_delete(mid)
            return len(ids)
        return self._delete_all_by_contact(contact_uuid)

    # ---------- 内部：quick ----------

    def _quick_delete(self, msg_id: str) -> bool:
        conn = sqlite3.connect(self._store.db_path)
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM messages WHERE msg_id = ?", (msg_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()

    def _delete_all_by_contact(self, contact_uuid: str) -> int:
        conn = sqlite3.connect(self._store.db_path)
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM messages WHERE contact_uuid = ?", (contact_uuid,))
            n = cur.rowcount
            conn.commit()
            return n
        finally:
            conn.close()

    def _list_msg_ids(self, contact_uuid: str) -> list:
        conn = sqlite3.connect(self._store.db_path)
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT msg_id FROM messages WHERE contact_uuid = ?",
                (contact_uuid,))
            return [r[0] for r in cur.fetchall()]
        finally:
            conn.close()

    # ---------- 内部：secure（覆写后删除）----------

    def _secure_delete(self, msg_id: str) -> bool:
        """
        安全删除：用随机数据覆写 plaintext/nonce/signature/filename/filesize
        等字段后再 DELETE。SQLite 的 DELETE 会将原行标记为可重用，覆写能
        降低明文在数据库页面中残留的概率（不保证 SSD 磨损均衡层清除）。
        """
        conn = sqlite3.connect(self._store.db_path)
        try:
            cur = conn.cursor()
            # 先取文件消息的落盘路径，以便随后覆写文件
            cur.execute(
                "SELECT id, is_file, filename, plaintext FROM messages WHERE msg_id = ?",
                (msg_id,))
            row = cur.fetchone()
            if not row:
                return False
            db_id, is_file, fname, plaintext = row
            # 覆写可变文本/二进制字段
            garbage_text = base64.b64encode(os.urandom(256)).decode("ascii")
            garbage_nonce = base64.b64encode(os.urandom(12)).decode("ascii")
            garbage_sig = base64.b64encode(os.urandom(64)).decode("ascii")
            cur.execute(
                """UPDATE messages SET plaintext = ?, nonce = ?, signature = ?,
                   filename = ?, filesize = 0 WHERE id = ?""",
                (garbage_text, garbage_nonce, garbage_sig, "", db_id))
            conn.commit()
            # 对文件消息：用随机字节覆写落盘文件后删除
            if is_file and fname:
                self._secure_wipe_file(fname)
            # 正式删除行
            cur.execute("DELETE FROM messages WHERE id = ?", (db_id,))
            conn.commit()
            return True
        finally:
            conn.close()

    def _secure_wipe_file(self, filename: str):
        """用随机数据覆写并删除一条已下载的附件文件（best-effort）。"""
        if not self._config.get(CONF_EPHEMERAL_FILES_SECURE_WIPE, True):
            return
        dl_dir = os.path.join(_get_data_dir(), "downloads")
        fp = os.path.join(dl_dir, filename)
        if not os.path.exists(fp):
            return
        try:
            size = os.path.getsize(fp)
            if size > 0:
                with open(fp, "rb+") as f:
                    f.write(os.urandom(size))
            os.remove(fp)
        except Exception as e:
            print(f"[EPHEMERAL] secure wipe file failed for {fp}: {e}")

    # ---------- 便捷入口：配合已读回执调用 ----------

    def burn_if_matches(self, contact_uuid: str, msg_id: str,
                        plaintext: str = "") -> bool:
        """
        组合判断 + 删除。返回 True 表示已焚毁。
        由 MainWindow 在发送已读回执（单条 / 批量标记已读）后调用。
        """
        if not self.should_burn(contact_uuid, plaintext):
            return False
        return self.burn_message(msg_id)


# ---------- 工具函数（供 settings.py / main_window.py 使用）----------

def validate_regex_patterns(patterns: Iterable[str]) -> tuple[list, list]:
    """
    校验正则列表。返回 (valid_patterns, error_messages)。
    非法正则被过滤并给出提示，不抛出异常，便于 UI 容错保存。
    """
    valid, errors = [], []
    for p in patterns or []:
        p = p.strip()
        if not p:
            continue
        try:
            re.compile(p)
            valid.append(p)
        except re.error as e:
            errors.append(f"无效正则 {p!r}: {e}")
    return valid, errors


def normalize_delete_mode(val) -> str:
    return "secure" if str(val).strip().lower() == "secure" else "quick"


def add_ephemeral_contact(config: dict, uuid_str: str) -> dict:
    lst = list(config.get(CONF_EPHEMERAL_CONTACTS, []) or [])
    if uuid_str and uuid_str not in lst:
        lst.append(uuid_str)
    config[CONF_EPHEMERAL_CONTACTS] = lst
    return config


def remove_ephemeral_contact(config: dict, uuid_str: str) -> dict:
    lst = [u for u in (config.get(CONF_EPHEMERAL_CONTACTS, []) or []) if u != uuid_str]
    config[CONF_EPHEMERAL_CONTACTS] = lst
    return config
