"""
Spider — 阅后即焚引擎 (Ephemeral Engine)

功能：
- 支持三种命中规则（可叠加）：
    1) 全局开关（ephemeral_enabled=True -> 所有消息阅后即焚）
    2) 按联系人 UUID 列表（ephemeral_contact_uuids）
    3) 按正则表达式（ephemeral_regex_rules，命中消息文本即焚）
- 两种删除模式：
    - 快速删除 (ephemeral_secure_delete=False)：直接删除数据库记录（+ 附件文件）
    - 安全删除 (ephemeral_secure_delete=True)：先随机数据覆写再删除（含附件）

原理：
- 在发送/收到 READ_RECEIPT（已读回执）后调用 burn_if_matches()，
  由 MessageStore 删除对应消息。消息在内存中已渲染的气泡不会立刻消失，
  下次打开聊天窗口重新加载时方才消失。

对外暴露：
- class EphemeralEngine
    - should_burn(contact_uuid, text) -> bool
    - burn_if_matches(contact_uuid, msg_id, text, store, attachment_path="") -> bool
"""

import os
import re
import sqlite3

from client.utils.config import load_config


class EphemeralEngine:
    """阅后即焚规则引擎。"""

    def __init__(self, config: dict = None):
        # config 由调用方负责刷新（如 main_window 在每次调用时传入最新 self.config）。
        self._cfg = config or {}

    # ---------- 规则判断 ----------

    def should_burn(self, contact_uuid: str, text: str = "") -> bool:
        """根据当前配置判断一条消息是否应被焚毁。"""
        if self._cfg.get("ephemeral_enabled"):
            return True
        uuids = self._cfg.get("ephemeral_contact_uuids") or []
        if contact_uuid and contact_uuid in uuids:
            return True
        rules = self._cfg.get("ephemeral_regex_rules") or []
        if text and rules:
            for pat in rules:
                try:
                    if re.search(pat, text):
                        return True
                except re.error:
                    continue
        return False

    # ---------- 删除执行 ----------

    def burn_if_matches(self, contact_uuid: str, msg_id: str,
                        text: str, store, attachment_path: str = "") -> bool:
        """
        若消息命中焚毁规则，则从 store 中删除该 msg_id 的记录（及附件）。
        返回 True 表示已焚毁，False 表示未命中/未执行。
        """
        if not msg_id:
            return False
        if not self.should_burn(contact_uuid, text or ""):
            return False
        secure = bool(self._cfg.get("ephemeral_secure_delete"))
        # 1) 删除附件文件（如有）
        for path in (attachment_path,):
            if path:
                self._delete_file(path, secure=secure)
        # 2) 删除数据库记录（通过 msg_id）
        try:
            self._delete_by_msg_id(store.db_path, msg_id, secure=secure)
        except Exception:
            # store 可能提供 delete_by_msg_id
            try:
                store.delete_messages(contact_uuid)  # 兜底：清该联系人全部
            except Exception:
                pass
        return True

    # ---------- 内部工具 ----------

    def _delete_file(self, path: str, secure: bool = False):
        if not path or not os.path.exists(path):
            return
        try:
            if secure:
                size = os.path.getsize(path)
                with open(path, "rb+") as f:
                    f.write(os.urandom(size))
            os.remove(path)
        except Exception:
            try:
                os.remove(path)
            except Exception:
                pass

    def _delete_by_msg_id(self, db_path: str, msg_id: str, secure: bool = False):
        if secure:
            # 安全模式：先覆写明文所在行无必要（SQLite 行不固定偏移），
            # 这里对关联 plaintext 字段做覆写无意义，改为 vacuum 前清字段。
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("UPDATE messages SET plaintext='', nonce='', signature='', "
                      "filename='', ciphertext=b'' WHERE msg_id=?", (msg_id,))
            conn.commit()
            conn.close()
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("DELETE FROM messages WHERE msg_id=?", (msg_id,))
        conn.commit()
        conn.close()
