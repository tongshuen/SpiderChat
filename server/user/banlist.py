"""
封禁列表管理 — UserManager 封禁函数的封装。
"""

class BanList:
    """管理封禁列表，支持可选原因记录。"""

    def __init__(self, user_manager):
        self.um = user_manager
        self._reasons = {}

    def ban(self, uuid_str: str, reason: str = "") -> bool:
        ok = self.um.ban_user(uuid_str)
        if ok and reason:
            self._reasons[uuid_str] = reason
        return ok

    def unban(self, uuid_str: str) -> bool:
        self._reasons.pop(uuid_str, None)
        return self.um.unban_user(uuid_str)

    def is_banned(self, uuid_str: str) -> bool:
        return self.um.is_banned(uuid_str)

    def get_reason(self, uuid_str: str) -> str:
        return self._reasons.get(uuid_str, "")

    def list_banned(self) -> list:
        """获取所有被封禁的 UUID。"""
        import sqlite3
        conn = sqlite3.connect(self.um.db_path)
        c = conn.cursor()
        c.execute("SELECT uuid, name FROM users WHERE is_banned=1")
        rows = c.fetchall()
        conn.close()
        return [{"uuid": r[0], "name": r[1], "reason": self._reasons.get(r[0], "")} for r in rows]
