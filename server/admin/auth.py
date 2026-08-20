"""
管理员认证 — PIN 验证 + 会话令牌管理。
"""

import hashlib
import time
import base64
import uuid as uuid_module
from server.keyring_store.credentials import verify_admin_pin, get_keyring_service
import keyring


class AdminAuth:
    """处理管理员 PIN 认证和会话令牌。"""

    def __init__(self, config: dict):
        self.config = config
        self.session_timeout_min = config.get("security", {}).get("session_timeout_min", SESSION_TIMEOUT_MIN)
        self.max_attempts = config.get("security", {}).get("max_login_attempts", MAX_LOGIN_ATTEMPTS)
        self.lockout_sec = config.get("security", {}).get("lockout_duration_sec", LOCKOUT_SEC)

        self._sessions = {}
        self._sessions_lock = threading.Lock()

        self._failures = {}
        self._fail_lock = threading.Lock()

    def authenticate(self, pin: str, ip: str) -> str | None:
        """
        验证管理员 PIN。成功返回会话令牌，失败返回 None。
        """

        with self._fail_lock:
            if ip in self._failures:
                fail = self._failures[ip]
                if fail["count"] >= self.max_attempts:
                    if time.time() - fail["last_attempt"] < self.lockout_sec:
                        return None
                    else:

                        fail["count"] = 0

        if not verify_admin_pin(pin):
            with self._fail_lock:
                if ip not in self._failures:
                    self._failures[ip] = {"count": 0, "last_attempt": 0}
                self._failures[ip]["count"] += 1
                self._failures[ip]["last_attempt"] = time.time()
            return None

        token = base64.b64encode(uuid_module.uuid4().bytes).decode().rstrip("=")
        now = time.time()
        with self._sessions_lock:
            self._sessions[token] = {
                "ip": ip,
                "created_at": now,
                "expires_at": now + (self.session_timeout_min * 60),
            }


        with self._fail_lock:
            self._failures.pop(ip, None)

        return token

    def validate_session(self, token: str) -> bool:
        """检查会话令牌是否有效且未过期。"""
        with self._sessions_lock:
            sess = self._sessions.get(token)
            if not sess:
                return False
            if time.time() > sess["expires_at"]:
                del self._sessions[token]
                return False
            sess["expires_at"] = time.time() + (self.session_timeout_min * 60)
            return True

    def destroy_session(self, token: str):
        with self._sessions_lock:
            self._sessions.pop(token, None)

    def change_pin(self, old_pin: str, new_pin: str) -> bool:
        """修改管理员 PIN。成功返回 True。"""
        if not verify_admin_pin(old_pin):
            return False
        if not (new_pin.isdigit() and len(new_pin) == 6):
            return False

        salt = os.urandom(16)
        new_hash = hashlib.pbkdf2_hmac("sha256", new_pin.encode(), salt, 100000, dklen=32)

        keyring.set_password(get_keyring_service(), "admin_pin_hash", base64.b64encode(new_hash).decode())
        keyring.set_password(get_keyring_service(), "admin_pin_salt", base64.b64encode(salt).decode())

        with self._sessions_lock:
            self._sessions.clear()

        return True

    def cleanup_sessions(self):
        now = time.time()
        with self._sessions_lock:
            expired = [t for t, s in self._sessions.items() if s["expires_at"] < now]
            for t in expired:
                del self._sessions[t]

    def active_sessions(self) -> int:
        with self._sessions_lock:
            return len(self._sessions)


import threading
import os
