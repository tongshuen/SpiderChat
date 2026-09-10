"""
在线人数管理 — TCP 活跃 + 60 秒内心跳，UUID 去重，管理员不计入。
load_ratio = online / max_online 用于限流。
heat = online / heat_reference 用于显示。
"""

import time
import threading
from server.forum.database import now_ts

# 在线用户集合：uuid -> last_seen_timestamp
_online_users = {}
_online_lock = threading.Lock()
HEARTBEAT_TIMEOUT = 60  # 秒


def mark_online(uuid_str: str, is_admin: bool = False):
    """标记用户在线。管理员不计入在线人数。"""
    if is_admin:
        return
    with _online_lock:
        _online_users[uuid_str] = now_ts()


def mark_offline(uuid_str: str):
    """标记用户离线。"""
    with _online_lock:
        _online_users.pop(uuid_str, None)


def get_online_count() -> int:
    """获取当前在线人数（清理超时后）。"""
    _cleanup()
    with _online_lock:
        return len(_online_users)


def get_online_users() -> list:
    """获取在线用户 UUID 列表。"""
    _cleanup()
    with _online_lock:
        return list(_online_users.keys())


def _cleanup():
    """清理超过 60 秒未心跳的用户。"""
    ts = now_ts()
    with _online_lock:
        expired = [u for u, t in _online_users.items() if ts - t > HEARTBEAT_TIMEOUT]
        for u in expired:
            del _online_users[u]


def get_load_ratio(max_online: int) -> float:
    """计算负载比 online/max_online。"""
    if max_online <= 0:
        return 0.0
    return min(get_online_count() / max_online, 1.0)


def get_heat(heat_reference: float) -> float:
    """计算热度比 online/heat_reference。"""
    if heat_reference <= 0:
        return 0.0
    return get_online_count() / heat_reference
