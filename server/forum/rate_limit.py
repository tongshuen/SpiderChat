"""
论坛负载限流 — 基于 load_ratio=online/max_online 的分级限流。

阈值：
  slow_messages  0.5   消息减速
  slow_posting   0.6   发帖减速
  block_search   0.7   禁止搜索
  block_register 0.75  禁止注册
  block_dht      0.8   禁止 DHT
  block_login    0.9   禁止登录
  logout_users   0.95  踢人
  block_all      1.0   全部禁止

hysteresis 0.05 防抖。
优雅降级按序执行：先限流后禁功能最后踢人。
管理员豁免。
状态切换广播通知。
"""

import time
import threading
from server.forum.online import get_load_ratio
from shared.protocol import (
    FORUM_LOAD_SLOW_MESSAGES, FORUM_LOAD_SLOW_POSTING, FORUM_LOAD_BLOCK_SEARCH,
    FORUM_LOAD_BLOCK_REGISTER, FORUM_LOAD_BLOCK_DHT, FORUM_LOAD_BLOCK_LOGIN,
    FORUM_LOAD_LOGOUT_USERS, FORUM_LOAD_BLOCK_ALL, FORUM_LOAD_HYSTERESIS,
)

# 当前负载状态
_current_level = 0.0
_level_lock = threading.Lock()
_last_broadcast = 0
BROADCAST_INTERVAL = 10  # 秒

# 负载级别定义（从低到高）
LOAD_LEVELS = [
    ("slow_messages", FORUM_LOAD_SLOW_MESSAGES),
    ("slow_posting", FORUM_LOAD_SLOW_POSTING),
    ("block_search", FORUM_LOAD_BLOCK_SEARCH),
    ("block_register", FORUM_LOAD_BLOCK_REGISTER),
    ("block_dht", FORUM_LOAD_BLOCK_DHT),
    ("block_login", FORUM_LOAD_BLOCK_LOGIN),
    ("logout_users", FORUM_LOAD_LOGOUT_USERS),
    ("block_all", FORUM_LOAD_BLOCK_ALL),
]


def update_load(max_online: int) -> dict:
    """更新负载状态，返回当前各限制状态。"""
    global _current_level
    ratio = get_load_ratio(max_online)

    with _level_lock:
        # 迟滞：上升用阈值，下降用阈值-hysteresis
        if ratio > _current_level:
            _current_level = ratio
        elif ratio < _current_level - FORUM_LOAD_HYSTERESIS:
            _current_level = ratio

    return get_current_status()


def get_current_status() -> dict:
    """获取当前各限制状态。"""
    with _level_lock:
        level = _current_level
    status = {"load_ratio": level, "restrictions": {}}
    for name, threshold in LOAD_LEVELS:
        status["restrictions"][name] = level >= threshold
    return status


def is_allowed(action: str, is_admin: bool = False) -> tuple:
    """
    检查某操作是否被允许。
    返回 (allowed: bool, delay_seconds: float, reason: str)
    管理员豁免。
    """
    if is_admin:
        return True, 0, ""

    status = get_current_status()
    r = status["restrictions"]

    if action == "message":
        if r.get("block_all"):
            return False, 0, "服务器负载过高，暂时禁止所有操作"
        if r.get("slow_messages"):
            return True, 2.0, "服务器负载较高，消息发送已减速"
        return True, 0, ""

    elif action == "post":
        if r.get("block_all"):
            return False, 0, "服务器负载过高，暂时禁止所有操作"
        if r.get("slow_posting"):
            return True, 5.0, "服务器负载较高，发帖已减速"
        return True, 0, ""

    elif action == "search":
        if r.get("block_search") or r.get("block_all"):
            return False, 0, "服务器负载过高，搜索暂时不可用"
        return True, 0, ""

    elif action == "register":
        if r.get("block_register") or r.get("block_all"):
            return False, 0, "服务器负载过高，注册暂时不可用"
        return True, 0, ""

    elif action == "login":
        if r.get("block_login") or r.get("block_all"):
            return False, 0, "服务器负载过高，登录暂时不可用"
        return True, 0, ""

    elif action == "dht":
        if r.get("block_dht") or r.get("block_all"):
            return False, 0, "服务器负载过高，DHT 暂时不可用"
        return True, 0, ""

    elif action == "logout_trigger":
        return r.get("logout_users", False), 0, ""

    return True, 0, ""


def should_broadcast() -> bool:
    """是否应该广播负载状态变化（10秒间隔）。"""
    global _last_broadcast
    now = time.time()
    if now - _last_broadcast > BROADCAST_INTERVAL:
        _last_broadcast = now
        return True
    return False
