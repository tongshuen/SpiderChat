"""
API Key 存储管理。

安全设计：
- 完整 API key（128位16进制=64字节）只在生成时显示一次
- 存储 SHA-256 哈希（明文，因为哈希本身自带安全性）
- 存储前8位+后4位（明文，仅12位用于识别，暴露风险可忽略）
- 多个 key 可同时存在
- 权限粒度：每个权限0.1，全部API总权限>1.5（15项）时警告攻击面过宽（不拦截）
"""

import json
import os
import hashlib
import secrets
import time
from client.utils.config import get_data_dir

API_KEYS_FILE = "api_keys.json"

# 所有可用权限（细粒度）
ALL_PERMISSIONS = [
    "messages:send",       # 发送消息
    "messages:read",       # 读取历史消息
    "messages:delete",     # 删除消息
    "contacts:read",       # 读取联系人列表
    "contacts:add",        # 添加联系人
    "contacts:delete",     # 删除联系人
    "profile:read",        # 读取个人资料（名称/头像/UUID）
    "profile:write",       # 修改个人资料
    "settings:read",       # 读取设置
    "settings:write",      # 修改设置
    "deadman:read",        # 读取死人开关配置
    "deadman:write",       # 修改死人开关配置
    "groups:read",         # 读取群聊
    "groups:write",        # 管理群聊
    "files:send",          # 发送文件
    "files:download",      # 下载文件
]

PERMISSION_WARNING_THRESHOLD = 1.5  # 15项权限


def _keys_path():
    return os.path.join(get_data_dir(), API_KEYS_FILE)


def _load_keys():
    path = _keys_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return []


def _save_keys(keys):
    path = _keys_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(keys, f, indent=2)


def generate_api_key():
    """生成 128 位 16 进制随机数（64字节=128hex chars）。"""
    return secrets.token_hex(64)


def hash_key(api_key: str) -> str:
    """对 API key 做 SHA-256 哈希。"""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def key_mask(api_key: str) -> str:
    """返回前8位+后4位的掩码形式。"""
    if len(api_key) < 12:
        return api_key
    return api_key[:8] + "..." + api_key[-4:]


def create_api_key(name: str, permissions: list, expiry_hours: float = -1):
    """
    创建新 API key。

    Args:
        name: key 名称/描述
        permissions: 权限列表
        expiry_hours: 有效期（小时），负数=永久有效

    Returns:
        dict: {key, key_hash, mask, name, permissions, expiry, created_at}
        注意：完整 key 只在此返回，之后无法再获取
    """
    # 校验权限
    invalid = [p for p in permissions if p not in ALL_PERMISSIONS]
    if invalid:
        raise ValueError(f"无效权限: {invalid}")

    api_key = generate_api_key()
    key_hash = hash_key(api_key)
    mask = key_mask(api_key)

    expiry = None
    if expiry_hours >= 0:
        expiry = time.time() + expiry_hours * 3600

    entry = {
        "key_hash": key_hash,
        "mask": mask,
        "name": name,
        "permissions": permissions,
        "expiry": expiry,
        "created_at": time.time(),
    }

    keys = _load_keys()
    keys.append(entry)
    _save_keys(keys)

    return {
        "key": api_key,
        "key_hash": key_hash,
        "mask": mask,
        "name": name,
        "permissions": permissions,
        "expiry": expiry,
        "created_at": entry["created_at"],
    }


def verify_api_key(api_key: str):
    """
    验证 API key，返回对应的 key 条目（含权限），无效返回 None。
    同时检查过期时间。
    """
    if not api_key:
        return None
    key_hash = hash_key(api_key)
    keys = _load_keys()
    now = time.time()
    for entry in keys:
        if entry["key_hash"] == key_hash:
            # 检查过期
            if entry.get("expiry") and entry["expiry"] < now:
                return None
            return entry
    return None


def has_permission(entry: dict, permission: str) -> bool:
    """检查 key 是否有指定权限。"""
    if not entry:
        return False
    return permission in entry.get("permissions", [])


def list_api_keys():
    """列出所有 API key（只返回掩码，不返回完整 key）。"""
    keys = _load_keys()
    result = []
    for entry in keys:
        result.append({
            "key_hash": entry["key_hash"],
            "mask": entry["mask"],
            "name": entry["name"],
            "permissions": entry["permissions"],
            "expiry": entry.get("expiry"),
            "created_at": entry["created_at"],
        })
    return result


def delete_api_key(key_hash: str) -> bool:
    """删除指定 key_hash 的 API key。"""
    keys = _load_keys()
    original_len = len(keys)
    keys = [k for k in keys if k["key_hash"] != key_hash]
    if len(keys) < original_len:
        _save_keys(keys)
        return True
    return False


def get_total_permission_count() -> int:
    """获取所有 API key 的权限总数。"""
    keys = _load_keys()
    return sum(len(k.get("permissions", [])) for k in keys)


def is_attack_surface_warning() -> bool:
    """检查是否触发攻击面过宽警告（总权限>15项）。"""
    return get_total_permission_count() * 0.1 > PERMISSION_WARNING_THRESHOLD
