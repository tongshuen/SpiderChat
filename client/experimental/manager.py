"""
实验性功能管理。

实验性功能默认隐藏，启用需要：
1. 验证解锁密码（PIN）
2. 键入"打开实验性功能"
3. 滑块冷却期 5 秒
4. 滑块滑到最右边才能启用
关闭实验性功能直接关闭即可。

实验性功能包括：
- HTTP API 服务
- SpiderWallet 集成
- 其他高级功能
"""

import json
import os
from client.utils.config import get_data_dir

EXPERIMENTAL_FILE = "experimental.json"

# 实验性功能列表
EXPERIMENTAL_FEATURES = [
    {
        "id": "http_api",
        "name": "HTTP API 服务",
        "description": "启用本地 HTTP API，允许外部程序通过 REST API 操控客户端",
        "default": False,
    },
    {
        "id": "spider_wallet",
        "name": "SpiderWallet 集成",
        "description": "启用加密货币钱包集成，支持加密货币卡片跳转和地址自动补全（需先安装 SpiderWallet）",
        "default": False,
        "requires": ["http_api"],
    },
    {
        "id": "radio_link",
        "name": "无线电链路（SDR）",
        "description": "启用基于软件无线电（SDR）的业余无线电通信链路，含 FEC 纠错和 C 语言加速物理层",
        "default": False,
    },
]


def _exp_path():
    return os.path.join(get_data_dir(), EXPERIMENTAL_FILE)


def _load():
    path = _exp_path()
    if not os.path.exists(path):
        return {"enabled": False, "features": {}}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {"enabled": False, "features": {}}


def _save(data):
    path = _exp_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def is_experimental_enabled() -> bool:
    """实验性功能总开关是否打开。"""
    return _load().get("enabled", False)


def enable_experimental():
    """启用实验性功能总开关。"""
    data = _load()
    data["enabled"] = True
    _save(data)


def disable_experimental():
    """关闭实验性功能总开关（同时关闭所有子功能）。"""
    data = _load()
    data["enabled"] = False
    data["features"] = {}
    _save(data)


def is_feature_enabled(feature_id: str) -> bool:
    """检查某个实验性功能是否启用。"""
    if not is_experimental_enabled():
        return False
    data = _load()
    return data.get("features", {}).get(feature_id, False)


def enable_feature(feature_id: str) -> tuple:
    """启用某个实验性功能。返回 (success, message)。"""
    if not is_experimental_enabled():
        return False, "实验性功能总开关未打开"
    feature = next((f for f in EXPERIMENTAL_FEATURES if f["id"] == feature_id), None)
    if not feature:
        return False, f"未知功能: {feature_id}"
    # 检查依赖
    for req in feature.get("requires", []):
        if not is_feature_enabled(req):
            return False, f"需要先启用: {req}"
    data = _load()
    data.setdefault("features", {})[feature_id] = True
    _save(data)
    return True, f"已启用: {feature['name']}"


def disable_feature(feature_id: str):
    """关闭某个实验性功能。"""
    data = _load()
    if feature_id in data.get("features", {}):
        data["features"][feature_id] = False
        _save(data)


def get_all_features() -> list:
    """获取所有实验性功能及其状态。"""
    data = _load()
    result = []
    for f in EXPERIMENTAL_FEATURES:
        result.append({
            "id": f["id"],
            "name": f["name"],
            "description": f["description"],
            "enabled": data.get("features", {}).get(f["id"], False),
            "requires": f.get("requires", []),
        })
    return result
