"""
SpiderChat — SpiderWallet 集成模块。

通过 SpiderWallet 本地 HTTP API 实现：
- 获取钱包地址列表（用于加密卡片地址自动补全）
- 发送加密卡片信息到 SpiderWallet（跳转到 SW）
- 检测 SpiderWallet 是否安装并运行
"""

import json
import urllib.request
import urllib.error
from typing import Optional

from client.utils.config import load_config, save_config

DEFAULT_SW_PORT = 8766


def _get_sw_config() -> dict:
    config = load_config()
    return config.get("spiderwallet", {
        "enabled": False,
        "host": "127.0.0.1",
        "port": DEFAULT_SW_PORT,
        "path": "",
    })


def save_sw_config(enabled: bool, host: str = "127.0.0.1", port: int = DEFAULT_SW_PORT, path: str = ""):
    config = load_config()
    config["spiderwallet"] = {
        "enabled": enabled,
        "host": host,
        "port": port,
        "path": path,
    }
    save_config(config)


def is_sw_enabled() -> bool:
    """SpiderWallet 集成是否启用。"""
    from client.experimental.manager import is_feature_enabled
    if not is_feature_enabled("spider_wallet"):
        return False
    return _get_sw_config().get("enabled", False)


def is_sw_running() -> bool:
    """检测 SpiderWallet 是否正在运行。"""
    cfg = _get_sw_config()
    try:
        url = f"http://{cfg['host']}:{cfg['port']}/api/info"
        with urllib.request.urlopen(url, timeout=2) as resp:
            data = json.loads(resp.read())
            return data.get("name") == "SpiderWallet"
    except Exception:
        return False


def get_wallet_addresses() -> list:
    """从 SpiderWallet 获取所有钱包地址。返回 [{"chain": str, "address": str}, ...]"""
    cfg = _get_sw_config()
    try:
        url = f"http://{cfg['host']}:{cfg['port']}/api/addresses"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
            return data.get("addresses", [])
    except Exception:
        return []


def open_in_sw(currency: str, address: str, network: str) -> tuple:
    """
    发送加密卡片信息到 SpiderWallet（跳转到 SW）。
    返回 (success: bool, message: str)
    """
    cfg = _get_sw_config()
    try:
        url = f"http://{cfg['host']}:{cfg['port']}/api/open"
        payload = json.dumps({
            "currency": currency,
            "address": address,
            "network": network,
        }).encode()
        req = urllib.request.Request(url, data=payload,
                                      headers={"Content-Type": "application/json"},
                                      method="POST")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read())
            return data.get("success", False), data.get("message", "")
    except Exception as e:
        return False, f"无法连接 SpiderWallet: {e}"


def launch_spiderwallet() -> bool:
    """尝试启动 SpiderWallet（如果配置了路径）。"""
    import os
    import subprocess
    cfg = _get_sw_config()
    path = cfg.get("path", "")
    if not path or not os.path.exists(path):
        return False
    try:
        subprocess.Popen([path], cwd=os.path.dirname(path) or None)
        return True
    except Exception:
        return False
