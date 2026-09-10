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


class SWNotRunningError(Exception):
    """无法连接到 SpiderWallet（未启动 / 端口不通）。"""


def get_supported_chains(timeout: float = 3.0) -> list:
    """
    调用 SpiderWallet 的 GET /api/supported_chains，获取 SW 已支持的链/币列表。

    返回归一化后的链字典列表，每项至少包含 chain_id / symbol / name 字段
    （缺失字段用空串兜底）。无论 SW 返回 {"chains": [...]} 还是顶层即列表，
    都做容错归一化。

    异常：
        SWNotRunningError  当连接失败（SW 未启动 / 端口不可达）时抛出，
                           调用方据此提示"无法连接 SpiderWallet"。
    """
    cfg = _get_sw_config()
    try:
        url = f"http://{cfg['host']}:{cfg['port']}/api/supported_chains"
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        raise SWNotRunningError(f"无法连接 SpiderWallet: {e}") from e

    raw_list = data.get("chains", data) if isinstance(data, dict) else data
    if not isinstance(raw_list, list):
        return []

    chains = []
    for item in raw_list:
        if isinstance(item, str):
            # 纯字符串列表：当作 chain_id
            chains.append({"chain_id": item, "symbol": "", "name": item})
        elif isinstance(item, dict):
            chains.append({
                "chain_id": str(item.get("chain_id", item.get("chain", "")) or ""),
                "symbol": str(item.get("symbol", item.get("currency", "")) or ""),
                "name": str(item.get("name", item.get("network", "")) or ""),
            })
    return chains


def is_chain_supported(network: str, currency: str,
                       supported: Optional[list] = None) -> bool:
    """
    判断指定链/币是否被 SpiderWallet 支持。

    匹配规则（大小写不敏感）：
      - network（链名，如 "Bitcoin"）匹配任一支持项的 chain_id / name；
      - currency（币种符号，如 "BTC"）匹配任一支持项的 symbol。
    任一侧命中即视为支持（链或币其一可识别）。
    """
    if supported is None:
        try:
            supported = get_supported_chains()
        except SWNotRunningError:
            # 调用方应在连接失败时单独处理；这里保守返回 False
            return False
    net = (network or "").strip().lower()
    cur = (currency or "").strip().lower()
    if not net and not cur:
        return False
    for item in supported:
        chain_id = str(item.get("chain_id", "")).lower()
        symbol = str(item.get("symbol", "")).lower()
        name = str(item.get("name", "")).lower()
        if net and (net == chain_id or net == name or net in (chain_id, name)):
            return True
        if cur and (cur == symbol or cur == chain_id or cur == name):
            return True
    return False


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
