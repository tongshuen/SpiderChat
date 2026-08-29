"""
设置窗口辅助模块。

提供：
- 颜色获取/保存（原有）
- 安全功能配置校验（阅后即焚规则、删除模式、保险库 PIN）
- apply_settings：统一校验后落盘
"""

import re

from client.utils.config import load_config, save_config
from shared.protocol import (
    DEFAULT_SENT_COLOR, DEFAULT_RECV_COLOR, DEFAULT_BUTTON_COLOR,
    MIN_ONION_LAYERS, MAX_ONION_LAYERS, AVAILABLE_OBFUSCATION_MODES,
    DEFAULT_OBFUSCATION_MODE,
)


# ===== 颜色 =====

def get_colors() -> dict:
    cfg = load_config()
    return {
        "sent": cfg.get("sent_message_color", DEFAULT_SENT_COLOR),
        "recv": cfg.get("recv_message_color", DEFAULT_RECV_COLOR),
        "button": cfg.get("send_button_color", DEFAULT_BUTTON_COLOR),
    }


def validate_hex_color(hex_str: str) -> bool:
    if not hex_str.startswith("#"):
        return False
    if len(hex_str) not in (4, 7):
        return False
    try:
        int(hex_str[1:], 16)
        return True
    except ValueError:
        return False


def save_colors(sent: str, recv: str, button: str):
    cfg = load_config()
    if validate_hex_color(sent):
        cfg["sent_message_color"] = sent
    if validate_hex_color(recv):
        cfg["recv_message_color"] = recv
    if validate_hex_color(button):
        cfg["send_button_color"] = button
    save_config(cfg)


# ===== 端口 / 数值校验 =====

def validate_port(value) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 0
    if 1 <= v <= 65535:
        return v
    return 0


def normalize_onion_layers(value) -> int:
    try:
        v = int(value)
    except (TypeError, ValueError):
        v = DEFAULT_ONION_LAYERS
    return max(MIN_ONION_LAYERS, min(v, MAX_ONION_LAYERS))


def normalize_search_scope(value: str) -> str:
    allowed = {"local", "lan", "server", "global"}
    if isinstance(value, str) and value.lower() in allowed:
        return value.lower()
    return "local"


def normalize_obfuscation_mode(value: str) -> str:
    if isinstance(value, str) and value in AVAILABLE_OBFUSCATION_MODES:
        return value
    return DEFAULT_OBFUSCATION_MODE


# ===== 安全功能校验 =====

def validate_ephemeral_regex(rules) -> list:
    """校验正则规则列表，剔除非法规则。"""
    out = []
    if not isinstance(rules, list):
        return out
    for r in rules:
        if isinstance(r, str) and r.strip():
            try:
                re.compile(r)
                out.append(r)
            except re.error:
                continue
    return out


def normalize_delete_mode(mode) -> bool:
    """False=快速删除，True=安全删除。接受 bool / "secure"/"fast"。"""
    if isinstance(mode, bool):
        return mode
    if isinstance(mode, str):
        return mode.strip().lower() == "secure"
    return False


# ===== 统一落盘 =====

def apply_settings(cfg: dict) -> dict:
    """
    对传入的配置字典做统一校验/归一化后落盘，返回最终保存的配置。
    未提供的键保留原值。
    """
    cur = load_config() or {}
    if not isinstance(cfg, dict):
        cfg = {}

    for key in ("sent_message_color", "recv_message_color", "send_button_color"):
        if key in cfg and validate_hex_color(cfg[key]):
            cur[key] = cfg[key]

    if "auto_download_files" in cfg:
        cur["auto_download_files"] = bool(cfg["auto_download_files"])
    if "read_receipts_enabled" in cfg:
        cur["read_receipts_enabled"] = bool(cfg["read_receipts_enabled"])

    for key in ("server_port", "direct_connect_port", "public_port"):
        if key in cfg:
            p = validate_port(cfg[key])
            cur[key] = p if p else cur.get(key, 7891)

    if "onion_layers" in cfg:
        cur["onion_layers"] = normalize_onion_layers(cfg["onion_layers"])
    if "onion_enabled" in cfg:
        cur["onion_enabled"] = bool(cfg["onion_enabled"])
    if "obfuscation_mode" in cfg:
        cur["obfuscation_mode"] = normalize_obfuscation_mode(cfg["obfuscation_mode"])
    if "obfuscation_enabled" in cfg:
        cur["obfuscation_enabled"] = bool(cfg["obfuscation_enabled"])

    if "search_scope_default" in cfg:
        cur["search_scope_default"] = normalize_search_scope(cfg["search_scope_default"])

    # 安全：阅后即焚
    if "ephemeral_enabled" in cfg:
        cur["ephemeral_enabled"] = bool(cfg["ephemeral_enabled"])
    if "ephemeral_contact_uuids" in cfg:
        cur["ephemeral_contact_uuids"] = list(cfg["ephemeral_contact_uuids"] or [])
    if "ephemeral_regex_rules" in cfg:
        cur["ephemeral_regex_rules"] = validate_ephemeral_regex(cfg["ephemeral_regex_rules"])
    if "ephemeral_secure_delete" in cfg:
        cur["ephemeral_secure_delete"] = normalize_delete_mode(cfg["ephemeral_secure_delete"])

    # 安全：保险库
    if "vault_enabled" in cfg:
        cur["vault_enabled"] = bool(cfg["vault_enabled"])
    if "vault_pin" in cfg and isinstance(cfg["vault_pin"], str):
        cur["vault_pin"] = cfg["vault_pin"]

    # ===== 链路模式 + 无线电配置（Spider Radio 整合）=====
    if "link_mode" in cfg and isinstance(cfg["link_mode"], str):
        from client.network.link import LinkMode
        try:
            cur["link_mode"] = LinkMode(cfg["link_mode"]).value
        except ValueError:
            pass
    if "radio_config" in cfg and isinstance(cfg["radio_config"], dict):
        from client.network.link import RadioConfig
        cur["radio_config"] = RadioConfig.from_dict(cfg["radio_config"]).to_dict()

    # ===== 网关（Gateway）配置 =====
    if "gateway_mode" in cfg:
        cur["gateway_mode"] = normalize_gateway_mode(cfg["gateway_mode"])
    if "direct_network_sharing_enabled" in cfg:
        cur["direct_network_sharing_enabled"] = bool(cfg["direct_network_sharing_enabled"])

    save_config(cur)
    return cur


# ===== 无线电配置校验（设置界面 / 注册分流界面共用）=====

def validate_radio_config(form: dict) -> dict:
    """
    校验无线电配置表单（手动/自动通用）。
    返回 {'ok': bool, 'errors': [...], 'warning': str|None, 'config': RadioConfig}。
    频率越界仅产生 warning，不阻断保存。
    """
    from client.network.link import RadioConfig
    cfg = RadioConfig(
        frequency_hz=form.get("frequency_hz", 14_100_000),
        duplex=form.get("duplex", 1),
        modulation=form.get("modulation", 0),
        mode=form.get("mode", "auto"),
        mod_params=form.get("mod_params"),
        bandwidth_hz=form.get("bandwidth_hz", 12500),
        search_policy=form.get("search_policy", "ham_only"),
        custom_bands=form.get("custom_bands"),
        fallback_action=form.get("fallback_action", "ask"),
    )
    errs = cfg.validate()
    warn = cfg.warn_out_of_band()
    return {"ok": len(errs) == 0, "errors": errs, "warning": warn, "config": cfg}


def get_link_mode() -> str:
    """读取当前链路模式（默认公网）。"""
    from client.network.link import LinkMode
    cur = load_config() or {}
    try:
        return LinkMode(cur.get("link_mode", LinkMode.PUBLIC.value)).value
    except ValueError:
        return LinkMode.PUBLIC.value


def set_link_mode(mode: str) -> str:
    """切换链路模式并落盘。返回实际生效的模式。"""
    from client.network.link import LinkMode
    try:
        m = LinkMode(mode)
    except ValueError:
        m = LinkMode.PUBLIC
    cur = load_config() or {}
    cur["link_mode"] = m.value
    save_config(cur)
    return m.value


# ===== 网关（Gateway）配置 =====
def normalize_gateway_mode(mode) -> str:
    """
    归一化网关模式：'auto' / 'enabled' / 'disabled'。
    非法值回退到 'auto'。
    """
    from shared.protocol import GATEWAY_AUTO, GATEWAY_FORCE_ENABLED, GATEWAY_FORCE_DISABLED
    allowed = {GATEWAY_AUTO, GATEWAY_FORCE_ENABLED, GATEWAY_FORCE_DISABLED}
    if isinstance(mode, str) and mode.lower() in allowed:
        return mode.lower()
    return GATEWAY_AUTO


def get_gateway_mode() -> str:
    """读取当前网关模式（默认 auto）。"""
    cur = load_config() or {}
    return normalize_gateway_mode(cur.get("gateway_mode", "auto"))


def set_gateway_mode(mode: str) -> str:
    """
    设置网关模式并落盘。返回实际生效的模式。
    随时可配置：'auto'（自动判定）/ 'enabled'（强制开启）/ 'disabled'（强制关闭）。
    """
    m = normalize_gateway_mode(mode)
    cur = load_config() or {}
    cur["gateway_mode"] = m
    save_config(cur)
    return m


def get_direct_network_sharing_enabled() -> bool:
    """读取直连网络共享是否启用（默认 True）。"""
    cur = load_config() or {}
    return bool(cur.get("direct_network_sharing_enabled", True))


def set_direct_network_sharing_enabled(enabled: bool) -> bool:
    """设置直连网络共享开关并落盘。"""
    cur = load_config() or {}
    cur["direct_network_sharing_enabled"] = bool(enabled)
    save_config(cur)
    return bool(enabled)
