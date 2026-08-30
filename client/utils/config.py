"""
Spider — 客户端配置和数据目录管理。
所有端口均可配置 — 无硬编码值。
"""

import os
import json
import platform
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from shared.protocol import (
    DEFAULT_TCP_PORT, DEFAULT_DHT_PORT, DEFAULT_UDP_PORT,
    DEFAULT_DIRECT_CONNECT_PORT, DEFAULT_BLUETOOTH_PORT, DEFAULT_WIFI_DIRECT_PORT,
    DEFAULT_OBFUSCATION_MODE, AVAILABLE_OBFUSCATION_MODES,
    DEFAULT_ONION_LAYERS, MIN_ONION_LAYERS, MAX_ONION_LAYERS,
    DEFAULT_SENT_COLOR, DEFAULT_RECV_COLOR, DEFAULT_BUTTON_COLOR,
    TRANSPORT_KEY_ROTATION_SEC
)

SOFTWARE_NAME = "Spider"


def get_data_dir():
    """获取适合当前平台的 data 目录。"""
    system = platform.system()
    if system == "Windows":
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
        path = os.path.join(base, SOFTWARE_NAME)
    elif system == "Darwin":
        path = os.path.expanduser(f"~/Library/Application Support/{SOFTWARE_NAME}")
    else:
        base = os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share"))
        path = os.path.join(base, SOFTWARE_NAME.lower())
    os.makedirs(path, exist_ok=True)
    return path



IDENTITY_FILE = "identity.json"
SETTINGS_FILE = "settings.json"
CHAT_DB_FILE = "messages.db"
CONTACTS_FILE = "contacts.json"
PEERS_FILE = "peers.json"
DC_CONFIG_FILE = "direct_connect.json"
PROFILE_FILE = "profile.json"



DEFAULT_SETTINGS = {

    "server_host": "",
    "server_port": DEFAULT_TCP_PORT,

    "sent_message_color": DEFAULT_SENT_COLOR,
    "recv_message_color": DEFAULT_RECV_COLOR,
    "send_button_color": DEFAULT_BUTTON_COLOR,
    "auto_download_files": True,
    "read_receipts_enabled": True,  # 是否发送已读回执


    "group_sent_color": "#FF6B6B",
    "group_recv_color": "#6BFF6B",
    "max_group_size": 50,

    "transport_enabled": True,
    "transport_key_rotation_sec": TRANSPORT_KEY_ROTATION_SEC,

    "obfuscation_enabled": True,
    "obfuscation_mode": DEFAULT_OBFUSCATION_MODE,
    "available_obfuscation_modes": AVAILABLE_OBFUSCATION_MODES,

    "onion_enabled": False,
    "onion_layers": DEFAULT_ONION_LAYERS,

    "direct_connect_enabled": True,
    "direct_connect_port": DEFAULT_DIRECT_CONNECT_PORT,
    "bluetooth_enabled": True,
    "wifi_direct_enabled": True,
    "lan_discovery": True,
    "public_ip": "",
    "public_port": DEFAULT_TCP_PORT,

    "search_scope_default": "local",  # 本地/局域网/服务器/全局

    # ===== 网关（Gateway）自动判定 =====
    # 网关节点模式：'auto'（自动，同时具备公网+SDR时为网关）/
    #               'enabled'（强制开启）/ 'disabled'（强制关闭）
    "gateway_mode": "auto",
    # 直连网络共享：是否愿意为其他直连节点提供网络中继
    "direct_network_sharing_enabled": True,

    # ===== 阅后即焚（安全功能） =====
    "ephemeral_enabled": False,
    "ephemeral_contact_uuids": [],
    "ephemeral_regex_rules": [],
    "ephemeral_secure_delete": False,  # False=快速删除，True=随机覆写后删

    # ===== 聊天记录加密保险库（安全功能） =====
    "vault_enabled": False,
    # ===== 死人开关（Dead Man's Switch）=====
    "deadman_enabled": False,
    "deadman_warning_message": "",       # 警告消息内容（明文，服务器存储为特殊离线消息）
    "deadman_recipient_uuid": "",        # 预定收件人 UUID
    "deadman_grace_days": 7,             # 宽限期（天），超过未登录则触发
}


def load_config():
    """加载客户端设置，将用户配置合并到默认值之上。"""
    path = os.path.join(get_data_dir(), SETTINGS_FILE)
    config = json.loads(json.dumps(DEFAULT_SETTINGS))  # 深拷贝
    if os.path.exists(path):
        try:
            with open(path) as f:
                user_cfg = json.load(f)
            _deep_merge(config, user_cfg)
        except Exception as e:
            print(f"[CONFIG] Warning: {e}")


    _validate_config(config)
    return config


def save_config(cfg):
    """保存客户端设置。"""
    path = os.path.join(get_data_dir(), SETTINGS_FILE)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)


def load_direct_connect_config() -> dict:
    """加载直连专用配置。"""
    path = os.path.join(get_data_dir(), DC_CONFIG_FILE)
    defaults = {
        "enabled": True,
        "dc_port": DEFAULT_DIRECT_CONNECT_PORT,
        "bt_port": DEFAULT_BLUETOOTH_PORT,
        "wifi_port": DEFAULT_WIFI_DIRECT_PORT,
        "max_peers": 50,
        "transport_rotation_sec": TRANSPORT_KEY_ROTATION_SEC,
        "obfuscation_mode": DEFAULT_OBFUSCATION_MODE,
        "onion_enabled": False,
        "onion_layers": DEFAULT_ONION_LAYERS,
        "public_ip": "",
        "public_port": DEFAULT_DIRECT_CONNECT_PORT,
    }
    if os.path.exists(path):
        try:
            with open(path) as f:
                user_cfg = json.load(f)
            _deep_merge(defaults, user_cfg)
        except:
            pass
    return defaults


def save_direct_connect_config(cfg: dict):
    path = os.path.join(get_data_dir(), DC_CONFIG_FILE)
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)


def load_peers() -> list:
    """加载已知 P2P 对端。"""
    path = os.path.join(get_data_dir(), PEERS_FILE)
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except:
            pass
    return []


def save_peers(peers: list):
    path = os.path.join(get_data_dir(), PEERS_FILE)
    with open(path, "w") as f:
        json.dump(peers, f, indent=2)


def identity_path():
    return os.path.join(get_data_dir(), IDENTITY_FILE)


def contacts_path():
    return os.path.join(get_data_dir(), CONTACTS_FILE)


def profile_path():
    return os.path.join(get_data_dir(), PROFILE_FILE)


def chat_db_path():
    return os.path.join(get_data_dir(), CHAT_DB_FILE)


def get_all_ports(config: dict) -> dict:
    """返回配置中的所有端口。"""
    return {
        "server": config.get("server_port", DEFAULT_TCP_PORT),
        "direct_connect": config.get("direct_connect_port", DEFAULT_DIRECT_CONNECT_PORT),
        "public": config.get("public_port", DEFAULT_TCP_PORT),
    }



def _validate_config(config: dict):
    """验证并修复配置值。"""
    port_keys = ["server_port", "direct_connect_port", "public_port"]
    for key in port_keys:
        val = config.get(key, 0)
        if not isinstance(val, int) or val < 1 or val > 65535:
            defaults_map = {
                "server_port": DEFAULT_TCP_PORT,
                "direct_connect_port": DEFAULT_DIRECT_CONNECT_PORT,
                "public_port": DEFAULT_TCP_PORT,
            }
            config[key] = defaults_map.get(key, 7891)

    layers = config.get("onion_layers", DEFAULT_ONION_LAYERS)
    config["onion_layers"] = max(MIN_ONION_LAYERS, min(layers, MAX_ONION_LAYERS))

    mode = config.get("obfuscation_mode", DEFAULT_OBFUSCATION_MODE)
    if mode not in AVAILABLE_OBFUSCATION_MODES:
        config["obfuscation_mode"] = DEFAULT_OBFUSCATION_MODE


def _deep_merge(base: dict, override: dict):
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
