"""
Spider Server — Configuration Loader.

Reads server_config.json (non-sensitive) + guide.txt (bootstrap nodes).
All ports are CONFIGURABLE — no hardcoded values in production.
"""

import json
import os
import sys


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from shared.protocol import (
    DEFAULT_TCP_PORT, DEFAULT_DHT_PORT, DEFAULT_UDP_PORT,
    DEFAULT_INTERSERVER_PORT, DEFAULT_DIRECT_CONNECT_PORT,
    DEFAULT_BLUETOOTH_PORT, DEFAULT_WIFI_DIRECT_PORT,
    DEFAULT_RATE_LIMIT, DEFAULT_BURST_CAPACITY as DEFAULT_BURST,
    DEFAULT_MAX_FILE_MB,
    REPLAY_WINDOW_SEC,
    DEFAULT_OBFUSCATION_MODE, AVAILABLE_OBFUSCATION_MODES,
    DEFAULT_ONION_LAYERS, MIN_ONION_LAYERS, MAX_ONION_LAYERS,
    TRANSPORT_KEY_ROTATION_SEC,
)
# 下列常量在部分版本 shared.protocol 中未导出，此处给出兜底默认值。
try:
    from shared.protocol import DEFAULT_FILE_RETENTION_DAYS  # noqa
except ImportError:
    DEFAULT_FILE_RETENTION_DAYS = 30
try:
    from shared.protocol import MAX_LOGIN_ATTEMPTS  # noqa
except ImportError:
    MAX_LOGIN_ATTEMPTS = 5
try:
    from shared.protocol import LOCKOUT_SEC  # noqa
except ImportError:
    LOCKOUT_SEC = 300
try:
    from shared.protocol import SESSION_TIMEOUT_MIN  # noqa
except ImportError:
    SESSION_TIMEOUT_MIN = 60

SOFTWARE_NAME = "Spider"


DEFAULT_CONFIG = {

    "server_name": f"{SOFTWARE_NAME} Server",

    "tcp_port": DEFAULT_TCP_PORT,           # 客户端连接
    "dht_port": DEFAULT_DHT_PORT,
    "udp_port": DEFAULT_UDP_PORT,           # 局域网发现广播
    "interserver_port": DEFAULT_INTERSERVER_PORT,  # 跨服务器中继
    "direct_connect_port": DEFAULT_DIRECT_CONNECT_PORT,
    "bluetooth_port": DEFAULT_BLUETOOTH_PORT,
    "wifi_direct_port": DEFAULT_WIFI_DIRECT_PORT,
    "p2p_port": DEFAULT_DIRECT_CONNECT_PORT,

    "public_host": "",
    "public_port": DEFAULT_TCP_PORT,

    "hidden_mode": False,
    "dht_whitelist": [],

    "rate_limit": {
        "global_seconds_per_msg": DEFAULT_RATE_LIMIT,
        "burst_capacity": DEFAULT_BURST,
    },


    "file_transfer": {
        "enabled": True,
        "max_file_size_mb": DEFAULT_MAX_FILE_MB,
        "retention_days": DEFAULT_FILE_RETENTION_DAYS,
    },

    "user_management": {
        "strict_uuid_mac": True,
        "max_connections": 1000,
        "min_client_version": "1.0.0",
    },


    "group_chat": {
        "enabled": True,
        "max_group_size": 50,
        "allow_cross_server": True,
    },

    "dht": {
        "k_bucket_size": 20,
        "alpha": 3,
    },

    "logging": {
        "level": "INFO",
        "directory": "",
    },

    "security": {
        "max_login_attempts": MAX_LOGIN_ATTEMPTS,
        "lockout_seconds": LOCKOUT_SEC,
        "session_timeout_min": SESSION_TIMEOUT_MIN,
        "replay_window_sec": REPLAY_WINDOW_SEC,
    },

    "keyring": {
        "service_name": "spider-server",
        "required": True,
        "fallback_allowed": True,
        "headless_fallback": "cryptfile",
    },

    "transport": {
        "enabled": True,
        "key_rotation_sec": TRANSPORT_KEY_ROTATION_SEC,  # 每小时轮换
        "handshake_timeout": 10,
    },

    "obfuscation": {
        "enabled": True,
        "mode": DEFAULT_OBFUSCATION_MODE,
        "available_modes": AVAILABLE_OBFUSCATION_MODES,
    },

    "onion": {
        "enabled": False,               # 默认关闭（匿名功能需主动开启）
        "layers": DEFAULT_ONION_LAYERS,
        "min_layers": MIN_ONION_LAYERS,
        "max_layers": MAX_ONION_LAYERS,
    },

    "direct_connect": {
        "enabled": True,
        "max_peers": 50,
        "bluetooth_enabled": True,
        "wifi_direct_enabled": True,
        "lan_discovery": True,
        "public_ip": "",
    },

    "client_defaults": {
        "sent_message_color": "#FF4444",
        "recv_message_color": "#44FF44",
        "send_button_color": "#FF4444",
        "auto_download_files": True,
        "obfuscation_mode": DEFAULT_OBFUSCATION_MODE,
        "onion_enabled": False,
        "onion_layers": DEFAULT_ONION_LAYERS,
    },
}



def get_project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def get_data_dir() -> str:
    root = get_project_root()
    path = os.path.join(root, "data")
    os.makedirs(path, exist_ok=True)
    return path

def get_config_path() -> str:
    return os.path.join(get_data_dir(), "server_config.json")

def get_guide_path() -> str:
    return os.path.join(get_data_dir(), "guide.txt")

def load_config(config_path=None) -> dict:
    """加载服务端配置，将用户配置合并到默认值之上。"""
    if config_path is None:
        path = get_config_path()
    else:
        path = config_path
    config = json.loads(json.dumps(DEFAULT_CONFIG))  # 深拷贝
    if os.path.exists(path):
        try:
            with open(path) as f:
                user_cfg = json.load(f)
            _deep_merge(config, user_cfg)
        except Exception as e:
            print(f"[CONFIG] Warning: Failed to load config: {e}")
    else:
        save_config(config)

    _validate_ports(config)

    return config

def save_config(config: dict):
    """保存服务器配置到磁盘。"""
    path = get_config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)

def reload_config() -> dict:
    """从磁盘重新加载配置。"""
    return load_config()


def _validate_ports(config: dict):
    """确保所有端口有效且不冲突。"""
    port_keys = [
        "tcp_port", "dht_port", "udp_port", "interserver_port",
        "direct_connect_port", "bluetooth_port", "wifi_direct_port", "p2p_port"
    ]
    used = {}
    for key in port_keys:
        val = config.get(key, 0)
        if not isinstance(val, int) or val < 1 or val > 65535:
            print(f"[CONFIG] Warning: Invalid port {key}={val}, resetting to default")

            defaults_map = {
                "tcp_port": DEFAULT_TCP_PORT,
                "dht_port": DEFAULT_DHT_PORT,
                "udp_port": DEFAULT_UDP_PORT,
                "interserver_port": DEFAULT_INTERSERVER_PORT,
                "direct_connect_port": DEFAULT_DIRECT_CONNECT_PORT,
                "bluetooth_port": DEFAULT_BLUETOOTH_PORT,
                "wifi_direct_port": DEFAULT_WIFI_DIRECT_PORT,
                "p2p_port": DEFAULT_DIRECT_CONNECT_PORT,
            }
            config[key] = defaults_map.get(key, 7891)
            val = config[key]

        if val in used:
            print(f"[CONFIG] Warning: Port {val} used by both {used[val]} and {key}")
        else:
            used[val] = key


    onion = config.setdefault("onion", {})
    layers = onion.get("layers", DEFAULT_ONION_LAYERS)
    layers = max(MIN_ONION_LAYERS, min(layers, MAX_ONION_LAYERS))
    onion["layers"] = layers


    obf = config.setdefault("obfuscation", {})
    mode = obf.get("mode", DEFAULT_OBFUSCATION_MODE)
    if mode not in AVAILABLE_OBFUSCATION_MODES:
        print(f"[CONFIG] Warning: Invalid obfuscation mode '{mode}', using 'http'")
        obf["mode"] = "http"

def get_all_ports(config: dict) -> dict:
    """返回所有已配置的端口。"""
    return {
        "tcp": config.get("tcp_port", DEFAULT_TCP_PORT),
        "dht": config.get("dht_port", DEFAULT_DHT_PORT),
        "udp": config.get("udp_port", DEFAULT_UDP_PORT),
        "interserver": config.get("interserver_port", DEFAULT_INTERSERVER_PORT),
        "direct_connect": config.get("direct_connect_port", DEFAULT_DIRECT_CONNECT_PORT),
        "bluetooth": config.get("bluetooth_port", DEFAULT_BLUETOOTH_PORT),
        "wifi_direct": config.get("wifi_direct_port", DEFAULT_WIFI_DIRECT_PORT),
        "p2p": config.get("p2p_port", DEFAULT_DIRECT_CONNECT_PORT),
        "public": config.get("public_port", DEFAULT_TCP_PORT),
    }


def _deep_merge(base: dict, override: dict):
    """递归地将覆盖配置合并到基础配置中。"""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
