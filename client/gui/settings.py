"""
设置窗口 — 颜色自定义、自动下载开关。
核心设置 UI 集成在 MainWindow._open_settings 中。
本模块提供辅助函数。
"""

from client.utils.config import load_config, save_config
from shared.protocol import DEFAULT_SENT_COLOR, DEFAULT_RECV_COLOR, DEFAULT_BUTTON_COLOR


def get_colors() -> dict:
    """获取当前颜色设置（含默认值）。"""
    cfg = load_config()
    return {
        "sent": cfg.get("sent_message_color", DEFAULT_SENT_COLOR),
        "recv": cfg.get("recv_message_color", DEFAULT_RECV_COLOR),
        "button": cfg.get("send_button_color", DEFAULT_BUTTON_COLOR),
    }


def validate_hex_color(hex_str: str) -> bool:
    """验证十六进制颜色字符串（如 #FF4444）。"""
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
    """保存颜色设置。"""
    cfg = load_config()
    if validate_hex_color(sent):
        cfg["sent_message_color"] = sent
    if validate_hex_color(recv):
        cfg["recv_message_color"] = recv
    if validate_hex_color(button):
        cfg["send_button_color"] = button
    save_config(cfg)
