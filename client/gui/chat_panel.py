"""
聊天面板 — 右侧消息显示 + 输入区域。
注意：核心聊天功能已集成到 MainWindow 中。
本模块提供消息渲染的额外辅助函数。
"""

import time
from shared.protocol import *

def format_timestamp(ts: int) -> str:
    """将 Unix 时间戳格式化为可读字符串。"""
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))

def make_message_bubble(parent, text: str, direction: str, color: str, timestamp: int = 0):
    """创建消息气泡控件。"""
    side = "right" if direction == "sent" else "left"
    return None

def create_file_card(parent, filename: str, filesize: int, direction: str, color: str, on_download=None):
    """创建带下载按钮的文件消息卡片。"""
    return None
