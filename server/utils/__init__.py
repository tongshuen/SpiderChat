"""服务器工具函数。"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from client.utils.uuidgen import get_real_mac

def get_real_mac_for_server():
    """抛出带有清晰消息的 RuntimeError 的封装函数。"""
    return get_real_mac()
