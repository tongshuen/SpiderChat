"""
Spider — P2P 模块

允许 Spider 客户端充当轻量级服务器，
提供带完整加密的点对点通信。
"""

from .node import P2PNode, P2PPeer, P2PRelay
from .transport import SecureTransport, TransportConfig, build_onion_chain, process_onion_packet

__all__ = [
    "P2PNode",
    "P2PPeer", 
    "P2PRelay",
    "SecureTransport",
    "TransportConfig",
    "build_onion_chain",
    "process_onion_packet",
]
