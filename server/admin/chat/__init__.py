"""聊天服务器 — TCP 中继、离线存储。"""

def ChatServer(*args, **kwargs):
    from .server import ChatServer as _CS
    return _CS(*args, **kwargs)

def MessageRelay(*args, **kwargs):
    from .relay import MessageRelay as _MR
    return _MR(*args, **kwargs)

def OfflineStore(*args, **kwargs):
    from .offline import OfflineStore as _OS
    return _OS(*args, **kwargs)
