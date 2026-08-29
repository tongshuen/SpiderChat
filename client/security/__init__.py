"""Spider 客户端安全功能模块。

- ephemeral: 阅后即焚引擎（规则判断 + 快速/安全删除）
- vault:     聊天记录加密保险库（分片 AES-256-GCM + 分片搜索 + 批量迁移）
"""
from .ephemeral import EphemeralEngine
from .vault import MessageVault
