"""
消息编码/解码辅助函数。
所有消息均为 JSON 格式，包含 'type' 字段，换行分隔。
"""

import json


def encode_message(msg: dict) -> bytes:
    """将消息字典编码为换行结尾的 JSON 字节。"""
    return (json.dumps(msg) + "\n").encode("utf-8")


def decode_message(raw: bytes) -> dict:
    """将换行结尾的 JSON 字节解码为字典。"""
    return json.loads(raw.decode("utf-8").strip())


def make_envelope(msg_type: str, **fields) -> dict:
    """创建带版本字段的协议信封。"""
    env = {"type": msg_type, "version": 1}
    env.update(fields)
    return env
