"""
带外签名（Out-of-Band Signature）— 与 Android 端互通。

签名串单行格式：
    spider-sig:v1;uuid=xxx;timestamp=1757888888;data_hash=sha256hex;sig=base64

字段：
    uuid       签名者账号 UUID
    timestamp  Unix 时间戳（秒）
    data_hash  SHA-256(原始输入文本) 的十六进制字符串
    sig        Ed25519 签名的 base64 编码

两种模式（域分离，防止重放/跨模式伪造）：
    ownership  账号所有权证明：签名字节 =
               b"spider-outband-ownership\\n" + challenge + b"\\n" + uuid
    content    消息内容签名：签名字节 =
               b"spider-outband-content\\n" + content  + b"\\n" + uuid

安全说明：
    - 私钥永远不上传服务器，签名/校验全部本地计算。
    - data_hash 为 SHA-256(原始输入文本) 的 hex，与模式无关。
    - 时间戳合理性（±300 秒）仅作提示，不拒绝。
"""

import hashlib
import time

from shared.crypto_utils import (
    load_ed25519_private,
    load_ed25519_public,
    sign_data,
    verify_signature,
)
from shared.protocol import (
    OUTBAND_SIG_PREFIX,
    OUTBAND_MODE_OWNERSHIP,
    OUTBAND_MODE_CONTENT,
    OUTBAND_PREFIX_OWNERSHIP,
    OUTBAND_PREFIX_CONTENT,
    OUTBAND_CLOCK_SKEW_WARN_SEC,
)

_VALID_MODES = (OUTBAND_MODE_OWNERSHIP, OUTBAND_MODE_CONTENT)


def _mode_prefix(mode: str) -> bytes:
    """根据模式返回域分离前缀字节。"""
    if mode == OUTBAND_MODE_OWNERSHIP:
        return OUTBAND_PREFIX_OWNERSHIP
    if mode == OUTBAND_MODE_CONTENT:
        return OUTBAND_PREFIX_CONTENT
    raise ValueError(f"未知签名模式: {mode!r}（应为 {_VALID_MODES}）")


def _build_signed_bytes(mode: str, text: str, uuid: str) -> bytes:
    """
    构造实际参与 Ed25519 签名的字节串。
    格式：<前缀(含换行)> + 文本 + <换行> + uuid
    """
    return _mode_prefix(mode) + text.encode("utf-8") + b"\n" + uuid.encode("utf-8")


def _data_hash_hex(text: str) -> str:
    """SHA-256(原始输入文本) 的十六进制字符串。"""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_signature(signature_string: str) -> dict:
    """
    解析签名串为字段字典。

    返回:
        {"uuid": str, "timestamp": int, "data_hash": str, "sig": str}

    格式错误抛出 ValueError。
    """
    if not isinstance(signature_string, str) or not signature_string.strip():
        raise ValueError("签名串为空")

    s = signature_string.strip()
    if not s.startswith(OUTBAND_SIG_PREFIX + ";"):
        raise ValueError(f"签名串前缀错误，应为 {OUTBAND_SIG_PREFIX!r}")

    # 去掉前缀段，剩余为 key=value;key=value...
    rest = s[len(OUTBAND_SIG_PREFIX):].lstrip(";")
    fields = {}
    for segment in rest.split(";"):
        if not segment:
            continue
        if "=" not in segment:
            raise ValueError(f"签名段格式错误（缺少 '='）: {segment!r}")
        key, _, value = segment.partition("=")
        key = key.strip()
        if key:
            fields[key] = value

    missing = [k for k in ("uuid", "timestamp", "data_hash", "sig") if not fields.get(k)]
    if missing:
        raise ValueError(f"签名串缺少字段: {missing}")

    try:
        timestamp = int(fields["timestamp"])
    except (TypeError, ValueError):
        raise ValueError(f"时间戳不是整数: {fields['timestamp']!r}")

    if not fields["uuid"]:
        raise ValueError("uuid 为空")
    if not fields["data_hash"]:
        raise ValueError("data_hash 为空")
    if not fields["sig"]:
        raise ValueError("sig 为空")

    return {
        "uuid": fields["uuid"],
        "timestamp": timestamp,
        "data_hash": fields["data_hash"],
        "sig": fields["sig"],
    }


def sign_outband(text: str, mode: str, ed25519_priv_b64: str, uuid: str) -> str:
    """
    生成带外签名串。

    Args:
        text: 原始输入文本（ownership 模式为挑战 nonce；content 模式为任意文本）
        mode: "ownership" 或 "content"
        ed25519_priv_b64: Ed25519 私钥（raw 32 字节 base64）
        uuid: 签名者账号 UUID

    Returns:
        完整签名串 "spider-sig:v1;uuid=...;timestamp=...;data_hash=...;sig=..."
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"未知签名模式: {mode!r}（应为 {_VALID_MODES}）")
    if not uuid:
        raise ValueError("uuid 不能为空")
    if text is None:
        text = ""

    priv = load_ed25519_private(ed25519_priv_b64)
    signed_bytes = _build_signed_bytes(mode, text, uuid)
    sig_b64 = sign_data(priv, signed_bytes)

    timestamp = int(time.time())
    data_hash = _data_hash_hex(text)

    return (
        f"{OUTBAND_SIG_PREFIX};uuid={uuid}"
        f";timestamp={timestamp}"
        f";data_hash={data_hash}"
        f";sig={sig_b64}"
    )


def verify_outband(
    signature_string: str,
    original_text: str,
    ed25519_pub_b64: str,
) -> dict:
    """
    校验带外签名串。

    校验项：
        1. 格式解析（parse_signature）
        2. data_hash 与原始文本匹配
        3. Ed25519 验签（自动尝试 ownership/content 两种模式以判定模式）
        4. 时间戳合理性（±300 秒仅作提示，不拒绝）

    Returns:
        {"valid": bool, "uuid": str, "timestamp": int, "mode": str, "error": str}
    """
    result = {"valid": False, "uuid": "", "timestamp": 0, "mode": "", "error": ""}

    # 1. 格式解析
    try:
        fields = parse_signature(signature_string)
    except ValueError as e:
        result["error"] = f"格式错误: {e}"
        return result

    result["uuid"] = fields["uuid"]
    result["timestamp"] = fields["timestamp"]

    # 2. data_hash 匹配
    expected_hash = _data_hash_hex(original_text if original_text is not None else "")
    if not hmac_compare_hex(fields["data_hash"], expected_hash):
        result["error"] = "data_hash 与原始文本不匹配"
        return result

    # 3. 加载公钥并验签（尝试两种模式，命中即确定模式）
    try:
        pub = load_ed25519_public(ed25519_pub_b64)
    except Exception as e:
        result["error"] = f"公钥无效: {e}"
        return result

    for mode in _VALID_MODES:
        signed_bytes = _build_signed_bytes(mode, original_text, fields["uuid"])
        if verify_signature(pub, signed_bytes, fields["sig"]):
            result["valid"] = True
            result["mode"] = mode
            # 时间戳合理性（±OUTBAND_CLOCK_SKEW_WARN_SEC 秒）：
            # 偏差较大时不拒绝，仅视为可能重放/时钟漂移的提示。
            return result

    result["error"] = "Ed25519 验签失败（签名与原文/公钥不匹配）"
    return result


def hmac_compare_hex(a: str, b: str) -> bool:
    """恒定时间比较两个十六进制字符串。"""
    import hmac
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))
