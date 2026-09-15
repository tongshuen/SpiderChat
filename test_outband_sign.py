#!/usr/bin/env python3
"""
带外签名（Out-of-Band Signature）测试。

运行：
    cd <repo_root>
    python3 test_outband_sign.py

覆盖：
    1. sign_outband + verify_outband 往返（ownership / content 两种模式）
    2. 篡改原文后校验失败
    3. 错误公钥校验失败
    4. 格式错误的签名串解析失败
    5. data_hash 不匹配时失败
    6. 跨端互通：固定密钥对生成签名，打印签名串与公钥供 Android 端验证
"""

import hashlib
import os
import sys

# 允许从仓库根目录直接运行
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.crypto_utils import (
    generate_ed25519_keypair,
    load_ed25519_private,
    b64_encode,
)
from client.crypto.outband_sign import (
    sign_outband,
    verify_outband,
    parse_signature,
)
from shared.protocol import OUTBAND_MODE_OWNERSHIP, OUTBAND_MODE_CONTENT, OUTBAND_SIG_PREFIX


PASSED = 0
FAILED = 0


def check(name: str, cond: bool, detail: str = ""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  [PASS] {name}")
    else:
        FAILED += 1
        print(f"  [FAIL] {name}  {detail}")


def _deterministic_keypair(seed: str):
    """从固定种子派生确定性 Ed25519 密钥对（用于跨端互通测试）。"""
    from cryptography.hazmat.primitives import serialization
    raw = hashlib.sha256(seed.encode("utf-8")).digest()  # 32 字节
    priv = load_ed25519_private(b64_encode(raw))
    pub = priv.public_key()
    priv_b64 = b64_encode(raw)
    pub_b64 = b64_encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))
    return priv_b64, pub_b64


def test_roundtrip():
    print("\n== 1. 签名/校验往返（两种模式）==")
    priv_b64, pub_b64 = generate_ed25519_keypair()
    uuid = "11111111-2222-3333-4444-555555555555"

    for mode, text in [
        (OUTBAND_MODE_OWNERSHIP, "random-challenge-nonce-abc123"),
        (OUTBAND_MODE_CONTENT, "这是一条要签名的消息 content 🦂"),
    ]:
        sig = sign_outband(text, mode, priv_b64, uuid)
        check(f"签名串以 {OUTBAND_SIG_PREFIX} 开头 ({mode})",
              sig.startswith(OUTBAND_SIG_PREFIX + ";"), sig)
        res = verify_outband(sig, text, pub_b64)
        check(f"往返校验通过 ({mode})", res["valid"] is True, str(res))
        check(f"模式识别正确 ({mode})", res["mode"] == mode, res["mode"])
        check(f"UUID 正确 ({mode})", res["uuid"] == uuid, res["uuid"])
        check(f"时间戳为正整数 ({mode})", isinstance(res["timestamp"], int) and res["timestamp"] > 0)


def test_tampered_content():
    print("\n== 2. 篡改原文后校验失败 ==")
    priv_b64, pub_b64 = generate_ed25519_keypair()
    uuid = "uuid-tamper"
    sig = sign_outband("原始原文", OUTBAND_MODE_CONTENT, priv_b64, uuid)
    res = verify_outband(sig, "篡改后的原文", pub_b64)
    check("篡改原文 → 校验无效", res["valid"] is False, str(res))
    check("返回错误说明", "data_hash" in res["error"] or "验签" in res["error"], res["error"])


def test_wrong_pubkey():
    print("\n== 3. 错误公钥校验失败 ==")
    priv_b64, pub_b64 = generate_ed25519_keypair()
    _, other_pub = generate_ed25519_keypair()
    uuid = "uuid-wrong-key"
    text = "用 A 私钥签，拿 B 公钥验"
    sig = sign_outband(text, OUTBAND_MODE_CONTENT, priv_b64, uuid)
    res = verify_outband(sig, text, other_pub)
    check("错误公钥 → 校验无效", res["valid"] is False, str(res))
    check("正确公钥 → 仍然有效", verify_outband(sig, text, pub_b64)["valid"] is True)


def test_malformed_signature():
    print("\n== 4. 格式错误的签名串解析失败 ==")
    for bad in ["", "spider-sig:v2;uuid=x", "garbage",
                "spider-sig:v1;uuid=;timestamp=abc;data_hash=d;sig=s",
                "spider-sig:v1;uuid=u;timestamp=123;data_hash=d"]:
        try:
            parse_signature(bad)
            check(f"应抛 ValueError: {bad!r}", False, "未抛出")
        except ValueError:
            check(f"解析失败: {bad!r}", True)

    # verify_outband 对坏串返回 valid=False 而非异常
    res = verify_outband("not-a-signature", "anything", "cHd1Yg")
    check("verify_outband 对坏串安全返回", res["valid"] is False and res["error"] != "", str(res))


def test_data_hash_mismatch():
    print("\n== 5. data_hash 不匹配时失败 ==")
    priv_b64, pub_b64 = generate_ed25519_keypair()
    uuid = "uuid-hash"
    sig = sign_outband("待签文本", OUTBAND_MODE_CONTENT, priv_b64, uuid)
    fields = parse_signature(sig)
    # 构造 data_hash 被篡改、但 sig 仍原样保留的串
    tampered = (f"{OUTBAND_SIG_PREFIX};uuid={uuid}"
                f";timestamp={fields['timestamp']}"
                f";data_hash={hashlib.sha256(b'other-original').hexdigest()}"
                f";sig={fields['sig']}")
    res = verify_outband(tampered, "待签文本", pub_b64)
    check("data_hash 被改 → 校验无效", res["valid"] is False, str(res))
    check("错误指向 data_hash", "data_hash" in res["error"], res["error"])


def test_cross_platform():
    print("\n== 6. 跨端互通（固定密钥对，供 Android 端验证）==")
    priv_b64, pub_b64 = _deterministic_keypair("spider-outband-interop-seed")
    uuid = "00000000-0000-4000-8000-000000000001"

    challenge = "interop-challenge-4e11c0ffee"
    content = "Spider out-of-band signature interop sample."

    sig_own = sign_outband(challenge, OUTBAND_MODE_OWNERSHIP, priv_b64, uuid)
    sig_content = sign_outband(content, OUTBAND_MODE_CONTENT, priv_b64, uuid)

    # 自验
    r1 = verify_outband(sig_own, challenge, pub_b64)
    r2 = verify_outband(sig_content, content, pub_b64)
    check("跨端样例 ownership 自验通过", r1["valid"] and r1["mode"] == OUTBAND_MODE_OWNERSHIP, str(r1))
    check("跨端样例 content 自验通过", r2["valid"] and r2["mode"] == OUTBAND_MODE_CONTENT, str(r2))

    print("\n----- 供 Android 端验证（复制以下内容）-----")
    print(f"public_key_b64 = {pub_b64}")
    print(f"uuid           = {uuid}")
    print(f"[ownership] challenge = {challenge}")
    print(f"[ownership] signature = {sig_own}")
    print(f"[content]   original  = {content}")
    print(f"[content]   signature = {sig_content}")
    print("-------------------------------------------")


def main():
    print("Spider 带外签名测试")
    test_roundtrip()
    test_tampered_content()
    test_wrong_pubkey()
    test_malformed_signature()
    test_data_hash_mismatch()
    test_cross_platform()

    print(f"\n===== 结果: {PASSED} 通过, {FAILED} 失败 =====")
    sys.exit(0 if FAILED == 0 else 1)


if __name__ == "__main__":
    main()
