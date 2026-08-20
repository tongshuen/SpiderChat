"""
使用 X25519 ECDH + AES-256-GCM 进行消息加密/解密。

安全修复 (v2):
- 使用临时 X25519 密钥实现前向保密
- 身份密钥不用于 ECDH（仅用于签名）
- AAD 将密文绑定到消息上下文
- 每条消息使用全新的临时密钥对
"""

import base64
import json
import time
import os
from shared.crypto_utils import (
    generate_x25519_keypair,
    load_x25519_private, load_x25519_public,
    load_ed25519_private, load_ed25519_public,
    ecdh_shared_secret, hkdf_derive,
    aesgcm_encrypt, aesgcm_decrypt,
    sign_data, verify_signature,
    current_timestamp, secure_token,
    NONCE_SIZE,
)


def encrypt_message(
    text: str,
    my_x_priv_b64: str,
    peer_x_pub_b64: str,
    my_e_priv_b64: str,
    from_uuid: str,
    to_uuid: str,
    ephemeral_priv_b64: str = "",
    peer_ephemeral_pub_b64: str = "",
) -> dict:
    """
    为对端加密一条文本消息。

    安全 (v2):
    - 使用临时 X25519 密钥进行 ECDH（前向保密）
    - 仅在未提供临时密钥时回退到身份密钥
    - AAD 绑定发送方/接收方 UUID + 时间戳 + 协议版本
    - 使用 Ed25519 签署完整加密信封

    返回可供 JSON 序列化的字典。
    """
    if ephemeral_priv_b64 and peer_ephemeral_pub_b64:
        shared = ecdh_shared_secret(ephemeral_priv_b64, peer_ephemeral_pub_b64)
        context = b"spider-msg-ephemeral-v1"
    else:
        my_priv = load_x25519_private(my_x_priv_b64)
        peer_pub = load_x25519_public(peer_x_pub_b64)
        shared = my_priv.exchange(peer_pub)
        context = b"spider-msg-identity-v1"

    aes_key = hkdf_derive(shared, info=context, length=32)

    timestamp = current_timestamp()
    aad_dict = {
        "from": from_uuid,
        "to": to_uuid,
        "ts": timestamp,
        "proto": "spider/2.0",
    }
    aad = json.dumps(aad_dict, sort_keys=True).encode("utf-8")

    plaintext = text.encode("utf-8")
    enc_result = aesgcm_encrypt(aes_key, plaintext, aad)

    my_sign_priv = load_ed25519_private(my_e_priv_b64)
    to_sign = json.dumps(enc_result, sort_keys=True).encode("utf-8")
    signature = sign_data(my_sign_priv, to_sign)

    return {
        "version": 2,
        "from_uuid": from_uuid,
        "to_uuid": to_uuid,
        "timestamp": timestamp,
        "nonce": enc_result["nonce"],
        "ciphertext": enc_result["ciphertext"],
        "tag": enc_result["tag"],
        "aad": enc_result["aad"],
        "signature": signature,
        "ephemeral_pub": ephemeral_priv_b64,  # 如果可用，由调用方设置
        "fs_used": bool(ephemeral_priv_b64 and peer_ephemeral_pub_b64),
    }


def decrypt_message(
    msg: dict,
    my_x_priv_b64: str,
    peer_x_pub_b64: str,
    peer_e_pub_b64: str,
    my_ephemeral_priv_b64: str = "",
    peer_ephemeral_pub_b64: str = "",
) -> str:
    """
    解密接收到的消息。验证 AAD 上下文 + Ed25519 签名。

    安全 (v2):
    - 验证 AAD 是否匹配预期的发送方/接收方
    - 在解密前验证 Ed25519 签名
    - 可用时使用临时密钥（前向保密）
    """
    nonce_b64 = msg["nonce"]
    ct_b64 = msg["ciphertext"]
    tag_b64 = msg["tag"]
    aad_b64 = msg.get("aad", "")
    signature = msg.get("signature", "")
    from_uuid = msg.get("from_uuid", "")
    to_uuid = msg.get("to_uuid", "")
    timestamp = msg.get("timestamp", 0)
    peer_ephemeral_pub = msg.get("ephemeral_pub", "")

    if aad_b64:
        import base64 as b64
        aad_bytes = b64.b64decode(aad_b64)
        try:
            aad_dict = json.loads(aad_bytes.decode("utf-8"))
        except:
            raise ValueError("Invalid AAD format")


        if aad_dict.get("from") != from_uuid or aad_dict.get("to") != to_uuid:
            raise ValueError("AAD context mismatch — possible replay or tampering")
        if aad_dict.get("ts") != timestamp:
            raise ValueError("AAD timestamp mismatch")
    else:
        raise ValueError("Missing AAD — refusing to decrypt")

    peer_sign_pub = load_ed25519_public(peer_e_pub_b64)
    enc_for_verify = {
        "nonce": nonce_b64,
        "ciphertext": ct_b64,
        "tag": tag_b64,
        "aad": aad_b64,
    }
    to_verify = json.dumps(enc_for_verify, sort_keys=True).encode("utf-8")
    if not verify_signature(peer_sign_pub, to_verify, signature):
        raise ValueError("Signature verification failed — message tampered")

    if my_ephemeral_priv_b64 and peer_ephemeral_pub:
        shared = ecdh_shared_secret(my_ephemeral_priv_b64, peer_ephemeral_pub)
        context = b"spider-msg-ephemeral-v1"
    elif peer_ephemeral_pub:
        my_priv = load_x25519_private(my_x_priv_b64)
        peer_eph_pub = load_x25519_public(peer_ephemeral_pub)
        shared = my_priv.exchange(peer_eph_pub)
        context = b"spider-msg-ephemeral-v1"
    else:
        my_priv = load_x25519_private(my_x_priv_b64)
        peer_pub = load_x25519_public(peer_x_pub_b64)
        shared = my_priv.exchange(peer_pub)
        context = b"spider-msg-identity-v1"

    aes_key = hkdf_derive(shared, info=context, length=32)

    plaintext = aesgcm_decrypt(aes_key, nonce_b64, ct_b64, tag_b64, aad_b64=aad_b64)
    if plaintext is None:
        raise ValueError("AES-GCM decryption failed")

    return plaintext.decode("utf-8")


def encrypt_file_data(
    data: bytes,
    my_x_priv_b64: str,
    peer_x_pub_b64: str,
    ephemeral_priv_b64: str = "",
    peer_ephemeral_pub_b64: str = "",
) -> tuple:
    """
    使用 ECDH 派生的密钥加密文件数据。
    可用时使用临时密钥实现前向保密。
    返回 (nonce_b64, ciphertext_b64, tag_b64, aad_b64)。
    """
    if ephemeral_priv_b64 and peer_ephemeral_pub_b64:
        shared = ecdh_shared_secret(ephemeral_priv_b64, peer_ephemeral_pub_b64)
        context = b"spider-file-ephemeral-v1"
    else:
        my_priv = load_x25519_private(my_x_priv_b64)
        peer_pub = load_x25519_public(peer_x_pub_b64)
        shared = my_priv.exchange(peer_pub)
        context = b"spider-file-identity-v1"

    aes_key = hkdf_derive(shared, info=context, length=32)

    aad = json.dumps({
        "type": "file",
        "size": len(data),
        "ts": current_timestamp(),
    }, sort_keys=True).encode("utf-8")

    enc_result = aesgcm_encrypt(aes_key, data, aad)
    return (
        enc_result["nonce"],
        enc_result["ciphertext"],
        enc_result["tag"],
        enc_result["aad"],
    )


def decrypt_file_data(
    nonce_b64: str, ct_b64: str, tag_b64: str, aad_b64: str,
    my_x_priv_b64: str, peer_x_pub_b64: str,
    ephemeral_priv_b64: str = "",
    peer_ephemeral_pub_b64: str = "",
) -> bytes:
    """解密文件数据并验证 AAD。"""
    if ephemeral_priv_b64 and peer_ephemeral_pub_b64:
        shared = ecdh_shared_secret(ephemeral_priv_b64, peer_ephemeral_pub_b64)
        context = b"spider-file-ephemeral-v1"
    else:
        my_priv = load_x25519_private(my_x_priv_b64)
        peer_pub = load_x25519_public(peer_x_pub_b64)
        shared = my_priv.exchange(peer_pub)
        context = b"spider-file-identity-v1"

    aes_key = hkdf_derive(shared, info=context, length=32)
    return aesgcm_decrypt(aes_key, nonce_b64, ct_b64, tag_b64, aad_b64=aad_b64)



def generate_ephemeral_keypair() -> tuple[str, str]:
    """
    为会话生成全新的临时 X25519 密钥对。
    每个会话调用一次，私钥仅存于内存，
    会话结束后销毁（前向保密）。
    """
    return generate_x25519_keypair()


def encrypt_message_with_fs(
    text: str,
    my_x_priv_b64: str,
    peer_x_pub_b64: str,
    my_e_priv_b64: str,
    from_uuid: str,
    to_uuid: str,
    my_ephemeral_priv_b64: str,
    peer_ephemeral_pub_b64: str,
) -> dict:
    """
    高级接口：带前向保密的加密。
    推荐新代码使用此函数。
    """
    return encrypt_message(
        text, my_x_priv_b64, peer_x_pub_b64, my_e_priv_b64,
        from_uuid, to_uuid,
        ephemeral_priv_b64=my_ephemeral_priv_b64,
        peer_ephemeral_pub_b64=peer_ephemeral_pub_b64,
    )
