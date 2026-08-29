"""
会话密钥管理。
每个会话通过 ECDH 派生唯一的会话密钥。
"""

import hashlib
import os
from shared.crypto_utils import (
    ecdh_shared_secret, hkdf_derive,
    load_x25519_private, load_x25519_public
)

_session_keys = {}

def get_session_key(my_uuid: str, peer_uuid: str,
                     my_x_priv_b64: str, peer_x_pub_b64: str) -> bytes:
    """
    获取或创建会话密钥。
    使用双方的 UUID 作为 HKDF 的盐值输入。
    """
    pair = tuple(sorted([my_uuid, peer_uuid]))
    if pair in _session_keys:
        return _session_keys[pair]

    my_priv = load_x25519_private(my_x_priv_b64)
    peer_pub = load_x25519_public(peer_x_pub_b64)
    shared = ecdh_shared_secret(my_priv, peer_pub)

    salt_input = ("|".join(pair)).encode()
    salt = hashlib.sha256(salt_input).digest()
    key = hkdf_derive(shared, info=b"spider-session-key-v1", length=32, salt=salt)
    _session_keys[pair] = key
    return key

def clear_session_key(my_uuid: str, peer_uuid: str):
    pair = tuple(sorted([my_uuid, peer_uuid]))
    _session_keys.pop(pair, None)

def clear_all_sessions():
    _session_keys.clear()
