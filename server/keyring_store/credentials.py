"""
凭据存储（使用 keyring）。
所有敏感服务端凭据存储在操作系统原生钥匙链中。
支持系统钥匙链 + cryptfile 后备（无显示器服务器）。
"""

import base64
import hashlib
import os
import keyring
from keyring.errors import PasswordDeleteError

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)

SERVICE = "spider-server"



def get_credential(username: str) -> str | None:
    try:
        return keyring.get_password(SERVICE, username)
    except Exception:
        return None

def set_credential(username: str, value: str):
    keyring.set_password(SERVICE, username, value)

def delete_credential(username: str):
    try:
        keyring.delete_password(SERVICE, username)
    except PasswordDeleteError:
        pass



def get_admin_pin_hash() -> tuple | None:
    h = get_credential("admin_pin_hash")
    s = get_credential("admin_pin_salt")
    if h and s:
        return (h, s)
    return None

def set_admin_pin_hash(pin_hash_b64: str, salt_b64: str):
    set_credential("admin_pin_hash", pin_hash_b64)
    set_credential("admin_pin_salt", salt_b64)

def verify_admin_pin(pin: str) -> bool:
    creds = get_admin_pin_hash()
    if not creds:
        return False
    h_b64, s_b64 = creds
    stored_hash = base64.b64decode(h_b64)
    salt = base64.b64decode(s_b64)
    attempt = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100000, dklen=32)
    return attempt == stored_hash



def get_server_keys() -> dict | None:
    keys = {}
    for name in ["server_x25519_priv", "server_x25519_pub",
                 "server_ed25519_priv", "server_ed25519_pub"]:
        val = get_credential(name)
        if not val:
            return None
        keys[name] = val
    return keys

def set_server_keys(keys: dict):
    for name in ["server_x25519_priv", "server_x25519_pub",
                 "server_ed25519_priv", "server_ed25519_pub"]:
        if name in keys:
            set_credential(name, keys[name])

def get_node_id() -> str | None:
    return get_credential("node_id")

def set_node_id(node_id: str):
    set_credential("node_id", node_id)



def get_keyring_service() -> str:
    return SERVICE



def initialize_server_credentials() -> dict:
    """
    首次运行初始化:
    1. 提示输入管理员 PIN
    2. 生成服务器密钥对
    3. 计算 NodeID
    4. 将所有内容存储到 keyring
    返回包含全部凭据的字典（内存中）。
    """
    from .backend import prompt_initial_pin, show_setup_popup

    pin = prompt_initial_pin()

    salt = os.urandom(16)
    pin_hash = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 100000, dklen=32)

    set_admin_pin_hash(
        base64.b64encode(pin_hash).decode(),
        base64.b64encode(salt).decode()
    )


    x_priv = x25519.X25519PrivateKey.generate()
    x_pub = x_priv.public_key()
    x_priv_b64 = base64.b64encode(x_priv.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )).decode()
    x_pub_b64 = base64.b64encode(x_pub.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )).decode()


    e_priv = ed25519.Ed25519PrivateKey.generate()
    e_pub = e_priv.public_key()
    e_priv_b64 = base64.b64encode(e_priv.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption()
    )).decode()
    e_pub_b64 = base64.b64encode(e_pub.public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )).decode()

    keys = {
        "server_x25519_priv": x_priv_b64,
        "server_x25519_pub": x_pub_b64,
        "server_ed25519_priv": e_priv_b64,
        "server_ed25519_pub": e_pub_b64,
    }
    set_server_keys(keys)

    pub_raw = base64.b64decode(e_pub_b64)
    node_id = hashlib.sha256(pub_raw).digest()[:20].hex()
    set_node_id(node_id)

    show_setup_popup("初始化完成", f"服务器NodeID: {node_id}\n密钥已安全存储在系统凭据管理器中。")

    return {
        "node_id": node_id,
        "admin_pin_hash": base64.b64encode(pin_hash).decode(),
        "admin_pin_salt": base64.b64encode(salt).decode(),
        **keys,
    }
