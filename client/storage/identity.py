"""
身份文件存储 — 读写加密身份。(v2 — 安全加固版)

SECURITY FIXES:
- PBKDF2 salt is os.urandom(16), NOT derived from UUID
- Duress PIN gets its own independent salt + hash, stored properly
- Separate encryption keys for unlock vs duress domain
- Wipe function also deletes the identity file atomically
- Display name and avatar stored separately in profile.json
"""

import json
import os
import base64
import hashlib

from client.utils.config import identity_path, contacts_path, profile_path
from shared.crypto_utils import (
    derive_key_from_pin, aesgcm_encrypt, aesgcm_decrypt,
    PBKDF2_ITERATIONS, SALT_SIZE,
)


def _generate_salt() -> bytes:
    """生成密码学安全的随机 16 字节盐值。"""
    return os.urandom(SALT_SIZE)



def save_identity_file(identity: dict, pin: str, duress_pin: str = ""):
    """
    Save identity to disk. Private keys are encrypted with PIN-derived key.

    Args:
        identity: dict with uuid, mac_address, server_host, server_port,
                  x25519_public, x25519_private, ed25519_public, ed25519_private
        pin: unlock PIN (6 digits)
        duress_pin: duress PIN (6 digits), optional at save time
    """
    enc_salt = _generate_salt()
    enc_key = derive_key_from_pin(pin, enc_salt)

    to_save = {
        "uuid": identity["uuid"],
        "mac_address": identity.get("mac_address", ""),
        "server_host": identity.get("server_host", ""),
        "server_port": identity.get("server_port", 0),
        "encryption_salt": base64.b64encode(enc_salt).decode(),
        "kdf_iterations": PBKDF2_ITERATIONS,
        "duress_salt": base64.b64encode(_generate_salt()).decode(),
        "duress_pin_hash": "",
        "has_duress_pin": False,
    }


    for key_name in ["x25519_public", "ed25519_public"]:
        if key_name in identity:
            to_save[key_name] = identity[key_name]


    aad = b"spider-identity-encryption"
    for key_name in ["x25519_private", "ed25519_private"]:
        if key_name in identity:
            raw = base64.b64decode(identity[key_name])
            enc_result = aesgcm_encrypt(enc_key, raw, aad)
            to_save[key_name + "_enc"] = enc_result["ciphertext"]
            to_save[key_name + "_nonce"] = enc_result["nonce"]
            to_save[key_name + "_tag"] = enc_result["tag"]
            to_save[key_name + "_aad"] = enc_result["aad"]

    if duress_pin:
        _set_duress_pin_internal(to_save, duress_pin)


    path = identity_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(to_save, f, indent=2)
    os.replace(tmp_path, path)


def _set_duress_pin_internal(data_dict: dict, duress_pin: str):
    """内部函数：用独立盐值计算并存储胁迫 PIN 哈希。"""
    duress_salt = base64.b64decode(data_dict["duress_salt"])
    duress_hash = hashlib.pbkdf2_hmac(
        "sha256", duress_pin.encode("utf-8"),
        duress_salt, PBKDF2_ITERATIONS, dklen=32
    )
    data_dict["duress_pin_hash"] = base64.b64encode(duress_hash).decode()
    data_dict["has_duress_pin"] = True


def set_duress_pin(pin: str, duress_pin: str) -> bool:
    """
    设置或更新胁迫 PIN。从设置中调用。
    需要先验证解锁 PIN。
    成功返回 True。
    """

    try:
        load_identity_file(pin)
    except (ValueError, FileNotFoundError):
        return False

    path = identity_path()
    if not os.path.exists(path):
        return False
    with open(path) as f:
        data = json.load(f)
    _set_duress_pin_internal(data, duress_pin)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)
    return True


def clear_duress_pin(pin: str) -> bool:
    """清除胁迫 PIN（需验证解锁 PIN）。"""
    path = identity_path()
    if not os.path.exists(path):
        return False
    try:
        load_identity_file(pin)
    except (ValueError, FileNotFoundError):
        return False
    with open(path) as f:
        data = json.load(f)
    data["duress_pin_hash"] = ""
    data["has_duress_pin"] = False
    data["duress_salt"] = base64.b64encode(_generate_salt()).decode()
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)
    return True


def load_identity_file(pin: str) -> dict:
    """
    Load and decrypt identity file.
    Returns full identity dict with decrypted private keys (base64).
    Raises ValueError if PIN is wrong.
    Raises FileNotFoundError if identity file missing.
    """
    path = identity_path()
    if not os.path.exists(path):
        raise FileNotFoundError("Identity file not found")

    with open(path) as f:
        data = json.load(f)


    enc_salt = base64.b64decode(data["encryption_salt"])
    enc_key = derive_key_from_pin(pin, enc_salt)

    result = {
        "uuid": data["uuid"],
        "mac_address": data.get("mac_address", ""),
        "server_host": data.get("server_host", ""),
        "server_port": data.get("server_port", 0),
        "has_duress_pin": data.get("has_duress_pin", False),
    }

    for key_name in ["x25519_public", "ed25519_public"]:
        if key_name in data:
            result[key_name] = data[key_name]

    aad = b"spider-identity-encryption"
    for key_name in ["x25519_private", "ed25519_private"]:
        enc_key_name = key_name + "_enc"
        nonce_key = key_name + "_nonce"
        tag_key = key_name + "_tag"
        aad_key = key_name + "_aad"
        if all(k in data for k in [enc_key_name, nonce_key, tag_key]):
            ct = data[enc_key_name]
            nonce = data[nonce_key]
            tag = data[tag_key]
            aad_b64 = data.get(aad_key, base64.b64encode(aad).decode())
            raw = aesgcm_decrypt(enc_key, nonce, ct, tag, aad_b64=aad_b64)
            if raw is None:
                raise ValueError("PIN incorrect or identity file corrupted")
            result[key_name] = base64.b64encode(raw).decode()

    return result


def check_duress_pin(pin: str) -> bool:
    """
    Check if the given PIN matches the stored duress PIN hash.
    Returns True if it's the duress PIN.
    Does NOT decrypt private keys (by design).
    """
    path = identity_path()
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return False

    if not data.get("has_duress_pin") or not data.get("duress_pin_hash"):
        return False

    duress_salt = base64.b64decode(data["duress_salt"])
    duress_hash = base64.b64decode(data["duress_pin_hash"])

    try:
        attempt_hash = hashlib.pbkdf2_hmac(
            "sha256", pin.encode("utf-8"),
            duress_salt, PBKDF2_ITERATIONS, dklen=32
        )
        return hmac_compare(attempt_hash, duress_hash)
    except Exception:
        return False


def hmac_compare(a: bytes, b: bytes) -> bool:
    """恒定时间比较。"""
    import hmac
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


def wipe_all_data():
    """
    原子性地删除所有本地数据文件。在输入胁迫 PIN 时调用。
    删除前用随机数据覆写文件（安全删除）。
    """
    from client.utils.config import get_data_dir

    data_dir = get_data_dir()
    files_to_wipe = []

    for fname in ["identity.json", "settings.json", "contacts.json",
                  "profile.json", "messages.db", "session_keys.db"]:
        fp = os.path.join(data_dir, fname)
        if os.path.exists(fp):
            files_to_wipe.append(fp)

    if os.path.exists(data_dir):
        for fname in os.listdir(data_dir):
            fp = os.path.join(data_dir, fname)
            if os.path.isfile(fp) and fp not in files_to_wipe:
                files_to_wipe.append(fp)

    for fp in files_to_wipe:
        try:
            size = os.path.getsize(fp)
            with open(fp, "rb+") as f:
                f.write(os.urandom(size))
            os.remove(fp)
        except Exception:
            try:
                os.remove(fp)
            except Exception:
                pass



def save_contacts(contacts: list):
    path = contacts_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(contacts, f, indent=2)
    os.replace(tmp, path)


def load_contacts() -> list:
    path = contacts_path()
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)



def save_user_profile(profile: dict):
    """
    Save user profile (display name + avatar) separately from identity.
    Profile is NOT encrypted (display name is public metadata).
    Avatar is stored as base64.

    Profile dict: {display_name, avatar_b64, avatar_mime, avatar_width, avatar_height}
    """
    path = profile_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(profile, f, indent=2)
    os.replace(tmp, path)


def load_user_profile() -> dict:
    """加载用户资料。未设置时返回空字典。"""
    path = profile_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}
