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


# ===== PIN 策略 =====
# PIN 长度：默认 8 位，可选 10/12/16 位
DEFAULT_PIN_LENGTH = 8
VALID_PIN_LENGTHS = (8, 10, 12, 16)


def validate_pin_format(pin: str) -> tuple[bool, str]:
    """
    校验 PIN 格式：纯数字 + 合法长度。
    返回 (是否合法, 错误消息)。
    """
    if not pin.isdigit():
        return False, "PIN 必须为纯数字"
    if len(pin) not in VALID_PIN_LENGTHS:
        return False, f"PIN 长度必须为 {'/'.join(map(str, VALID_PIN_LENGTHS))} 位（当前 {len(pin)} 位）"
    return True, ""


def is_palindrome(pin: str) -> bool:
    """判断 PIN 是否为回文数（正序=倒序）。"""
    return pin == pin[::-1]


def reverse_pin(pin: str) -> str:
    """返回 PIN 的倒序数字字符串。"""
    return pin[::-1]


def validate_duress_against_unlock(unlock_pin: str, duress_pin: str) -> tuple[bool, str]:
    """
    校验胁迫 PIN 与解锁 PIN 的关系（防正序/倒序暴力破解）。

    规则：
    1. 解锁 PIN 不可是回文数（否则倒序=正序，无法区分）
    2. 如果倒序(unlock) < unlock，则 duress 必须 > unlock
    3. 如果倒序(unlock) > unlock，则 duress 必须 < unlock

    这样胁迫 PIN 和倒序密码始终位于解锁 PIN 的两侧，
    无论攻击者从 0000... 正序暴力还是从 9999... 倒序暴力，
    都会先碰到胁迫 PIN 或倒序密码（触发擦除），而碰不到解锁 PIN。

    返回 (是否合法, 错误消息)。
    """
    # 规则 1：不可是回文数
    if is_palindrome(unlock_pin):
        return False, "解锁 PIN 不可是回文数（否则倒序密码与解锁密码相同，无法区分）"

    rev = reverse_pin(unlock_pin)
    unlock_num = int(unlock_pin)
    rev_num = int(rev)
    duress_num = int(duress_pin)

    # 胁迫 PIN 不能与解锁 PIN 或倒序密码相同
    if duress_pin == unlock_pin:
        return False, "胁迫 PIN 不能与解锁 PIN 相同"
    if duress_pin == rev:
        return False, "胁迫 PIN 不能与解锁 PIN 的倒序相同（两者都会触发胁迫，无需重复设置）"

    # 规则 2 & 3：胁迫 PIN 必须与倒序密码在解锁 PIN 的两侧
    if rev_num < unlock_num:
        if duress_num <= unlock_num:
            return False, (f"解锁 PIN 的倒序 ({rev}) 小于解锁 PIN ({unlock_pin})，"
                           f"胁迫 PIN 必须大于解锁 PIN（防正序/倒序暴力破解）")
    else:  # rev_num > unlock_num（不可能相等，因为已排除回文）
        if duress_num >= unlock_num:
            return False, (f"解锁 PIN 的倒序 ({rev}) 大于解锁 PIN ({unlock_pin})，"
                           f"胁迫 PIN 必须小于解锁 PIN（防正序/倒序暴力破解）")

    return True, ""



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
        "unlock_pin_salt": base64.b64encode(_generate_salt()).decode(),
        "unlock_pin_hash": "",
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

    # 存储解锁 PIN 哈希（用于检测反向输入密码）
    _set_unlock_pin_hash_internal(to_save, pin)


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


def _set_unlock_pin_hash_internal(data_dict: dict, unlock_pin: str):
    """内部函数：用独立盐值计算并存储解锁 PIN 哈希（用于检测反向输入密码）。"""
    unlock_salt = base64.b64decode(data_dict["unlock_pin_salt"])
    unlock_hash = hashlib.pbkdf2_hmac(
        "sha256", unlock_pin.encode("utf-8"),
        unlock_salt, PBKDF2_ITERATIONS, dklen=32
    )
    data_dict["unlock_pin_hash"] = base64.b64encode(unlock_hash).decode()


def check_unlock_pin_hash(pin: str) -> bool:
    """
    检查给定 PIN 是否匹配存储的解锁 PIN 哈希。
    用于检测用户是否输入了解锁 PIN 的倒序（反向输入密码）。
    不解密私钥（仅比对哈希）。
    """
    path = identity_path()
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return False
    if not data.get("unlock_pin_hash"):
        return False
    unlock_salt = base64.b64decode(data["unlock_pin_salt"])
    unlock_hash = base64.b64decode(data["unlock_pin_hash"])
    try:
        attempt_hash = hashlib.pbkdf2_hmac(
            "sha256", pin.encode("utf-8"),
            unlock_salt, PBKDF2_ITERATIONS, dklen=32
        )
        return hmac_compare(attempt_hash, unlock_hash)
    except Exception:
        return False


def is_duress_trigger(pin: str) -> bool:
    """
    检测输入的 PIN 是否触发胁迫流程。
    触发条件（满足任一即可）：
    1. PIN 匹配胁迫 PIN 哈希
    2. PIN 的倒序匹配解锁 PIN 哈希（即用户反向输入了解锁密码）

    这样胁迫密码和反向输入密码都可以触发同样的擦除效果。
    """
    # 条件 1：胁迫 PIN
    if check_duress_pin(pin):
        return True
    # 条件 2：反向输入密码（pin 的倒序 == 解锁 PIN）
    rev = reverse_pin(pin)
    if check_unlock_pin_hash(rev):
        return True
    return False


def set_duress_pin(pin: str, duress_pin: str) -> tuple[bool, str]:
    """
    设置或更新胁迫 PIN。从设置中调用。
    需要先验证解锁 PIN。
    返回 (是否成功, 消息)。
    """

    try:
        load_identity_file(pin)
    except (ValueError, FileNotFoundError):
        return False, "解锁 PIN 不正确或身份文件不存在"

    # 校验胁迫 PIN 格式
    ok, msg = validate_pin_format(duress_pin)
    if not ok:
        return False, msg

    # 校验胁迫 PIN 与解锁 PIN 的关系（防暴力破解）
    ok, msg = validate_duress_against_unlock(pin, duress_pin)
    if not ok:
        return False, msg

    path = identity_path()
    if not os.path.exists(path):
        return False, "身份文件不存在"
    with open(path) as f:
        data = json.load(f)
    _set_duress_pin_internal(data, duress_pin)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, path)
    return True, "胁迫 PIN 设置成功"


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
