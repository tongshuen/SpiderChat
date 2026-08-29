"""
客户端密钥管理：生成、加密、解密。(v2)

安全修复:
- 盐值为 os.urandom(16)，完全独立于 UUID
- 显示名称（4-32 字节 UTF-8）严格验证
- 头像支持（最大 64²，格式验证，基于 Pillow 的压缩）
"""

import base64
import hashlib
import os
import json
import struct
from io import BytesIO

from shared.crypto_utils import (
    generate_x25519_keypair, generate_ed25519_keypair,
    b64_encode, b64_decode,
    derive_key_from_pin, aesgcm_encrypt, aesgcm_decrypt,
    sign_data, verify_signature,
    PBKDF2_ITERATIONS, SALT_SIZE,
)
from client.storage.identity import (
    save_identity_file, load_identity_file,
    save_user_profile, load_user_profile,
    set_duress_pin as identity_set_duress_pin,
    clear_duress_pin as identity_clear_duress_pin,
    check_duress_pin,
)


MIN_DISPLAY_NAME = 4
MAX_DISPLAY_NAME = 32

def validate_display_name(name: str) -> tuple[bool, str]:
    """
    验证显示名称（这不是 UUID — 只是用户选择的昵称）。

    规则:
    - 4-32 个字节
    - 必须是有效 UTF-8
    - 无控制字符、无换行符、无空字节
    - 无首尾空格
    - 无路径分隔符或 shell 元字符
    返回 (是否通过, 错误消息)
    """
    if not isinstance(name, str):
        return False, "Display name must be a string"
    stripped = name.strip()
    if stripped != name:
        return False, "Display name cannot have leading/trailing whitespace"
    if not stripped:
        return False, "Display name cannot be empty"
    utf8_bytes = stripped.encode("utf-8")
    if len(utf8_bytes) < MIN_DISPLAY_NAME:
        return False, f"Display name too short (min {MIN_DISPLAY_NAME} UTF-8 bytes, got {len(utf8_bytes)})"
    if len(utf8_bytes) > MAX_DISPLAY_NAME:
        return False, f"Display name too long (max {MAX_DISPLAY_NAME} UTF-8 bytes, got {len(utf8_bytes)})"

    for ch in stripped:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            return False, "Display name contains invalid control characters"

    if "\n" in stripped or "\r" in stripped:
        return False, "Display name cannot contain newlines"

    forbidden = ['/', '\\', ';', '&', '|', '`', '$', '<', '>']
    for f in forbidden:
        if f in stripped:
            return False, f"Display name cannot contain '{f}'"
    return True, ""


def set_display_name(name: str) -> tuple[bool, str]:
    """设置显示名称。返回 (是否成功, 消息)。"""
    ok, err = validate_display_name(name)
    if not ok:
        return False, err
    profile = load_user_profile()
    profile["display_name"] = name.strip()
    save_user_profile(profile)
    return True, "Display name set successfully"


def get_display_name() -> str:
    """获取当前显示名称，若无则返回空字符串。"""
    profile = load_user_profile()
    return profile.get("display_name", "")



MAX_AVATAR_SIZE = 270 * 1024
ALLOWED_AVATAR_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
MAX_AVATAR_DIMENSION = 64 # 像素
def validate_avatar(file_path: str) -> tuple[bool, str, dict]:
    """
    验证头像图片文件。
    检查：文件存在、格式、尺寸（≤64²）、文件大小。
    返回 (是否通过, 错误消息, 信息字典)。
    """
    if not os.path.exists(file_path):
        return False, "File does not exist", {}

    file_size = os.path.getsize(file_path)
    if file_size > MAX_AVATAR_SIZE * 2:  # 允许原始与编码格式之间的差异
        return False, f"File too large (max {MAX_AVATAR_SIZE // 1024}KB)", {}

    try:
        from PIL import Image
        img = Image.open(file_path)
    except ImportError:
        return _validate_avatar_fallback(file_path)
    except Exception as e:
        return False, f"Cannot open image: {e}", {}

    width, height = img.size
    fmt = img.format or "UNKNOWN"

    if width > MAX_AVATAR_DIMENSION or height > MAX_AVATAR_DIMENSION:
        return False, f"Image too large: {width}x{height} (max {MAX_AVATAR_DIMENSION}x{MAX_AVATAR_DIMENSION})", {}


    buf = BytesIO()
    if fmt == "JPEG":
        mime = "image/jpeg"
        img.save(buf, format="JPEG", quality=90, optimize=True)
    elif fmt == "WEBP":
        mime = "image/webp"
        img.save(buf, format="WEBP", quality=90)
    elif fmt == "GIF":
        mime = "image/gif"
        with open(file_path, "rb") as f:
            buf.write(f.read())
    else:
        mime = "image/png"
        img.save(buf, format="PNG", optimize=True)

    b64_data = base64.b64encode(buf.getvalue()).decode("ascii")

    if len(b64_data) > MAX_AVATAR_SIZE:
        buf2 = BytesIO()
        img.save(buf2, format="JPEG", quality=70, optimize=True)
        b64_data = base64.b64encode(buf2.getvalue()).decode("ascii")
        mime = "image/jpeg"
        if len(b64_data) > MAX_AVATAR_SIZE:
            return False, f"Avatar too large after compression (max {MAX_AVATAR_SIZE // 1024}KB)", {}

    info = {
        "width": width,
        "height": height,
        "format": fmt,
        "mime_type": mime,
        "base64_data": b64_data,
        "size_bytes": len(b64_data),
    }
    return True, "", info


def _validate_avatar_fallback(file_path: str) -> tuple[bool, str, dict]:
    """Pillow 未安装时的回退方案。"""
    ext = os.path.splitext(file_path)[1].lower()
    allowed_ext = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
    if ext not in allowed_ext:
        return False, f"Unsupported format: {ext} (allowed: PNG/JPEG/WebP/GIF)", {}
    size = os.path.getsize(file_path)
    if size > MAX_AVATAR_SIZE:
        return False, f"File too large (max {MAX_AVATAR_SIZE // 1024}KB)", {}
    with open(file_path, "rb") as f:
        data = f.read()
    b64 = base64.b64encode(data).decode("ascii")
    mime = "image/png" if ext == ".png" else "image/jpeg"
    return True, "", {
        "width": 0, "height": 0, "format": ext[1:].upper(),
        "mime_type": mime, "base64_data": b64,
        "size_bytes": len(b64),
    }


def set_avatar(file_path: str) -> tuple[bool, str]:
    """从文件路径设置头像。返回 (是否成功, 消息)。"""
    ok, err, info = validate_avatar(file_path)
    if not ok:
        return False, err
    profile = load_user_profile()
    profile["avatar_b64"] = info["base64_data"]
    profile["avatar_mime"] = info["mime_type"]
    profile["avatar_width"] = info["width"]
    profile["avatar_height"] = info["height"]
    save_user_profile(profile)
    return True, f"Avatar set ({info['width']}x{info['height']}, {info['size_bytes'] // 1024}KB)"


def clear_avatar() -> bool:
    """移除头像。"""
    profile = load_user_profile()
    for k in ["avatar_b64", "avatar_mime", "avatar_width", "avatar_height"]:
        profile.pop(k, None)
    save_user_profile(profile)
    return True


def get_avatar_b64() -> str:
    """获取头像 base64 数据，若无则返回空字符串。"""
    profile = load_user_profile()
    return profile.get("avatar_b64", "")


def get_avatar_mime() -> str:
    """获取头像 MIME 类型，若无则返回空字符串。"""
    profile = load_user_profile()
    return profile.get("avatar_mime", "")



def generate_keypairs() -> dict:
    """生成 X25519 和 Ed25519 密钥对。返回 base64 字符串字典。"""
    x_priv, x_pub = generate_x25519_keypair()
    e_priv, e_pub = generate_ed25519_keypair()
    return {
        "x25519_public": x_pub,
        "x25519_private": x_priv,
        "ed25519_public": e_pub,
        "ed25519_private": e_priv,
    }



def encrypt_private_keys(keys_b64: dict, pin: str, uuid_str: str = "") -> dict:
    """
    使用 PIN 派生的 AES 密钥加密私钥。
    盐值为随机 os.urandom(16) — 不从 UUID 派生。

    返回包含加密数据 + 独立盐值 + nonce + tag + AAD 的字典。
    """
    salt = os.urandom(SALT_SIZE)
    key = derive_key_from_pin(pin, salt)

    result = {
        "pin_salt": base64.b64encode(salt).decode(),
        "kdf_iterations": PBKDF2_ITERATIONS,
    }

    aad = b"spider-legacy-encryption"
    for k, v in keys_b64.items():
        if "private" in k:
            raw = base64.b64decode(v)
            enc_result = aesgcm_encrypt(key, raw, aad)
            result[k + "_enc"] = enc_result["ciphertext"]
            result[k + "_nonce"] = enc_result["nonce"]
            result[k + "_tag"] = enc_result["tag"]
            result[k + "_aad"] = enc_result["aad"]
        else:
            result[k] = v

    return result


def decrypt_private_keys(encrypted_data: dict, pin: str) -> dict:
    """
    使用 PIN 解密私钥。返回 base64 私钥字典。
    PIN 错误时抛出 ValueError。
    """
    salt = base64.b64decode(encrypted_data["pin_salt"])
    key = derive_key_from_pin(pin, salt)

    result = {}
    for k in encrypted_data:
        if k.endswith("_enc") and "private" in k:
            base_name = k[:-4]
            nonce = encrypted_data.get(base_name + "_nonce", "")
            ct = encrypted_data.get(base_name + "_enc", "")
            tag = encrypted_data.get(base_name + "_tag", "")
            aad_b64 = encrypted_data.get(base_name + "_aad", "")

            raw = aesgcm_decrypt(key, nonce, ct, tag, aad_b64=aad_b64)
            if raw is None:
                raise ValueError(f"Failed to decrypt {base_name} — wrong PIN?")
            result[base_name] = base64.b64encode(raw).decode()
        elif not k.endswith(("_nonce", "_enc", "_tag", "_aad")) and k not in ("pin_salt", "kdf_iterations"):
            result[k] = encrypted_data[k]
    return result



def load_identity(pin: str) -> dict:
    """加载并解密身份文件。返回完整身份字典。"""
    return load_identity_file(pin)


def save_identity(identity: dict, pin: str, uuid_str: str = ""):
    """加密私钥并保存身份文件（旧版封装）。"""
    from client.utils.config import identity_path
    enc = encrypt_private_keys(
        {k: v for k, v in identity.items() if "private" in k or "public" in k},
        pin
    )
    to_save = {
        "uuid": identity["uuid"],
        "mac_address": identity.get("mac_address", ""),
        "server_host": identity.get("server_host", ""),
        "server_port": identity.get("server_port", 0),
    }
    to_save.update(enc)
    path = identity_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(to_save, f, indent=2)
    os.replace(tmp, path)


def delete_identity():
    """清除所有本地身份、资料和聊天数据。由胁迫 PIN 调用。"""
    from client.utils.config import identity_path, chat_db_path, contacts_path, profile_path
    paths = [
        identity_path(), chat_db_path(), contacts_path(), profile_path(),
    ]
    for fp in paths:
        if os.path.exists(fp):
            try:
                size = os.path.getsize(fp)
                with open(fp, "rb+") as f:
                    f.write(os.urandom(size))
            except Exception:
                pass
            try:
                os.remove(fp)
            except Exception:
                pass
    data_dir = os.path.dirname(identity_path())
    if os.path.exists(data_dir):
        for fname in os.listdir(data_dir):
            fp = os.path.join(data_dir, fname)
            if os.path.isfile(fp):
                try:
                    size = os.path.getsize(fp)
                    with open(fp, "rb+") as f:
                        f.write(os.urandom(size))
                    os.remove(fp)
                except Exception:
                    pass



def set_duress_pin(unlock_pin: str, duress_pin: str) -> tuple[bool, str]:
    """
    设置胁迫 PIN。需要解锁 PIN 进行身份验证。
    返回 (是否成功, 消息)。
    """
    try:
        load_identity_file(unlock_pin)
    except (ValueError, FileNotFoundError):
        return False, "Unlock PIN is incorrect or identity not found"

    if not duress_pin.isdigit() or len(duress_pin) != 6:
        return False, "Duress PIN must be 6 digits"

    ok = identity_set_duress_pin(unlock_pin, duress_pin)
    if ok:
        return True, "Duress PIN set successfully"
    return False, "Failed to set duress PIN"


def verify_duress_pin(pin: str) -> bool:
    """检查给定 PIN 是否为胁迫 PIN。"""
    return check_duress_pin(pin)


def remove_duress_pin(unlock_pin: str) -> tuple[bool, str]:
    """移除胁迫 PIN。需要解锁 PIN。"""
    ok = identity_clear_duress_pin(unlock_pin)
    if ok:
        return True, "Duress PIN removed"
    return False, "Failed to remove duress PIN"
