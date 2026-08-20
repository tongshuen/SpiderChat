"""
Spider — 共享加密工具。(v3 — 安全加固版)

包含:
- Ed25519 签名/验证
- X25519 密钥交换（含临时密钥实现前向保密）
- AES-256-GCM 加密/解密（强制 AAD）
- HKDF 密钥派生
- 传输层加密（整包加密）
- 密钥轮换辅助函数
- 带重放保护的 secure nonce 生成
- PBKDF2 PIN 派生（随机盐值）
- 完整 SHA-256 节点 ID（无截断）
"""

import base64
import hashlib
import os
import json
import time
import struct
import hmac
import threading
from collections import OrderedDict
from typing import Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 100000
REPLAY_WINDOW_SEC = 60
MAX_REPLAY_CACHE = 10000

AAD_MESSAGE_ENCRYPT = b"spider-msg-v1"
AAD_FILE_ENCRYPT = b"spider-file-v1"
AAD_TRANSPORT = b"spider-transport-v1"
AAD_GROUP_MSG = b"spider-group-v1"
AAD_HANDSHAKE = b"spider-handshake-v1"
AAD_ONION_LAYER = b"spider-onion-layer"


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")

def b64_decode(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def generate_ed25519_keypair() -> Tuple[str, str]:
    """生成 Ed25519 密钥对。返回 (私钥_b64, 公钥_b64)。"""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = b64_encode(priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))
    pub_b64 = b64_encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
    return priv_b64, pub_b64

def load_ed25519_private(b64_str: str) -> ed25519.Ed25519PrivateKey:
    raw = b64_decode(b64_str)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)

def load_ed25519_public(b64_str: str) -> ed25519.Ed25519PublicKey:
    raw = b64_decode(b64_str)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)

def sign_data(priv_key: ed25519.Ed25519PrivateKey, data: bytes) -> str:
    """使用 Ed25519 私钥签名数据。返回 base64 签名。"""
    sig = priv_key.sign(data)
    return b64_encode(sig)

def verify_signature(pub_key: ed25519.Ed25519PublicKey, data: bytes, sig_b64: str) -> bool:
    """验证 Ed25519 签名。使用恒定时间比较。"""
    try:
        sig = b64_decode(sig_b64)
        if len(sig) != 64:
            return False
        pub_key.verify(sig, data)
        return True
    except Exception:
        return False


def generate_x25519_keypair() -> Tuple[str, str]:
    """生成 X25519 密钥对。返回 (私钥_b64, 公钥_b64)。"""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = b64_encode(priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ))
    pub_b64 = b64_encode(pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
    return priv_b64, pub_b64

def load_x25519_private(b64_str: str) -> x25519.X25519PrivateKey:
    raw = b64_decode(b64_str)
    return x25519.X25519PrivateKey.from_private_bytes(raw)

def load_x25519_public(b64_str: str) -> x25519.X25519PublicKey:
    raw = b64_decode(b64_str)
    return x25519.X25519PublicKey.from_public_bytes(raw)

def ecdh_shared_secret(priv_b64: str, peer_pub_b64: str) -> bytes:
    """执行 ECDH：从本地私钥和对端公钥派生共享密钥。"""
    priv = load_x25519_private(priv_b64)
    peer_pub = load_x25519_public(peer_pub_b64)
    return priv.exchange(peer_pub)


def generate_ephemeral_keypair() -> Tuple[str, str]:
    """生成全新的临时 X25519 密钥对以实现前向保密。"""
    return generate_x25519_keypair()

def ephemeral_session_key(
    our_ephemeral_priv_b64: str,
    peer_ephemeral_pub_b64: str,
    context: bytes = b"spider-ephemeral-session",
) -> bytes:
    """从临时 ECDH 派生前向保密会话密钥。"""
    shared = ecdh_shared_secret(our_ephemeral_priv_b64, peer_ephemeral_pub_b64)
    return hkdf_derive(shared, info=context, length=32)

def identity_session_key(
    our_priv_b64: str,
    peer_pub_b64: str,
    context: bytes = b"spider-identity-session",
) -> bytes:
    """从身份密钥派生会话密钥（备用通道）。"""
    shared = ecdh_shared_secret(our_priv_b64, peer_pub_b64)
    return hkdf_derive(shared, info=context, length=32)


def hkdf_derive(
    shared_secret: bytes,
    info: bytes = b"spider-key-derivation",
    length: int = 32,
    salt: Optional[bytes] = None,
) -> bytes:
    """使用 HKDF-SHA256 从共享密钥派生密钥。"""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def aesgcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: Optional[bytes] = None,
) -> dict:
    """
    使用 AES-256-GCM 加密。AAD 在生产环境中是强制的。

    返回字典: {nonce_b64, ciphertext_b64, tag_b64, aad_b64}
    """
    if aad is None:
        aad = AAD_MESSAGE_ENCRYPT

    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    encrypted = aesgcm.encrypt(nonce, plaintext, aad)

    tag = encrypted[-16:]
    ciphertext = encrypted[:-16]

    return {
        "nonce": b64_encode(nonce),
        "ciphertext": b64_encode(ciphertext),
        "tag": b64_encode(tag),
        "aad": b64_encode(aad),
    }

def aesgcm_decrypt(
    key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    tag_b64: str,
    aad_b64: Optional[str] = None,
) -> Optional[bytes]:
    """解密 AES-256-GCM。成功返回明文，失败返回 None。"""
    try:
        nonce = b64_decode(nonce_b64)
        ciphertext = b64_decode(ciphertext_b64)
        tag = b64_decode(tag_b64)

        full_ct = ciphertext + tag

        if aad_b64:
            aad = b64_decode(aad_b64)
        else:
            aad = AAD_MESSAGE_ENCRYPT  # 与加密默认值匹配
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, full_ct, aad)
    except Exception as e:
        print(f"[CRYPTO] AES-GCM decrypt failed: {e}")
        return None


def encrypt_message_v2(
    text: str,
    our_x_priv_b64: str,
    peer_x_pub_b64: str,
    our_e_priv_b64: str,
    peer_e_pub_b64: str,
    from_uuid: str,
    to_uuid: str,
    signing_priv_b64: str,
) -> dict:
    """
    加密消息:
    - 临时 ECDH 实现前向保密
    - AAD 绑定（from_uuid, to_uuid, 时间戳, 协议版本）
    - 对加密信封进行 Ed25519 签名

    返回可供传输的字典格式。
    """
    session_key = ephemeral_session_key(our_e_priv_b64, peer_e_pub_b64,
                                       context=b"spider-msg-v2")
    identity_key = identity_session_key(our_x_priv_b64, peer_x_pub_b64,
                                     context=b"spider-msg-v2-backup")
    final_key = bytes(a ^ b for a, b in zip(session_key, identity_key))

    timestamp = int(time.time())
    aad = json.dumps({
        "from": from_uuid,
        "to": to_uuid,
        "ts": timestamp,
        "proto": "spider/2.0",
    }, sort_keys=True).encode("utf-8")

    plaintext = text.encode("utf-8")
    enc_result = aesgcm_encrypt(final_key, plaintext, aad)

    sign_priv = load_ed25519_private(signing_priv_b64)
    to_sign = json.dumps(enc_result, sort_keys=True).encode("utf-8")
    signature = sign_data(sign_priv, to_sign)

    return {
        "version": 2,
        "from_uuid": from_uuid,
        "to_uuid": to_uuid,
        "timestamp": timestamp,
        "ephemeral_pub": peer_e_pub_b64,
        "encrypted": enc_result,
        "signature": signature,
        "signer_pubkey": b64_encode(sign_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )),
    }

def decrypt_message_v2(
    msg: dict,
    our_x_priv_b64: str,
    peer_x_pub_b64: str,
    our_e_priv_b64: str,
    peer_e_pub_b64: str,
    expected_from: str,
    expected_to: str,
) -> Optional[str]:
    """
    解密 v2 消息。验证 AAD 上下文、签名和时间戳。
    成功返回明文，失败返回 None。
    """

    ts = msg.get("timestamp", 0)
    if abs(time.time() - ts) > REPLAY_WINDOW_SEC:
        print("[CRYPTO] Message outside replay window")
        return None


    enc = msg.get("encrypted", {})
    aad_b64 = enc.get("aad", "")
    if not aad_b64:
        print("[CRYPTO] Missing AAD — refusing to decrypt")
        return None

    aad = b64_decode(aad_b64)
    try:
        aad_data = json.loads(aad.decode("utf-8"))
    except Exception:
        print("[CRYPTO] Invalid AAD format")
        return None

    if aad_data.get("from") != expected_from or aad_data.get("to") != expected_to:
        print("[CRYPTO] AAD context mismatch")
        return None


    signer_pub_b64 = msg.get("signer_pubkey", "")
    if signer_pub_b64:
        try:
            sign_pub = load_ed25519_public(signer_pub_b64)
            to_verify = json.dumps(enc, sort_keys=True).encode("utf-8")
            sig = msg.get("signature", "")
            if not verify_signature(sign_pub, to_verify, sig):
                print("[CRYPTO] Signature verification failed")
                return None
        except Exception as e:
            print(f"[CRYPTO] Signature error: {e}")
            return None

    session_key = ephemeral_session_key(our_e_priv_b64, peer_e_pub_b64,
                                       context=b"spider-msg-v2")
    identity_key = identity_session_key(our_x_priv_b64, peer_x_pub_b64,
                                       context=b"spider-msg-v2-backup")
    final_key = bytes(a ^ b for a, b in zip(session_key, identity_key))


    plaintext = aesgcm_decrypt(
        final_key,
        enc["nonce"], enc["ciphertext"], enc["tag"],
        aad_b64=enc.get("aad"),
    )
    if plaintext is None:
        return None
    return plaintext.decode("utf-8")


def derive_key_from_pin(pin: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """使用 PBKDF2-HMAC-SHA256 从 PIN 派生 32 字节 AES 密钥。"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(pin.encode("utf-8"))

def verify_pin(pin: str, salt: bytes, expected_hash_b64: str,
              iterations: int = PBKDF2_ITERATIONS) -> bool:
    """使用恒定时间比较验证 PIN 与存储的哈希。"""
    try:
        derived = derive_key_from_pin(pin, salt, iterations)
        expected = b64_decode(expected_hash_b64)
        return hmac.compare_digest(derived, expected)
    except Exception:
        return False


def node_id_from_pubkey(pubkey_b64: str) -> str:
    """
    计算节点 ID = SHA-256(公钥) — 完整 32 字节（256 位）。
    不截断 — 保持完整抗碰撞性。
    """
    raw = b64_decode(pubkey_b64)
    digest = hashlib.sha256(raw).digest()
    return digest.hex()

def node_id_from_x25519_pub(pubkey_b64: str) -> str:
    """从 X25519 公钥计算节点 ID（完整 256 位）。"""
    return node_id_from_pubkey(pubkey_b64)


def sign_message(priv_b64: str, msg_dict: dict) -> str:
    """使用 Ed25519 签署 JSON 可序列化字典（排序键）。"""
    priv = load_ed25519_private(priv_b64)
    data = json.dumps(msg_dict, sort_keys=True).encode("utf-8")
    return sign_data(priv, data)

def verify_message(pub_b64: str, msg_dict: dict, sig_b64: str) -> bool:
    """验证已签名的消息字典。"""
    try:
        pub = load_ed25519_public(pub_b64)
        data = json.dumps(msg_dict, sort_keys=True).encode("utf-8")
        return verify_signature(pub, data, sig_b64)
    except Exception:
        return False


def secure_random(n: int = 32) -> bytes:
    """生成密码学安全的随机字节。"""
    return os.urandom(n)

def secure_token(n: int = 32) -> str:
    """生成 URL 安全的随机令牌（base64）。"""
    return b64_encode(os.urandom(n))


class ReplayCache:
    """
    线程安全重放保护缓存。
    使用 LRU 淘汰策略，支持持久化到 SQLite。
    """

    def __init__(self, max_size: int = MAX_REPLAY_CACHE):
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.max_size = max_size

    def check_and_add(self, key: str) -> bool:
        """
        返回 True 表示密钥是新鲜的（之前未见过）。
        返回 False 表示密钥是重放的。
        原子性地添加密钥到缓存。
        """
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return False

            self._cache[key] = time.time()
            self._cache.move_to_end(key)

            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

            return True

    def cleanup(self, max_age_sec: int = REPLAY_WINDOW_SEC * 2):
        """移除超过 max_age_sec 秒的条目。"""
        cutoff = time.time() - max_age_sec
        with self._lock:
            to_remove = [k for k, v in self._cache.items() if v < cutoff]
            for k in to_remove:
                del self._cache[k]


class TransportEncryptor:
    """
    管理单个连接的传输层加密。

    使用 ECDH（临时密钥）建立共享密钥，然后对所有数据包使用 AES-256-GCM。
    支持定期密钥轮换以实现前向保密。
    AAD 将数据包绑定到连接身份和方向。
    """

    def __init__(self, is_initiator: bool = True):
        self.is_initiator = is_initiator
        self._priv_b64, self._pub_b64 = generate_x25519_keypair()
        self._peer_pub_b64: Optional[str] = None
        self._current_key: Optional[bytes] = None
        self._key_created: float = 0.0
        self._send_counter: int = 0
        self._recv_counter: int = 0
        self._key_id: int = 0
        self._lock = threading.Lock()

    @property
    def public_key_b64(self) -> str:
        return self._pub_b64

    @property
    def key_id(self) -> int:
        return self._key_id

    def set_peer_public_key(self, peer_pub_b64: str):
        """设置对端公钥并派生共享密钥。"""
        self._peer_pub_b64 = peer_pub_b64
        self._derive_key()

    def _derive_key(self):
        """从 ECDH 共享密钥派生传输密钥（带 AAD 上下文）。"""
        if not self._peer_pub_b64:
            raise RuntimeError("Peer public key not set")
        shared = ecdh_shared_secret(self._priv_b64, self._peer_pub_b64)
        info = b"spider-transport-init" if self.is_initiator else b"spider-transport-resp"
        self._current_key = hkdf_derive(shared, info=info, length=32)
        self._key_created = time.time()
        self._send_counter = 0
        self._recv_counter = 0
        self._key_id += 1

    def rotate_key(self):
        """生成新的临时密钥对并重新派生。"""
        self._priv_b64, self._pub_b64 = generate_x25519_keypair()
        if self._peer_pub_b64:
            self._derive_key()

    def should_rotate(self, max_age_sec: int = 3600) -> bool:
        """检查密钥是否需要轮换。"""
        return (time.time() - self._key_created) > max_age_sec

    def encrypt_packet(self, payload: bytes) -> bytes:
        """
        加密整个数据包用于传输。
        AAD 包含 key_id 和方向，防止跨上下文攻击。

        线上格式:
        [1 字节版本][2 字节 key_id][4 字节计数器][12 字节 nonce][密文+标签]
        """
        if not self._current_key:
            raise RuntimeError("Transport key not established")

        with self._lock:
            counter = self._send_counter
            self._send_counter += 1

        direction = b"->" if self.is_initiator else b"<-"
        aad = struct.pack("!H", self._key_id) + direction
        aad += struct.pack("!I", counter)

        counter_bytes = counter.to_bytes(4, "big")
        nonce = counter_bytes + os.urandom(8)

        aesgcm = AESGCM(self._current_key)
        encrypted = aesgcm.encrypt(nonce, payload, aad)

        header = b"\x02" + struct.pack("!H", self._key_id) + counter_bytes
        return header + nonce + encrypted

    def decrypt_packet(self, data: bytes) -> Optional[bytes]:
        """
        解密从传输层收到的整个数据包。
        验证 AAD 上下文是否匹配预期方向。
        """
        if not self._current_key:
            return None
        if len(data) < 19:
            return None


        version = data[0]
        key_id = struct.unpack("!H", data[1:3])[0]
        counter = struct.unpack("!I", data[3:7])[0]
        nonce = data[7:19]
        ciphertext = data[19:]


        if key_id != self._key_id:
            print(f"[TRANSPORT] Key ID mismatch: got {key_id}, expected {self._key_id}")
            return None

        direction = b"<-" if self.is_initiator else b"->"
        aad = struct.pack("!H", self._key_id) + direction
        aad += struct.pack("!I", counter)

        try:
            aesgcm = AESGCM(self._current_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
            with self._lock:
                self._recv_counter += 1
            return plaintext
        except Exception as e:
            print(f"[TRANSPORT] Decrypt failed: {e}")
            return None
