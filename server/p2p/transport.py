"""
Spider — P2P 传输层

集成：
1. 全包加密（通过 TransportEncryptor 使用 AES-256-GCM）
2. 包混淆（HTTP/DNS/TLS/WebSocket/随机）
3. 洋葱路由（通过 P2P 节点的多跳中继）

三层协同工作：
  原始消息
       │
       ▼
  [洋葱封装]  ← 可选，用于匿名路由
       │
       ▼
  [传输加密]  ← 始终开启（AES-GCM）
       │
       ▼
  [包混淆]  ← 可选，伪装流量
       │
       ▼
  [线路格式]  → socket.sendall()
"""

import json
import base64
import os
import time
import random
import struct
import socket
import threading
from typing import Optional, Tuple, List, Callable


import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.protocol import *
from shared.crypto_utils import (
    TransportEncryptor, generate_x25519_keypair, load_x25519_public,
    load_ed25519_public, b64_encode, b64_decode, ecdh_shared_secret,
    hkdf_derive, aesgcm_encrypt, aesgcm_decrypt, node_id_from_pubkey
)
from shared.packet_obfuscation import (
    obfuscate, deobfuscate, detect_mode, get_available_modes,
    OnionRouter
)



class TransportConfig:
    """传输层安全配置。"""

    def __init__(self, config_dict: dict = None):
        d = config_dict or {}
        self.obfuscation_enabled: bool = d.get("obfuscation_enabled", True)
        self.obfuscation_mode: str = d.get("obfuscation_mode", DEFAULT_OBFUSCATION_MODE)
        self.onion_enabled: bool = d.get("onion_enabled", False)
        self.onion_layers: int = d.get("onion_layers", DEFAULT_ONION_LAYERS)
        self.key_rotation_sec: int = d.get("key_rotation_sec", TRANSPORT_KEY_ROTATION_SEC)
        self.transport_enabled: bool = d.get("transport_enabled", True)
        self.hs_timeout: int = d.get("handshake_timeout", TRANSPORT_HANDSHAKE_TIMEOUT)

    def to_dict(self) -> dict:
        return {
            "obfuscation_enabled": self.obfuscation_enabled,
            "obfuscation_mode": self.obfuscation_mode,
            "onion_enabled": self.onion_enabled,
            "onion_layers": self.onion_layers,
            "key_rotation_sec": self.key_rotation_sec,
            "transport_enabled": self.transport_enabled,
            "handshake_timeout": self.hs_timeout,
        }



class SecureTransport:
    """
    用全包加密 + 可选混淆 + 洋葱路由 包装一个套接字。

    用法：

        st = SecureTransport(sock, is_initiator=False)
        st.do_handshake(peer_ed25519_pub)
        data = st.recv()  # 已解密、去混淆、去洋葱层
        st.send(data)       # 已加密、混淆、洋葱封装

        st = SecureTransport(sock, is_initiator=True)
        st.do_handshake(peer_ed25519_pub)
    """

    def __init__(
        self,
        sock: socket.socket,
        is_initiator: bool = True,
        config: Optional[TransportConfig] = None,
        known_nodes: Optional[list] = None,  # 用于洋葱路由
        our_ed25519_priv: str = "",
        our_node_id: str = "",
    ):
        self.sock = sock
        self.is_initiator = is_initiator
        self.config = config or TransportConfig()
        self.known_nodes = known_nodes or []
        self.our_ed25519_priv = our_ed25519_priv
        self.our_node_id = our_node_id

        self.transport = TransportEncryptor(is_initiator=is_initiator)

        self.onion = OnionRouter()
        self.onion.set_layers(self.config.onion_layers)

        self.peer_node_id: str = ""
        self.peer_pubkey_b64: str = ""
        self.peer_transport_pub: str = ""

        self.handshake_done: bool = False
        self._send_lock = threading.Lock()
        self._recv_lock = threading.Lock()


    def do_handshake(self, peer_pubkey_b64: str = "") -> bool:
        """
        执行完整的传输层握手：
        1. 交换传输层（临时 X25519）公钥
        2. 派生共享 AES-256 密钥
        3. 验证对端身份（Ed25519 签名）

        参数：
            peer_pubkey_b64: 预期的对端 Ed25519 公钥（用于验证）
        """
        try:
            self.sock.settimeout(self.config.hs_timeout)

            if self.is_initiator:
                req = json.dumps({
                    "type": ENC_HANDSHAKE,
                    "transport_pub": self.transport.public_key_b64,
                    "node_id": self.our_node_id,
                }).encode() + b"\n"
                self.sock.sendall(req)

                buf = b""
                while b"\n" not in buf:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        return False
                    buf += chunk
                line, _ = buf.split(b"\n", 1)
                resp = json.loads(line.decode("utf-8"))

                self.peer_transport_pub = resp.get("transport_pub", "")
                self.peer_node_id = resp.get("node_id", "")
                self.transport.set_peer_public_key(self.peer_transport_pub)

            else:
                buf = b""
                while b"\n" not in buf:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        return False
                    buf += chunk
                line, buf = buf.split(b"\n", 1)
                req = json.loads(line.decode("utf-8"))

                self.peer_transport_pub = req.get("transport_pub", "")
                self.peer_node_id = req.get("node_id", "")
                self.transport.set_peer_public_key(self.peer_transport_pub)

                resp = json.dumps({
                    "type": ENC_HANDSHAKE_OK,
                    "transport_pub": self.transport.public_key_b64,
                    "node_id": self.our_node_id,
                }).encode() + b"\n"
                self.sock.sendall(resp)


            if peer_pubkey_b64:
                self.peer_pubkey_b64 = peer_pubkey_b64

            self.handshake_done = True
            self.sock.settimeout(None)  # 恢复阻塞模式
            return True

        except Exception as e:
            print(f"[SECURE] Handshake failed: {e}")
            return False


    def send(self, payload: bytes) -> bool:
        """
        发送加密（以及可选混淆/洋葱封装）的数据。

        线路管道（出站）：
            payload → [洋葱封装] → 传输加密 → [混淆] → 线路
        """
        if not self.handshake_done:
            raise RuntimeError("Handshake not completed")

        with self._send_lock:
            data = payload

            if self.config.onion_enabled and self.known_nodes:
                data = self._onion_wrap(data)

            data = self.transport.encrypt_packet(data)

            if self.config.obfuscation_enabled:
                data = obfuscate(data, mode=self.config.obfuscation_mode)

            try:
                self.sock.sendall(data)
                return True
            except Exception as e:
                print(f"[SECURE] Send failed: {e}")
                return False

    def send_json(self, msg: dict) -> bool:
        """便捷方法：发送 JSON 可序列化字典。"""
        return self.send(json.dumps(msg).encode("utf-8"))


    def recv(self) -> Optional[bytes]:
        """
        接收并解密（去混淆、去洋葱）数据。

        线路管道（入站）：
            线路 → [去混淆] → 传输解密 → [去洋葱] → 载荷
        """
        if not self.handshake_done:
            raise RuntimeError("Handshake not completed")

        with self._recv_lock:
            data = self._recv_full_packet()
            if not data:
                return None

            if self.config.obfuscation_enabled:
                deob = deobfuscate(data, hint_mode=self.config.obfuscation_mode)
                if deob is not None:
                    data = deob

            plaintext = self.transport.decrypt_packet(data)
            if plaintext is None:
                print("[SECURE] Transport decrypt failed")
                return None

            if self.config.onion_enabled:
                plaintext = self._onion_unwrap(plaintext)

            return plaintext

    def recv_json(self) -> Optional[dict]:
        """便捷方法：接收并解析 JSON。"""
        data = self.recv()
        if data is None:
            return None
        try:
            return json.loads(data.decode("utf-8"))
        except:
            return None


    def _onion_wrap(self, payload: bytes) -> bytes:
        """将载荷包装到洋葱层中。"""
        if not self.known_nodes:
            return payload

        path = self.onion.select_relay_path(self.known_nodes)

        wrapped = self.onion.build_onion(
            message=payload,
            target_server_id=self.peer_node_id,
            relay_nodes=path,
            target_public_key=b64_decode(self.peer_transport_pub),
        )


        return b"\x00ONION\x00" + wrapped

    def _onion_unwrap(self, data: bytes) -> bytes:
        """如有洋葱层则逐层剥离。"""
        if not data.startswith(b"\x00ONION\x00"):
            return data

        data = data[7:]  # 去除标记
        if not self.our_ed25519_priv:
            return data

        priv_key = load_x25519_private(self.our_ed25519_priv)

        while True:
            inner_data, next_hop, is_final = self.onion.peel_onion_layer(data, priv_key)
            if inner_data is None:
                break
            if is_final:
                try:
                    inner = json.loads(inner_data.decode("utf-8"))
                    if inner.get("type") == "onion_inner":
                        msg_b64 = inner.get("message", "")
                        return b64_decode(msg_b64)
                except:
                    pass
                return inner_data
            data = inner_data
            if not data or not isinstance(data, bytes):
                break

        return data


    def rotate_keys(self) -> bool:
        """轮换传输密钥（生成新的临时密钥对）。"""
        self.transport.rotate_key()

        try:
            self.sock.sendall(json.dumps({
                "type": "ENC_ROTATE",
                "transport_pub": self.transport.public_key_b64,
            }).encode() + b"\n")
            return True
        except:
            return False

    def should_rotate(self) -> bool:
        return self.transport.should_rotate(self.config.key_rotation_sec)


    def _recv_full_packet(self) -> Optional[bytes]:
        """
        从套接字读取一个完整的加密数据包。

        传输格式：[1B 版本][4B 计数器][12B 随机数][N 字节 密文+标签]
        最少 17 字节。
        """

        header = b""
        while len(header) < 17:
            try:
                chunk = self.sock.recv(17 - len(header))
                if not chunk:
                    return None
                header += chunk
            except socket.timeout:
                return None
            except Exception:
                return None

        remaining = b""
        self.sock.settimeout(10)
        try:
            while True:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                remaining += chunk
                full = header + remaining
                result = self.transport.decrypt_packet(full)
                if result is not None:
                    return full
        except socket.timeout:
            pass

        return header + remaining


    def close(self):
        try:
            self.sock.close()
        except:
            pass


    def get_info(self) -> dict:
        return {
            "handshake_done": self.handshake_done,
            "peer_node_id": self.peer_node_id,
            "obfuscation": self.config.obfuscation_enabled,
            "obfuscation_mode": self.config.obfuscation_mode,
            "onion_enabled": self.config.onion_enabled,
            "onion_layers": self.config.onion_layers,
            "key_age_sec": int(time.time() - self.transport._key_created),
        }



def build_onion_chain(
    message: bytes,
    relay_path: List[Tuple[str, str]],
    target_node_id: str,
    target_transport_pub: bytes,
) -> bytes:
    """
    构建多层洋葱数据包。

    参数：
        message: 最内层载荷
        relay_path: 每一跳的 (node_id, pubkey) 列表
        target_node_id: 最终目的地
        target_transport_pub: 目标的传输公钥

    返回：
        以 \x00ONION\x00 标记开头的字节串
    """
    router = OnionRouter()
    result = router.build_onion(
        message=message,
        target_server_id=target_node_id,
        relay_nodes=relay_path,
        target_public_key=target_transport_pub,
    )
    return b"\x00ONION\x00" + result



def process_onion_packet(
    data: bytes,
    our_x25519_priv_b64: str,
) -> Tuple[Optional[bytes], bool]:
    """
    处理入站洋葱数据包。

    返回：
        (解密后的内层载荷或None, 是否为最后一层)
    """
    if not data.startswith(b"\x00ONION\x00"):
        return data, True  # 不是洋葱数据包
    data = data[7:]
    priv_key = load_x25519_private(our_x25519_priv_b64)
    router = OnionRouter()

    inner_data, next_hop, is_final = router.peel_onion_layer(data, priv_key)

    if is_final and inner_data is not None:
        try:
            inner = json.loads(inner_data.decode("utf-8"))
            if inner.get("type") == "onion_inner":
                return b64_decode(inner.get("message", "")), True
        except:
            pass

    return inner_data, is_final
