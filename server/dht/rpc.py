"""
DHT RPC 消息处理器。
本模块提供 DHT 协议消息的发送/接收逻辑。
所有出站消息均使用 Ed25519 签名，与 node.py 的验证机制对齐。
"""

import json
import socket
import time
import os
from shared.protocol import *
from shared.crypto_utils import (
    sign_data, verify_signature,
    load_ed25519_private, load_ed25519_public,
    b64_encode, b64_decode,
)


class DHTRPC:
    """处理 DHT RPC 消息的发送和分发。"""

    def __init__(self, dht_node):
        self.node = dht_node
        self._pending_find: dict[str, list] = {}  # target_id -> [results]
        self._pending_lock = dht_node._seen_lock  # 复用锁

    # ─── 签名辅助 ────────────────────────────────────────────

    def _sign(self, msg: dict) -> dict:
        """为消息添加 timestamp / nonce / signature / signer_pubkey。"""
        if "timestamp" not in msg:
            msg["timestamp"] = int(time.time())
        if "nonce" not in msg:
            msg["nonce"] = b64_encode(os.urandom(8))
        signable = json.dumps(msg, sort_keys=True).encode("utf-8")
        priv = load_ed25519_private(self.node._dht_priv_b64)
        msg["signature"] = sign_data(priv, signable)
        msg["signer_pubkey"] = self.node._dht_pub_b64
        return msg

    # ─── 发送方法（均带签名） ────────────────────────────────

    def send_ping(self, sock: socket.socket, addr: tuple) -> bool:
        msg = {
            "type": DHT_PING,
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
            return True
        except Exception:
            return False

    def send_find_node(self, sock: socket.socket, addr: tuple, target_id: str):
        msg = {
            "type": "FIND_NODE",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "target_id": target_id,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT-RPC] FIND_NODE send error: {e}")

    def send_find_node_response(self, sock: socket.socket, addr: tuple,
                                target_id: str, nodes: list):
        msg = {
            "type": "FIND_NODE_RESPONSE",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "target_id": target_id,
            "nodes": nodes,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT-RPC] FIND_NODE_RESPONSE send error: {e}")

    def send_store(self, sock: socket.socket, addr: tuple,
                   key: str, value: str, ttl: int = 3600):
        msg = {
            "type": DHT_STORE,
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "key": key,
            "value": value,
            "ttl": ttl,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT-RPC] STORE send error: {e}")

    def send_store_ack(self, sock: socket.socket, addr: tuple, key: str):
        msg = {
            "type": "STORE_ACK",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "key": key,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT-RPC] STORE_ACK send error: {e}")

    def send_get(self, sock: socket.socket, addr: tuple, key: str):
        msg = {
            "type": DHT_GET,
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "key": key,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT-RPC] GET send error: {e}")

    def send_get_response(self, sock: socket.socket, addr: tuple,
                          key: str, value: str):
        msg = {
            "type": "GET_RESPONSE",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "key": key,
            "value": value,
        }
        try:
            data = json.dumps(self._sign(msg)).encode()
            sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT-RPC] GET_RESPONSE send error: {e}")

    # ─── Pending 查询管理 ────────────────────────────────────

    def _notify_find_node_result(self, target_id: str, nodes: list):
        """被 node.py 调用，将 FIND_NODE_RESPONSE 的结果存入 pending。"""
        with self._pending_lock:
            self._pending_find[target_id] = nodes

    def wait_find_node(self, target_id: str, timeout: float = 3.0) -> list:
        """阻塞等待 FIND_NODE 的结果（最多 timeout 秒）。"""
        import time as _time
        deadline = _time.time() + timeout
        while _time.time() < deadline:
            with self._pending_lock:
                if target_id in self._pending_find:
                    return self._pending_find.pop(target_id)
            _time.sleep(0.05)
        return []

    # ─── 入站分发（供 node.py dispatch 使用） ────────────────

    def dispatch(self, data: bytes, addr: tuple) -> dict | None:
        """解析并分发入站 DHT 消息。返回响应字典或 None。"""
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            return None

        # 验证签名
        sig = msg.pop("signature", None)
        signer_pubkey_b64 = msg.pop("signer_pubkey", None)
        if not sig or not signer_pubkey_b64:
            return None

        try:
            signable = json.dumps(msg, sort_keys=True).encode("utf-8")
            pubkey_obj = load_ed25519_public(signer_pubkey_b64)
            if not verify_signature(pubkey_obj, signable, sig):
                return None
        except Exception:
            return None

        # 恢复签名信息
        msg["signature"] = sig
        msg["signer_pubkey"] = signer_pubkey_b64

        msg_type = msg.get("type")
        sender_id = msg.get("sender_id", "")

        # 更新路由表（非隐藏模式 或 白名单内）
        if not self.node.hidden_mode or sender_id in self.node.whitelist:
            self.node.routing_table.add_node({
                "node_id": sender_id,
                "host": msg.get("sender_host", addr[0]),
                "port": msg.get("sender_port", addr[1]),
                "last_seen": time.time(),
                "ed25519_pubkey": signer_pubkey_b64,
            })

        if msg_type == DHT_PING:
            return self._dispatch_pong(msg)
        elif msg_type == "FIND_NODE":
            return self._dispatch_find_node(msg)
        elif msg_type == "FIND_NODE_RESPONSE":
            self._notify_find_node_result(msg.get("target_id", ""), msg.get("nodes", []))
            return None  # 响应不需要回复
        elif msg_type == DHT_STORE:
            return self._dispatch_store(msg)
        elif msg_type == "STORE_ACK":
            return None  # 确认无需回复
        elif msg_type == DHT_GET:
            return self._dispatch_get(msg)

        return None

    # ─── 内部分发方法 ────────────────────────────────────────

    def _dispatch_pong(self, msg: dict) -> dict:
        return {
            "type": "DHT_PONG",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "timestamp": int(time.time()),
            "nonce": msg.get("nonce", ""),
        }

    def _dispatch_find_node(self, msg: dict) -> dict:
        if self.node.hidden_mode and msg.get("sender_id") not in self.node.whitelist:
            return None
        target = msg.get("target_id", "")
        closest = self.node.routing_table.get_closest(target)
        return {
            "type": "FIND_NODE_RESPONSE",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "target_id": target,
            "nodes": closest,
            "timestamp": int(time.time()),
        }

    def _dispatch_store(self, msg: dict) -> dict:
        if self.node.hidden_mode and msg.get("sender_id") not in self.node.whitelist:
            return None
        key = msg.get("key", "")
        value = msg.get("value", "")
        ttl = msg.get("ttl", 3600)
        with self.node._store_lock:
            self.node._store[key] = {
                "value": value,
                "expires": time.time() + ttl,
                "publisher": msg.get("signer_pubkey", ""),
            }
        return {
            "type": "STORE_ACK",
            "sender_id": self.node.node_id,
            "sender_host": self.node.host,
            "sender_port": self.node.dht_port,
            "key": key,
        }

    def _dispatch_get(self, msg: dict) -> dict | None:
        if self.node.hidden_mode and msg.get("sender_id") not in self.node.whitelist:
            return None
        key = msg.get("key", "")
        with self.node._store_lock:
            entry = self.node._store.get(key)
            if entry and entry["expires"] > time.time():
                return {
                    "type": "GET_RESPONSE",
                    "sender_id": self.node.node_id,
                    "sender_host": self.node.host,
                    "sender_port": self.node.dht_port,
                    "key": key,
                    "value": entry["value"],
                }
        return None
