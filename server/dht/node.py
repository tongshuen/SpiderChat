"""
DHT 节点 — 核心 Kademlia 节点实现。
处理 PING/PONG、FIND_NODE、STORE、GET 操作。

SECURITY FIX (v2):
- All DHT messages are signed with Ed25519
- Each node has a DHT identity key pair (stored in keyring)
- Messages without valid signatures are dropped
- Replay protection with timestamp window
- Sender identity verified against routing table
"""

import socket
import json
import threading
import time
import hashlib
import struct
from collections import OrderedDict
from .routing import RoutingTable
from .rpc import DHTRPC
from shared.protocol import *
from shared.crypto_utils import (
    sign_data, verify_signature,
    load_ed25519_private, load_ed25519_public,
    b64_encode, b64_decode,
)
from server.keyring_store.credentials import (
    get_server_keys, get_node_id,
)



DHT_REPLAY_WINDOW = 60
MAX_REPLAY_CACHE = 5000
DHT_MAX_PACKET = 1400
class DHTNode:
    """带签名消息的 Kademlia DHT 节点。"""

    def __init__(self, node_id: str, host: str, dht_port: int,
                 config: dict, hidden: bool = False, whitelist: list = None):
        self.node_id = node_id
        self.host = host
        self.dht_port = dht_port
        self.config = config
        self.hidden_mode = hidden
        self.whitelist = set(whitelist or [])

        self.rpc = DHTRPC(self)

        k = config.get("dht", {}).get("k_bucket_size", 20)
        alpha = config.get("dht", {}).get("alpha", 3)
        self.routing_table = RoutingTable(node_id, k=k, alpha=alpha)

        keys = get_server_keys()
        self._dht_priv_b64 = keys["server_ed25519_priv"]
        self._dht_pub_b64 = keys["server_ed25519_pub"]

        self._sock = None
        self._running = False
        self._thread = None

        self._store: dict[str, dict] = {}
        self._store_lock = threading.Lock()


        self._seen_messages: OrderedDict = OrderedDict()
        self._seen_lock = threading.Lock()

        self._node_info: dict = {}
        self._node_lock = threading.Lock()


    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256 * 1024)
        self._sock.bind(("", self.dht_port))
        self._running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        print(f"[DHT] Node {self.node_id[:16]}... listening on UDP:{self.dht_port} (signed messages)")

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except:
                pass


    def _check_replay(self, sender_id: str, timestamp: int, nonce: str) -> bool:
        """如果是新消息（非重放）则返回 True。"""
        now = time.time()

        if abs(now - timestamp) > DHT_REPLAY_WINDOW:
            return False

        key = f"{sender_id}:{timestamp}:{nonce}"
        with self._seen_lock:
            if key in self._seen_messages:
                return False
            self._seen_messages[key] = now

            cutoff = now - DHT_REPLAY_WINDOW * 2
            while self._seen_messages and next(iter(self._seen_messages.values())) < cutoff:
                self._seen_messages.popitem(last=False)
            while len(self._seen_messages) > MAX_REPLAY_CACHE:
                self._seen_messages.popitem(last=False)
        return True


    def _sign_message(self, msg: dict) -> dict:
        """向 DHT 消息添加签名。"""

        if "timestamp" not in msg:
            msg["timestamp"] = int(time.time())

        if "nonce" not in msg:
            msg["nonce"] = b64_encode(os.urandom(8))

        signable = json.dumps(msg, sort_keys=True).encode("utf-8")
        priv = load_ed25519_private(self._dht_priv_b64)
        sig = sign_data(priv, signable)
        msg["signature"] = sig
        msg["signer_pubkey"] = self._dht_pub_b64
        return msg

    def _verify_message(self, msg: dict, addr) -> bool:
        """验证入站 DHT 消息的签名 + 重放保护。"""
        sig = msg.pop("signature", None)
        signer_pubkey_b64 = msg.pop("signer_pubkey", None)

        if not sig or not signer_pubkey_b64:
            print(f"[DHT] 🚫 Message from {addr} has no signature — DROPPED")
            return False


        sender_id = msg.get("sender_id", "")
        ts = msg.get("timestamp", 0)
        nonce = msg.get("nonce", "")
        if not self._check_replay(sender_id, ts, nonce):
            print(f"[DHT] 🚫 Replay detected from {sender_id[:16]}... — DROPPED")
            return False


        try:
            signable = json.dumps(msg, sort_keys=True).encode("utf-8")
            pubkey_obj = load_ed25519_public(signer_pubkey_b64)
            if not verify_signature(pubkey_obj, signable, sig):
                print(f"[DHT] 🚫 Bad signature from {addr} — DROPPED")
                return False
        except Exception as e:
            print(f"[DHT] 🚫 Key parse error from {addr}: {e} — DROPPED")
            return False

        msg["signature"] = sig
        msg["signer_pubkey"] = signer_pubkey_b64
        return True


    def _listen_loop(self):
        self._sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = self._sock.recvfrom(DHT_MAX_PACKET)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[DHT] Error: {e}")

    def _handle_packet(self, data: bytes, addr):
        try:
            msg = json.loads(data.decode("utf-8"))
        except:
            return

        if not self._verify_message(msg, addr):
            return

        msg_type = msg.get("type")
        sender_id = msg.get("sender_id", "")


        if sender_id and not self.hidden_mode:
            self.routing_table.add_node({
                "node_id": sender_id,
                "host": msg.get("sender_host", addr[0]),
                "port": msg.get("sender_port", addr[1]),
                "last_seen": time.time(),
                "ed25519_pubkey": msg.get("signer_pubkey", ""),
            })


        if msg_type == DHT_PING:
            self._handle_ping(msg, addr)
        elif msg_type == "DHT_PONG":
            self._handle_pong(msg)
        elif msg_type == "FIND_NODE":
            self._handle_find_node(msg, addr)
        elif msg_type == "FIND_NODE_RESPONSE":
            self._handle_find_node_response(msg)
        elif msg_type == DHT_STORE:
            self._handle_store(msg)
        elif msg_type == "STORE_ACK":
            self._handle_store_ack(msg)
        elif msg_type == DHT_GET:
            self._handle_get(msg, addr)


    def _handle_ping(self, msg: dict, addr):
        response = {
            "type": "DHT_PONG",
            "sender_id": self.node_id,
            "sender_host": self.host,
            "sender_port": self.dht_port,
            "timestamp": int(time.time()),
            "nonce": msg.get("nonce", ""),
        }
        signed = self._sign_message(response)
        self._send_to(addr, signed)

    def _handle_pong(self, msg: dict):
        """处理 DHT_PONG：更新路由表并记录 RTT。"""
        sender_id = msg.get("sender_id", "")
        if not sender_id:
            return
        # 计算 RTT（如果消息中带了原始时间戳）
        orig_ts = msg.get("timestamp", 0)
        rtt = time.time() - orig_ts if orig_ts else 0

        self.routing_table.add_node({
            "node_id": sender_id,
            "host": msg.get("sender_host", ""),
            "port": msg.get("sender_port", self.dht_port),
            "last_seen": time.time(),
            "ed25519_pubkey": msg.get("signer_pubkey", ""),
            "rtt": round(rtt, 3),
        })
    def _handle_find_node(self, msg: dict, addr):
        if self.hidden_mode and msg.get("sender_id") not in self.whitelist:
            return  # 静默
        target = msg.get("target_id", "")
        closest = self.routing_table.get_closest(target, count=self.config.get("dht", {}).get("k_bucket_size", 20))

        response = {
            "type": "FIND_NODE_RESPONSE",
            "sender_id": self.node_id,
            "target_id": target,
            "nodes": closest,
            "timestamp": int(time.time()),
        }
        signed = self._sign_message(response)
        self._send_to(addr, signed)

    def _handle_find_node_response(self, msg: dict):
        """处理 FIND_NODE_RESPONSE：更新路由表并唤醒 pending 查询。"""
        sender_id = msg.get("sender_id", "")
        target_id = msg.get("target_id", "")
        nodes = msg.get("nodes", [])

        # 将响应者自身加入路由表
        if sender_id:
            self.routing_table.add_node({
                "node_id": sender_id,
                "host": msg.get("sender_host", ""),
                "port": msg.get("sender_port", self.dht_port),
                "last_seen": time.time(),
                "ed25519_pubkey": msg.get("signer_pubkey", ""),
            })

        # 将返回的每个节点也加入路由表
        for n in nodes:
            if isinstance(n, dict) and n.get("node_id"):
                self.routing_table.add_node({
                    "node_id": n["node_id"],
                    "host": n.get("host", ""),
                    "port": n.get("port", self.dht_port),
                    "last_seen": time.time(),
                    "ed25519_pubkey": n.get("ed25519_pubkey", ""),
                })

        # 唤醒该 target 的 pending 查询
        if target_id:
            self.rpc._notify_find_node_result(target_id, nodes)

    def _handle_store(self, msg: dict):
        if self.hidden_mode and msg.get("sender_id") not in self.whitelist:
            return
        key = msg.get("key", "")
        value = msg.get("value", "")
        ttl = msg.get("ttl", 3600)
        publisher = msg.get("signer_pubkey", "")

        with self._store_lock:
            self._store[key] = {
                "value": value,
                "expires": time.time() + ttl,
                "publisher": publisher,
            }

        response = {
            "type": "STORE_ACK",
            "sender_id": self.node_id,
            "key": key,
            "timestamp": int(time.time()),
        }

    def _handle_store_ack(self, msg: dict):
        """处理 STORE_ACK：记录确认并将发送者加入路由表。"""
        sender_id = msg.get("sender_id", "")
        key = msg.get("key", "")

        if sender_id:
            self.routing_table.add_node({
                "node_id": sender_id,
                "host": msg.get("sender_host", ""),
                "port": msg.get("sender_port", self.dht_port),
                "last_seen": time.time(),
                "ed25519_pubkey": msg.get("signer_pubkey", ""),
            })

        # 记录该 key 已被哪些节点确认存储
        if key:
            with self._store_lock:
                ack_entry = self._store.get(f"_acks:{key}", {"value": "[]"})
                try:
                    ack_list = json.loads(ack_entry["value"])
                except:
                    ack_list = []
                if sender_id not in ack_list:
                    ack_list.append(sender_id)
                self._store[f"_acks:{key}"] = {
                    "value": json.dumps(ack_list),
                    "expires": time.time() + 3600,
                    "publisher": self._dht_pub_b64,
                }

    def _handle_get(self, msg: dict, addr):
        if self.hidden_mode and msg.get("sender_id") not in self.whitelist:
            return
        key = msg.get("key", "")
        with self._store_lock:
            entry = self._store.get(key)

        if entry and entry["expires"] > time.time():
            response = {
                "type": "GET_RESPONSE",
                "sender_id": self.node_id,
                "key": key,
                "value": entry["value"],
                "timestamp": int(time.time()),
            }
            signed = self._sign_message(response)
            self._send_to(addr, signed)


    def _send_to(self, addr, msg: dict):
        try:
            data = json.dumps(msg).encode("utf-8")
            if len(data) > DHT_MAX_PACKET:
                print(f"[DHT] ⚠️ Packet too large ({len(data)} bytes) — truncating")
                return
            self._sock.sendto(data, addr)
        except Exception as e:
            print(f"[DHT] Send error: {e}")


    def ping(self, host: str, port: int) -> bool:
        """Ping 一个节点。存活返回 True。"""
        msg = {
            "type": DHT_PING,
            "sender_id": self.node_id,
            "sender_host": self.host,
            "sender_port": self.dht_port,
            "timestamp": int(time.time()),
        }
        signed = self._sign_message(msg)
        try:
            self._sock.sendto(json.dumps(signed).encode(), (host, port))
            return True
        except:
            return False

    def find_node(self, target_id: str, via_host: str = None, via_port: int = None) -> list:
        """向 target_id 发送 FIND_NODE。"""
        msg = {
            "type": "FIND_NODE",
            "sender_id": self.node_id,
            "sender_host": self.host,
            "sender_port": self.dht_port,
            "target_id": target_id,
            "timestamp": int(time.time()),
        }
        signed = self._sign_message(msg)

        if via_host:
            self._sock.sendto(json.dumps(signed).encode(), (via_host, via_port))
        else:
            closest = self.routing_table.get_closest(target_id, count=self.config.get("dht", {}).get("alpha", 3))
            for n in closest:
                addr = (n.get("host", ""), n.get("port", self.dht_port))
                try:
                    self._sock.sendto(json.dumps(signed).encode(), addr)
                except:
                    pass

        return self.routing_table.get_closest(target_id)

    def store(self, key: str, value: str, ttl: int = 3600):
        """通过 STORE RPC（签名）存储键值对。"""
        msg = {
            "type": DHT_STORE,
            "sender_id": self.node_id,
            "sender_host": self.host,
            "sender_port": self.dht_port,
            "key": key,
            "value": value,
            "ttl": ttl,
            "timestamp": int(time.time()),
        }
        signed = self._sign_message(msg)


        with self._store_lock:
            self._store[key] = {
                "value": value,
                "expires": time.time() + ttl,
                "publisher": self._dht_pub_b64,
            }

        closest = self.routing_table.get_closest(key, count=self.config.get("dht", {}).get("k_bucket_size", 20))
        for n in closest:
            addr = (n.get("host", ""), n.get("port", self.dht_port))
            try:
                self._sock.sendto(json.dumps(signed).encode(), addr)
            except:
                pass

    def get(self, key: str) -> str | None:
        """从 DHT 存储中获取值。"""
        with self._store_lock:
            entry = self._store.get(key)
            if entry and entry["expires"] > time.time():
                return entry["value"]
        return None

    def bootstrap(self, bootstrap_nodes: list) -> int:
        """连接到引导节点并构建路由表。"""
        found = 0
        for node in bootstrap_nodes:
            host = node.get("host", "")
            port = node.get("port", self.dht_port)
            if not host:
                continue
            if self.ping(host, port):
                found += 1
                self.routing_table.add_node({
                    "node_id": node.get("node_id", ""),
                    "host": host,
                    "port": port,
                    "last_seen": time.time(),
                    "ed25519_pubkey": node.get("ed25519_pubkey", ""),
                })
                self.find_node(self.node_id, via_host=host, via_port=port)

        for _ in range(3):
            closest = self.routing_table.get_closest(self.node_id)
            for n in closest[:self.config.get("dht", {}).get("alpha", 3)]:
                self.find_node(self.node_id, via_host=n.get("host"), via_port=n.get("port"))

        return found


    def set_hidden(self, hidden: bool):
        self.hidden_mode = hidden
        print(f"[DHT] Hidden mode: {'ON' if hidden else 'OFF'}")

    def add_whitelist(self, node_id: str):
        self.whitelist.add(node_id)

    def remove_whitelist(self, node_id: str):
        self.whitelist.discard(node_id)

    def get_routing_info(self) -> dict:
        buckets_info = []
        for i, bucket in enumerate(self.routing_table.buckets):
            if len(bucket) > 0:
                buckets_info.append({
                    "index": i,
                    "count": len(bucket),
                    "nodes": [n["node_id"][:16] + "..." for n in bucket.get_all()],
                })
        return {
            "self_node_id": self.node_id,
            "hidden_mode": self.hidden_mode,
            "whitelist": list(self.whitelist),
            "total_nodes": self.routing_table.total_nodes(),
            "buckets": buckets_info,
            "dht_pubkey": self._dht_pub_b64[:16] + "...",
        }
