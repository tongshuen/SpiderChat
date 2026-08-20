"""
Spider — P2P 对端节点

当 Spider 客户端启用直连时，它同时充当迷你服务器，
提供与完整服务器相同的服务：

- 用户注册/认证（针对仅 P2P 用户）
- 已连接对端之间的消息中继
- 群聊托管
- 文件传输中继
- DHT 参与（轻量 Kademlia）
- 跨节点消息路由

本模块提供运行在客户端内部的服务端逻辑。
它镜像完整服务器的 ChatServer，但是轻量且点对点的。
"""

import socket
import threading
import json
import time
import base64
import os
import sys
from collections import defaultdict
from typing import Optional, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.protocol import *
from shared.crypto_utils import (
    TransportEncryptor, generate_x25519_keypair, generate_ed25519_keypair,
    sign_data, verify_signature, load_ed25519_public, load_x25519_public,
    b64_encode, b64_decode, node_id_from_pubkey, ecdh_shared_secret,
    hkdf_derive, aesgcm_encrypt, aesgcm_decrypt
)


class P2PPeer:
    """表示已连接的对端（服务器端视角）。"""

    def __init__(self, sock: socket.socket, addr: tuple):
        self.sock = sock
        self.addr = addr
        self.node_id: str = ""
        self.uuid: str = ""
        self.ed25519_pub: str = ""
        self.x25519_pub: str = ""
        self.transport_pub: str = ""
        self.authenticated: bool = False
        self.transport: Optional[TransportEncryptor] = None
        self.connect_type: str = "unknown"
        self.last_seen: float = time.time()
        self.send_lock = threading.Lock()


class P2PRelay:
    """P2P 对端之间的轻量级消息中继。"""

    def __init__(self, max_queue: int = 100):
        self._queues: Dict[str, list] = defaultdict(list)
        self._max_queue = max_queue
        self._lock = threading.Lock()

    def queue_message(self, to_uuid: str, msg: dict) -> bool:
        with self._lock:
            if len(self._queues.get(to_uuid, [])) >= self._max_queue:
                return False
            self._queues[to_uuid].append(msg)
            return True

    def get_messages(self, uuid: str) -> list:
        with self._lock:
            msgs = self._queues.pop(uuid, [])
            return msgs

    def clear(self, uuid: str):
        with self._lock:
            self._queues.pop(uuid, None)

    def count_pending(self, uuid: str) -> int:
        with self._lock:
            return len(self._queues.get(uuid, []))


class P2PNode:
    """
    同时充当客户端和服务端的 P2P 节点。

    提供：
    - 入站 TCP 连接处理（迷你服务端）
    - 出站对端连接（客户端）
    - 全包传输加密
    - 已连接对端之间的消息中继
    - 轻量级 DHT 用于对端发现
    - 群聊托管
    - 文件传输支持
    """

    def __init__(self, identity: dict, config: dict):
        """
        参数：
            identity: {uuid, ed25519_priv/pub, x25519_priv/pub}
            config: {port, max_peers, onion_enabled, obfuscation_mode, ...}
        """
        self.identity = identity
        self.config = config
        self.uuid = identity.get("uuid", "")
        self.ed25519_priv = identity.get("ed25519_priv", "")
        self.ed25519_pub = identity.get("ed25519_pub", "")
        self.x25519_priv = identity.get("x25519_priv", "")
        self.x25519_pub = identity.get("x25519_pub", "")
        self.node_id = node_id_from_pubkey(self.ed25519_pub)

        self.port = config.get("port", DEFAULT_DIRECT_CONNECT_PORT)
        self.max_peers = config.get("max_peers", MAX_DIRECT_CONNECTIONS)
        self.host = config.get("host", "0.0.0.0")

        self.peers: Dict[str, P2PPeer] = {}
        self._peers_lock = threading.Lock()

        self.outbound: Dict[str, P2PPeer] = {}
        self._outbound_lock = threading.Lock()

        self.relay = P2PRelay()

        self.groups: Dict[str, dict] = {}
        self._groups_lock = threading.Lock()

        self.known_nodes: Dict[str, dict] = {}
        self._known_lock = threading.Lock()

        self._transports: Dict[str, TransportEncryptor] = {}


        self._server_sock: Optional[socket.socket] = None
        self._running = False

        self.on_message: Optional[callable] = None
        self.on_peer_connected: Optional[callable] = None
        self.on_peer_disconnected: Optional[callable] = None

        self.stats = {
            "messages_relayed": 0,
            "peers_connected": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "start_time": time.time(),
        }


    def start(self):
        """启动 P2P 节点（开始监听）。"""
        self._running = True
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(self.max_peers)
            self._server_sock.settimeout(1.0)
            threading.Thread(target=self._accept_loop, daemon=True).start()
            print(f"[P2P] Node started — NodeID: {self.node_id[:16]}... port={self.port}")
        except Exception as e:
            print(f"[P2P] Start failed: {e}")

    def stop(self):
        """停止 P2P 节点。"""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except:
                pass

        with self._peers_lock:
            for peer in list(self.peers.values()):
                self._close_peer(peer)
        with self._outbound_lock:
            for peer in list(self.outbound.values()):
                self._close_peer(peer)
        print("[P2P] Node stopped")


    def _accept_loop(self):
        while self._running and self._server_sock:
            try:
                sock, addr = self._server_sock.accept()
                threading.Thread(
                    target=self._handle_incoming, args=(sock, addr), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_incoming(self, sock: socket.socket, addr: tuple):
        """处理入站对端连接（服务器端）。"""
        peer = P2PPeer(sock, addr)
        try:
            transport = TransportEncryptor(is_initiator=False)
            if not self._do_handshake(sock, transport, peer):
                sock.close()
                return

            peer.transport = transport


            data = self._recv_enc(sock, transport)
            if not data:
                sock.close()
                return
            msg = json.loads(data.decode("utf-8"))

            if msg.get("type") != DC_HELLO:
                sock.close()
                return


            verify_data = {k: v for k, v in msg.items() if k != "signature"}
            sig = msg.get("signature", "")
            if not verify_signature(
                load_ed25519_public(msg.get("ed25519_pub", "")),
                json.dumps(verify_data, sort_keys=True).encode(), sig
            ):
                sock.close()
                return


            peer.node_id = msg.get("node_id", "")
            peer.ed25519_pub = msg.get("ed25519_pub", "")
            peer.x25519_pub = msg.get("x25519_pub", "")
            peer.uuid = msg.get("uuid", "")
            peer.connect_type = msg.get("connect_type", "unknown")
            peer.authenticated = True

            with self._peers_lock:
                self.peers[peer.node_id] = peer
            self.stats["peers_connected"] += 1


            self._add_known_node(peer.node_id, peer.ed25519_pub, addr)


            hello = {
                "type": DC_HELLO,
                "node_id": self.node_id,
                "ed25519_pub": self.ed25519_pub,
                "x25519_pub": self.x25519_pub,
                "uuid": self.uuid,
                "transport_pub": transport.public_key_b64,
                "connect_type": "p2p",
                "software": SOFTWARE_NAME,
                "version": SOFTWARE_VERSION,
            }
            sig = sign_data(load_ed25519_private(self.ed25519_priv),
                           json.dumps(hello, sort_keys=True).encode())
            hello["signature"] = sig
            self._send_enc(sock, transport, json.dumps(hello).encode())

            if self.on_peer_connected:
                self.on_peer_connected(peer)


            self._peer_message_loop(sock, transport, peer)

        except Exception as e:
            print(f"[P2P] Incoming error from {addr}: {e}")
        finally:
            self._remove_peer(peer)


    def connect_to(self, host: str, port: int, peer_pubkey: str = "",
                   connect_type: str = "lan") -> bool:
        """作为客户端连接到对端。"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(DIRECT_CONNECT_TIMEOUT)
            sock.connect((host, port))

            transport = TransportEncryptor(is_initiator=True)
            if not self._do_handshake(sock, transport, None, is_initiator=True):
                sock.close()
                return False


            hello = {
                "type": DC_HELLO,
                "node_id": self.node_id,
                "ed25519_pub": self.ed25519_pub,
                "x25519_pub": self.x25519_pub,
                "uuid": self.uuid,
                "transport_pub": transport.public_key_b64,
                "connect_type": connect_type,
                "software": SOFTWARE_NAME,
                "version": SOFTWARE_VERSION,
            }
            sig = sign_data(load_ed25519_private(self.ed25519_priv),
                           json.dumps(hello, sort_keys=True).encode())
            hello["signature"] = sig
            self._send_enc(sock, transport, json.dumps(hello).encode())


            data = self._recv_enc(sock, transport)
            if not data:
                sock.close()
                return False
            msg = json.loads(data.decode("utf-8"))

            if msg.get("type") != DC_HELLO:
                sock.close()
                return False


            peer_id = msg.get("node_id", "")
            verify_data = {k: v for k, v in msg.items() if k != "signature"}
            if not verify_signature(
                load_ed25519_public(msg.get("ed25519_pub", "")),
                json.dumps(verify_data, sort_keys=True).encode(),
                msg.get("signature", "")
            ):
                sock.close()
                return False


            peer = P2PPeer(sock, (host, port))
            peer.node_id = peer_id
            peer.ed25519_pub = msg.get("ed25519_pub", "")
            peer.x25519_pub = msg.get("x25519_pub", "")
            peer.uuid = msg.get("uuid", "")
            peer.connect_type = connect_type
            peer.authenticated = True
            peer.transport = transport

            with self._outbound_lock:
                self.outbound[peer_id] = peer
            self._transports[peer_id] = transport
            self.stats["peers_connected"] += 1

            self._add_known_node(peer_id, peer.ed25519_pub, (host, port))

            if self.on_peer_connected:
                self.on_peer_connected(peer)


            threading.Thread(
                target=self._peer_message_loop,
                args=(sock, transport, peer), daemon=True
            ).start()

            print(f"[P2P] Connected to {peer_id[:16]}... ({host}:{port})")
            return True

        except Exception as e:
            print(f"[P2P] Connect to {host}:{port} failed: {e}")
            return False


    def _do_handshake(
        self, sock: socket.socket, transport: TransportEncryptor,
        peer: Optional[P2PPeer], is_initiator: bool = False
    ) -> bool:
        """执行传输层 ECDH 密钥交换。"""
        try:
            if is_initiator:

                req = json.dumps({
                    "type": ENC_HANDSHAKE,
                    "transport_pub": transport.public_key_b64,
                }).encode() + b"\n"
                sock.sendall(req)


                buf = b""
                while b"\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return False
                    buf += chunk
                line, _ = buf.split(b"\n", 1)
                resp = json.loads(line.decode("utf-8"))
                peer_tp = resp.get("transport_pub", "")
                transport.set_peer_public_key(peer_tp)
                return True
            else:

                buf = b""
                while b"\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return False
                    buf += chunk
                line, buf = buf.split(b"\n", 1)
                req = json.loads(line.decode("utf-8"))
                peer_tp = req.get("transport_pub", "")


                resp = json.dumps({
                    "type": ENC_HANDSHAKE_OK,
                    "transport_pub": transport.public_key_b64,
                }).encode() + b"\n"
                sock.sendall(resp)

                transport.set_peer_public_key(peer_tp)
                return True
        except Exception as e:
            print(f"[P2P] Handshake error: {e}")
            return False


    def _send_enc(self, sock: socket.socket, transport: TransportEncryptor, data: bytes):
        encrypted = transport.encrypt_packet(data)
        sock.sendall(encrypted)
        self.stats["bytes_sent"] += len(encrypted)

    def _recv_enc(self, sock: socket.socket, transport: TransportEncryptor) -> Optional[bytes]:
        """接收一个加密数据包。"""

        header = b""
        while len(header) < 17:
            chunk = sock.recv(17 - len(header))
            if not chunk:
                return None
            header += chunk



        remaining = b""
        sock.settimeout(15)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                remaining += chunk
                full = header + remaining
                result = transport.decrypt_packet(full)
                if result is not None:
                    self.stats["bytes_recv"] += len(full)
                    return result
        except socket.timeout:
            pass

        full = header + remaining
        return transport.decrypt_packet(full)

    def _peer_message_loop(self, sock: socket.socket, transport: TransportEncryptor, peer: P2PPeer):
        """从已连接对端读取消息。"""
        while self._running:
            try:
                data = self._recv_enc(sock, transport)
                if not data:
                    break
                msg = json.loads(data.decode("utf-8"))
                peer.last_seen = time.time()
                self._handle_peer_message(peer, msg)
            except Exception as e:
                if self._running:
                    print(f"[P2P] Peer {peer.node_id[:16]}... error: {e}")
                break
        self._remove_peer(peer)


    def _handle_peer_message(self, peer: P2PPeer, msg: dict):
        """处理来自对端的消息。"""
        msg_type = msg.get("type")

        if msg_type == DC_SEND_MSG:
            to_uuid = msg.get("to_uuid", "")

            with self._peers_lock:
                recipient = self._find_peer_by_uuid(to_uuid)
            if recipient and recipient.transport:
                relay = {
                    "type": DC_RECV_MSG,
                    "from_uuid": msg.get("from_uuid", ""),
                    "to_uuid": to_uuid,
                    "encrypted_payload": msg.get("encrypted_payload", {}),
                    "timestamp": msg.get("timestamp", int(time.time())),
                }
                self._send_enc(recipient.sock, recipient.transport,
                               json.dumps(relay).encode())
                self.stats["messages_relayed"] += 1
            else:

                self.relay.queue_message(to_uuid, msg)

        elif msg_type == DC_RECV_MSG:
            if self.on_message:
                self.on_message(msg.get("from_uuid", ""), msg)

        elif msg_type == DC_FILE_CHUNK:
            to_uuid = msg.get("to_uuid", "")
            with self._peers_lock:
                recipient = self._find_peer_by_uuid(to_uuid)
            if recipient and recipient.transport:
                self._send_enc(recipient.sock, recipient.transport,
                               json.dumps(msg).encode())

        elif msg_type == DC_PING:
            pong = {"type": DC_PONG, "timestamp": int(time.time())}
            self._send_enc(peer.sock, peer.transport, json.dumps(pong).encode())

        elif msg_type == DC_DISCONNECT:
            self._remove_peer(peer)

        elif msg_type == "P2P_QUERY_NODE":
            target_id = msg.get("target_node_id", "")
            known = self._get_known_node(target_id)
            resp = {
                "type": "P2P_NODE_INFO",
                "target_node_id": target_id,
                "found": known is not None,
                "node_info": known or {},
            }
            self._send_enc(peer.sock, peer.transport, json.dumps(resp).encode())


    def send_message(self, to_node_id: str, to_uuid: str, encrypted_payload: dict, signature: str) -> bool:
        """向对端发送加密消息。"""
        peer = self._get_peer(to_node_id)
        if not peer or not peer.transport:
            return False


        if peer.transport.should_rotate(self.config.get("key_rotation_sec", 3600)):
            peer.transport.rotate_key()

        msg = {
            "type": DC_SEND_MSG,
            "from_uuid": self.uuid,
            "to_uuid": to_uuid,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
            "timestamp": int(time.time()),
        }
        try:
            self._send_enc(peer.sock, peer.transport, json.dumps(msg).encode())
            return True
        except Exception as e:
            print(f"[P2P] Send to {to_node_id[:16]}... failed: {e}")
            return False

    def send_raw(self, to_node_id: str, msg: dict) -> bool:
        """向对端发送原始消息字典。"""
        peer = self._get_peer(to_node_id)
        if not peer or not peer.transport:
            return False
        try:
            self._send_enc(peer.sock, peer.transport, json.dumps(msg).encode())
            return True
        except:
            return False


    def _get_peer(self, node_id: str) -> Optional[P2PPeer]:
        with self._peers_lock:
            if node_id in self.peers:
                return self.peers[node_id]
        with self._outbound_lock:
            return self.outbound.get(node_id)

    def _find_peer_by_uuid(self, uuid: str) -> Optional[P2PPeer]:
        with self._peers_lock:
            for p in self.peers.values():
                if p.uuid == uuid:
                    return p
        with self._outbound_lock:
            for p in self.outbound.values():
                if p.uuid == uuid:
                    return p
        return None

    def _remove_peer(self, peer: P2PPeer):
        with self._peers_lock:
            if peer.node_id in self.peers:
                del self.peers[peer.node_id]
        with self._outbound_lock:
            if peer.node_id in self.outbound:
                del self.outbound[peer.node_id]
        self._transports.pop(peer.node_id, None)
        try:
            peer.sock.close()
        except:
            pass
        if self.on_peer_disconnected:
            self.on_peer_disconnected(peer.node_id)
        print(f"[P2P] Peer disconnected: {peer.node_id[:16]}...")

    def _close_peer(self, peer: P2PPeer):
        try:
            peer.sock.close()
        except:
            pass

    def disconnect_peer(self, node_id: str):
        peer = self._get_peer(node_id)
        if peer:
            self._remove_peer(peer)


    def _add_known_node(self, node_id: str, pubkey: str, addr: tuple):
        with self._known_lock:
            self.known_nodes[node_id] = {
                "pubkey": pubkey,
                "address": f"{addr[0]}:{addr[1]}",
                "last_seen": time.time(),
            }

    def _get_known_node(self, node_id: str) -> Optional[dict]:
        with self._known_lock:
            return self.known_nodes.get(node_id)

    def get_known_nodes(self) -> list:
        with self._known_lock:
            return [
                {"node_id": nid, **info}
                for nid, info in self.known_nodes.items()
            ]

    def find_node(self, target_id: str) -> Optional[dict]:
        """按 ID 查找节点。先查本地，再问对端。"""
        known = self._get_known_node(target_id)
        if known:
            return known

        with self._peers_lock:
            peers_copy = list(self.peers.values())
        for peer in peers_copy:
            if peer.transport and peer.authenticated:
                query = {
                    "type": "P2P_QUERY_NODE",
                    "target_node_id": target_id,
                }
                self._send_enc(peer.sock, peer.transport, json.dumps(query).encode())
        return None


    def create_group(self, group_name: str, members: list) -> str:
        """在此 P2P 节点上创建群组。"""
        group_id = b64_encode(os.urandom(16))[:22]
        with self._groups_lock:
            self.groups[group_id] = {
                "name": group_name,
                "members": list(members),
                "host": self.node_id,
                "created": int(time.time()),
            }
        return group_id

    def add_group_member(self, group_id: str, uuid: str) -> bool:
        with self._groups_lock:
            if group_id in self.groups:
                if uuid not in self.groups[group_id]["members"]:
                    self.groups[group_id]["members"].append(uuid)
                return True
        return False

    def relay_group_message(self, group_id: str, from_uuid: str, encrypted_payload: dict) -> int:
        """将群消息中继给所有成员。返回投递数量。"""
        delivered = 0
        with self._groups_lock:
            group = self.groups.get(group_id)
            if not group:
                return 0
            members = list(group["members"])

        for uuid in members:
            if uuid == from_uuid:
                continue
            peer = self._find_peer_by_uuid(uuid)
            if peer and peer.transport:
                msg = {
                    "type": "P2P_GROUP_MSG",
                    "group_id": group_id,
                    "from_uuid": from_uuid,
                    "encrypted_payload": encrypted_payload,
                    "timestamp": int(time.time()),
                }
                if self._send_enc(peer.sock, peer.transport, json.dumps(msg).encode()):
                    delivered += 1
        return delivered


    def get_stats(self) -> dict:
        with self._peers_lock, self._outbound_lock:
            total_peers = len(self.peers) + len(self.outbound)
        return {
            "node_id": self.node_id[:16],
            "peers": total_peers,
            "max_peers": self.max_peers,
            "messages_relayed": self.stats["messages_relayed"],
            "bytes_sent": self.stats["bytes_sent"],
            "bytes_recv": self.stats["bytes_recv"],
            "uptime": int(time.time() - self.stats["start_time"]),
            "known_nodes": len(self.known_nodes),
            "groups_hosted": len(self.groups),
        }


    def maintenance_loop(self):
        """周期性清理。"""
        while self._running:
            time.sleep(60)
            try:
                cutoff = time.time() - 600
                dead = []
                with self._peers_lock:
                    for nid, peer in list(self.peers.items()):
                        if peer.last_seen < cutoff:
                            dead.append(peer)
                for peer in dead:
                    self._remove_peer(peer)
                if dead:
                    print(f"[P2P] Cleaned {len(dead)} dead peer(s)")
            except Exception as e:
                print(f"[P2P] Maintenance error: {e}")
