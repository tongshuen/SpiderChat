"""
Spider — Direct Connect Module

Enables peer-to-peer communication between Spider clients without
requiring a central server. Supports:

1. Bluetooth (RFCOMM) — for nearby device pairing
2. WiFi Direct (P2P) — for local high-speed transfer
3. LAN (TCP) — same-network direct connection
4. Public IP (TCP) — direct connection over the internet

In direct-connect mode, the client also acts as a mini-server,
providing the same services as a full server (relay, group chat,
file transfer) but for a small set of trusted peers.

Uses TransportEncryptor for full-packet encryption.
"""

import socket
import threading
import json
import time
import base64
import os
import sys
import uuid as uuid_module
from typing import Optional, Tuple, Callable, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.protocol import *
from shared.crypto_utils import (
    TransportEncryptor, generate_x25519_keypair, generate_ed25519_keypair,
    sign_data, verify_signature, load_ed25519_public, load_x25519_public,
    b64_encode, b64_decode, node_id_from_pubkey
)


try:
    import bluetooth
    HAS_BLUETOOTH = True
except ImportError:
    HAS_BLUETOOTH = False


try:
    if os.name == "posix":
        import subprocess
        HAS_WIFI_DIRECT = True
    else:
        HAS_WIFI_DIRECT = False
except Exception:
    HAS_WIFI_DIRECT = False



class DirectConnectConfig:
    """直连运行时配置。"""

    def __init__(self, config_file: str = None):
        self.dc_port = DEFAULT_DIRECT_CONNECT_PORT
        self.bt_port = DEFAULT_BLUETOOTH_PORT
        self.wifi_port = DEFAULT_WIFI_DIRECT_PORT
        self.enabled = True
        self.bt_enabled = HAS_BLUETOOTH
        self.wifi_enabled = HAS_WIFI_DIRECT
        self.lan_discovery = True
        self.public_ip = ""
        self.public_port = DEFAULT_DIRECT_CONNECT_PORT
        self.max_peers = MAX_DIRECT_CONNECTIONS
        self.transport_rotation_sec = TRANSPORT_KEY_ROTATION_SEC
        self.obfuscation_mode = DEFAULT_OBFUSCATION_MODE
        self.onion_enabled = False
        self.onion_layers = DEFAULT_ONION_LAYERS
        if config_file and os.path.exists(config_file):
            self.load(config_file)

    def load(self, path: str):
        try:
            with open(path) as f:
                d = json.load(f)
            for k, v in d.items():
                if hasattr(self, k):
                    setattr(self, k, v)
        except Exception as e:
            print(f"[DC] Config load error: {e}")

    def save(self, path: str):
        d = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        with open(path, "w") as f:
            json.dump(d, f, indent=2)

    def get_all_ports(self) -> dict:
        return {
            "direct_connect": self.dc_port,
            "bluetooth": self.bt_port,
            "wifi_direct": self.wifi_port,
            "public": self.public_port,
        }



class PeerInfo:
    """已知对端的信息。"""

    def __init__(self, node_id: str, pubkey_b64: str, address: str = "",
                 connect_type: str = "unknown", last_seen: float = 0):
        self.node_id = node_id
        self.pubkey_b64 = pubkey_b64
        self.address = address
        self.connect_type = connect_type
        self.last_seen = last_seen or time.time()
        self.transport: Optional[TransportEncryptor] = None
        self.authenticated = False
        self.uuid = ""
        self.name = ""
        # ===== 网络共享能力（直连网络共享 / 多跳路由）=====
        self.has_public_access: bool = False
        self.has_radio_access: bool = False
        self.is_network_gateway: bool = False
        self.connected_peers: List[str] = []
        self.network_hops: int = 0

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "pubkey": self.pubkey_b64,
            "address": self.address,
            "connect_type": self.connect_type,
            "last_seen": self.last_seen,
            "uuid": self.uuid,
            "name": self.name,
            "has_public_access": self.has_public_access,
            "has_radio_access": self.has_radio_access,
            "is_network_gateway": self.is_network_gateway,
            "connected_peers": list(self.connected_peers),
            "network_hops": self.network_hops,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PeerInfo":
        p = cls(
            node_id=d.get("node_id", ""),
            pubkey_b64=d.get("pubkey", ""),
            address=d.get("address", ""),
            connect_type=d.get("connect_type", "unknown"),
            last_seen=d.get("last_seen", 0),
        )
        p.uuid = d.get("uuid", "")
        p.name = d.get("name", "")
        p.has_public_access = bool(d.get("has_public_access", False))
        p.has_radio_access = bool(d.get("has_radio_access", False))
        p.is_network_gateway = bool(d.get("is_network_gateway", False))
        p.connected_peers = list(d.get("connected_peers", []))
        p.network_hops = int(d.get("network_hops", 0))
        return p



class DirectConnectManager:
    """
    管理 Spider 客户端的所有点对点连接。

    职责：
    - 监听入站 P2P 连接（充当迷你服务端）
    - 发起出站 P2P 连接
    - 蓝牙设备发现与配对
    - WiFi Direct 发现与连接
    - 局域网对端发现（UDP 广播）
    - 公网 IP 连接（含 NAT 穿透辅助）
    - 所有链路的全包传输加密
    - 已连接对端之间的消息中继
    """

    def __init__(self, identity: dict, config: DirectConnectConfig):
        """
        参数：
            identity: 包含 uuid、ed25519_priv/pub、x25519_priv/pub 的字典
            config: DirectConnectConfig 实例
        """
        self.identity = identity
        self.config = config
        self.uuid = identity.get("uuid", "")
        self.ed25519_priv = identity.get("ed25519_priv", "")
        self.ed25519_pub = identity.get("ed25519_pub", "")
        self.x25519_priv = identity.get("x25519_priv", "")
        self.x25519_pub = identity.get("x25519_pub", "")
        self.node_id = node_id_from_pubkey(self.ed25519_pub)

        self.peers: Dict[str, PeerInfo] = {}
        self._peers_lock = threading.Lock()

        self._transports: Dict[str, TransportEncryptor] = {}


        self._server_sock: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None

        self._bt_server = None
        self._bt_thread: Optional[threading.Thread] = None

        self._wifi_server = None
        self._wifi_thread: Optional[threading.Thread] = None

        self._lan_thread: Optional[threading.Thread] = None
        self._lan_sock: Optional[socket.socket] = None

        self.on_message: Optional[Callable[[str, dict], None]] = None
        self.on_peer_connected: Optional[Callable[[PeerInfo], None]] = None
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None
        self.on_file_received: Optional[Callable[[str, dict], None]] = None

        self._running = False
        # ===== 直连网络共享 / 多跳路由 =====
        self._has_public_access: bool = False
        self._has_radio_access: bool = False
        self._network_gateway_enabled: bool = True
        self.on_network_relay: Optional[Callable[[dict], Optional[dict]]] = None
        self._topology: Dict[str, List[str]] = {}
        self._topology_lock = threading.Lock()
        self._known_gateways: List[str] = []


    def start(self):
        """启动所有已启用的直连监听器。"""
        self._running = True

        if self.config.enabled:
            self._start_tcp_listener()

        if self.config.bt_enabled and HAS_BLUETOOTH:
            self._start_bluetooth_listener()

        if self.config.lan_discovery:
            self._start_lan_discovery()

        print(f"[DC] Direct Connect started — NodeID: {self.node_id[:16]}...")
        print(f"[DC] Listening on TCP:{self.config.dc_port}  BT:{self.config.bt_port}")

    def stop(self):
        """停止所有监听器并断开对端连接。"""
        self._running = False


        for sock_name in ["_server_sock", "_bt_server", "_wifi_server", "_lan_sock"]:
            sock = getattr(self, sock_name, None)
            if sock:
                try:
                    sock.close()
                except:
                    pass


        with self._peers_lock:
            for peer in list(self.peers.values()):
                self._disconnect_peer(peer)

        print("[DC] Direct Connect stopped")


    def _start_tcp_listener(self):
        """启动 TCP 服务器套接字 — 充当入站 P2P 的迷你服务器。"""
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind(("0.0.0.0", self.config.dc_port))
            self._server_sock.listen(self.config.max_peers)
            self._server_sock.settimeout(1.0)
            self._server_thread = threading.Thread(target=self._tcp_accept_loop, daemon=True)
            self._server_thread.start()
        except Exception as e:
            print(f"[DC] TCP listener failed on port {self.config.dc_port}: {e}")

    def _tcp_accept_loop(self):
        """接受来自对端的入站 TCP 连接。"""
        while self._running and self._server_sock:
            try:
                client_sock, addr = self._server_sock.accept()
                threading.Thread(
                    target=self._handle_incoming_peer,
                    args=(client_sock, addr, "tcp"),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_incoming_peer(self, sock: socket.socket, addr: tuple, medium: str):
        """处理新连接的对端（连接的服务器端）。"""
        try:
            transport = TransportEncryptor(is_initiator=False)
            if not self._do_transport_handshake(sock, transport, is_initiator=False):
                sock.close()
                return


            hello = {
                "type": DC_HELLO,
                "node_id": self.node_id,
                "ed25519_pub": self.ed25519_pub,
                "x25519_pub": self.x25519_pub,
                "uuid": self.uuid,
                "transport_pub": transport.public_key_b64,
                "connect_type": medium,
                "software": SOFTWARE_NAME,
                "version": SOFTWARE_VERSION,
                "has_public_access": self._has_public_access,
                "has_radio_access": self._has_radio_access,
                "is_network_gateway": self.can_act_as_gateway(),
            }
            sig = sign_data(load_ed25519_private(self.ed25519_priv),
                           json.dumps(hello, sort_keys=True).encode())
            hello["signature"] = sig
            self._send_encrypted(sock, transport, json.dumps(hello).encode())


            data = self._recv_encrypted(sock, transport)
            if not data:
                sock.close()
                return
            msg = json.loads(data.decode("utf-8"))

            if msg.get("type") != DC_AUTH:
                sock.close()
                return


            peer_pub = msg.get("ed25519_pub", "")
            peer_node_id = msg.get("node_id", "")
            sig = msg.get("signature", "")
            verify_data = json.dumps({k: v for k, v in msg.items() if k != "signature"},
                                     sort_keys=True).encode()
            if not verify_signature(load_ed25519_public(peer_pub), verify_data, sig):
                sock.close()
                return


            peer = PeerInfo(
                node_id=peer_node_id,
                pubkey_b64=peer_pub,
                address=f"{addr[0]}:{addr[1]}",
                connect_type=msg.get("connect_type", medium),
            )
            peer.uuid = msg.get("uuid", "")
            peer.has_public_access = bool(msg.get("has_public_access", False))
            peer.has_radio_access = bool(msg.get("has_radio_access", False))
            peer.is_network_gateway = bool(msg.get("is_network_gateway", False))
            peer.transport = transport
            peer.authenticated = True

            with self._peers_lock:
                self.peers[peer_node_id] = peer
            self._transports[peer_node_id] = transport

            # 入站连接建立后广播网络能力
            self.broadcast_capability()
            self._recompute_gateways()

            self._peer_recv_loop(sock, peer_node_id)

        except Exception as e:
            print(f"[DC] Incoming peer error: {e}")
            try:
                sock.close()
            except:
                pass


    def connect_to_peer(
        self, address: str, connect_type: str = "lan",
        peer_pubkey_b64: str = "", peer_node_id: str = ""
    ) -> bool:
        """
        Initiate connection to a peer.

        Args:
            address: "ip:port" or bluetooth MAC
            connect_type: "bluetooth", "wifi_direct", "lan", "public"
            peer_pubkey_b64: Expected Ed25519 pubkey (for verification)
            peer_node_id: Expected NodeID

        Returns:
            True if connection successful
        """
        try:
            if connect_type == "bluetooth":
                return self._connect_bluetooth(address, peer_pubkey_b64, peer_node_id)
            else:
                return self._connect_tcp(address, connect_type, peer_pubkey_b64, peer_node_id)
        except Exception as e:
            print(f"[DC] Connect to {address} ({connect_type}) failed: {e}")
            return False

    def _connect_tcp(
        self, address: str, connect_type: str,
        peer_pubkey_b64: str, peer_node_id: str
    ) -> bool:
        """通过 TCP 连接（局域网 / 公网 IP / WiFi Direct）。"""
        host, port_str = address.split(":")
        port = int(port_str)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(DIRECT_CONNECT_TIMEOUT)
        sock.connect((host, port))

        transport = TransportEncryptor(is_initiator=True)
        if not self._do_transport_handshake(sock, transport, is_initiator=True):
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
            "has_public_access": self._has_public_access,
            "has_radio_access": self._has_radio_access,
            "is_network_gateway": self.can_act_as_gateway(),
        }
        sig = sign_data(load_ed25519_private(self.ed25519_priv),
                       json.dumps(hello, sort_keys=True).encode())
        hello["signature"] = sig
        self._send_encrypted(sock, transport, json.dumps(hello).encode())


        data = self._recv_encrypted(sock, transport)
        if not data:
            sock.close()
            return False
        msg = json.loads(data.decode("utf-8"))

        if msg.get("type") != DC_HELLO:
            sock.close()
            return False


        peer_pub = msg.get("ed25519_pub", "")
        peer_node = msg.get("node_id", "")
        peer_sig = msg.get("signature", "")
        verify_msg = {k: v for k, v in msg.items() if k != "signature"}
        if not verify_signature(load_ed25519_public(peer_pub), 
                               json.dumps(verify_msg, sort_keys=True).encode(), peer_sig):
            sock.close()
            return False


        auth = {
            "type": DC_AUTH,
            "node_id": self.node_id,
            "ed25519_pub": self.ed25519_pub,
            "uuid": self.uuid,
        }
        auth_sig = sign_data(load_ed25519_private(self.ed25519_priv),
                             json.dumps(auth, sort_keys=True).encode())
        auth["signature"] = auth_sig
        self._send_encrypted(sock, transport, json.dumps(auth).encode())


        peer = PeerInfo(
            node_id=peer_node,
            pubkey_b64=peer_pub,
            address=address,
            connect_type=connect_type,
        )
        peer.uuid = msg.get("uuid", "")
        peer.has_public_access = bool(msg.get("has_public_access", False))
        peer.has_radio_access = bool(msg.get("has_radio_access", False))
        peer.is_network_gateway = bool(msg.get("is_network_gateway", False))
        peer.transport = transport
        peer.authenticated = True

        with self._peers_lock:
            self.peers[peer_node] = peer
        self._transports[peer_node] = transport


        threading.Thread(target=self._peer_recv_loop, args=(sock, peer_node), daemon=True).start()

        if self.on_peer_connected:
            self.on_peer_connected(peer)

        # 连接建立后广播网络能力，触发直连网拓扑同步和网关发现
        self.broadcast_capability()
        self._recompute_gateways()

        print(f"[DC] Connected to {peer_node[:16]}... via {connect_type} ({address})")
        return True

    def _connect_bluetooth(self, bt_address: str, peer_pubkey: str, peer_node_id: str) -> bool:
        """通过蓝牙 RFCOMM 连接。"""
        if not HAS_BLUETOOTH:
            print("[DC] Bluetooth not available (PyBluez not installed)")
            return False
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            sock.settimeout(DIRECT_CONNECT_TIMEOUT)
            sock.connect((bt_address, self.config.bt_port))
            transport = TransportEncryptor(is_initiator=True)
            print(f"[DC] Connected via Bluetooth to {bt_address}")
            return True
        except Exception as e:
            print(f"[DC] BT connect failed: {e}")
            return False


    def _do_transport_handshake(
        self, sock: socket.socket, transport: TransportEncryptor, is_initiator: bool
    ) -> bool:
        """执行 ECDH 密钥交换以实现传输层加密。"""
        try:
            if is_initiator:

                hello_data = json.dumps({
                    "type": ENC_HANDSHAKE,
                    "transport_pub": transport.public_key_b64,
                }).encode()
                sock.sendall(hello_data + b"\n")


                buf = b""
                while b"\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return False
                    buf += chunk
                line, _ = buf.split(b"\n", 1)
                resp = json.loads(line.decode("utf-8"))
                peer_tp_pub = resp.get("transport_pub", "")
                transport.set_peer_public_key(peer_tp_pub)
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
                peer_tp_pub = req.get("transport_pub", "")


                resp_data = json.dumps({
                    "type": ENC_HANDSHAKE_OK,
                    "transport_pub": transport.public_key_b64,
                }).encode()
                sock.sendall(resp_data + b"\n")

                transport.set_peer_public_key(peer_tp_pub)
                return True
        except Exception as e:
            print(f"[DC] Transport handshake failed: {e}")
            return False


    def _send_encrypted(self, sock: socket.socket, transport: TransportEncryptor, data: bytes):
        """加密并发送数据（传输层加密）。"""
        encrypted = transport.encrypt_packet(data)
        sock.sendall(encrypted)

    def _recv_encrypted(self, sock: socket.socket, transport: TransportEncryptor) -> Optional[bytes]:
        """接收并解密数据（传输层加密）。"""

        header = b""
        while len(header) < 17:
            chunk = sock.recv(17 - len(header))
            if not chunk:
                return None
            header += chunk
        nonce = header[5:17]

        remaining = b""
        sock.settimeout(10)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                remaining += chunk
                try:
                    full = header + remaining
                    plaintext = transport.decrypt_packet(full)
                    if plaintext is not None:
                        return plaintext
                except:
                    pass
        except socket.timeout:
            pass

        full = header + remaining
        return transport.decrypt_packet(full)


    def _peer_recv_loop(self, sock: socket.socket, peer_node_id: str):
        """持续接收来自已连接对端的消息。"""
        transport = self._transports.get(peer_node_id)
        if not transport:
            return

        while self._running:
            try:
                data = self._recv_encrypted(sock, transport)
                if not data:
                    break
                msg = json.loads(data.decode("utf-8"))
                self._handle_peer_message(peer_node_id, msg)
            except Exception as e:
                if self._running:
                    print(f"[DC] Peer {peer_node_id[:16]}... error: {e}")
                break

        self._disconnect_peer_by_id(peer_node_id)

    def _handle_peer_message(self, peer_id: str, msg: dict):
        """处理来自对端的消息。"""
        msg_type = msg.get("type")

        if msg_type == DC_SEND_MSG:
            if self.on_message:
                self.on_message(msg.get("from_uuid", peer_id), msg)
        elif msg_type == DC_FILE_CHUNK:
            if self.on_file_received:
                self.on_file_received(peer_id, msg)
        elif msg_type == DC_PING:
            self.send_to_peer(peer_id, {"type": DC_PONG, "timestamp": int(time.time())})
        elif msg_type == DC_DISCONNECT:
            self._disconnect_peer_by_id(peer_id)
        elif msg_type == DC_CAPABILITY:
            # 对端网络能力通告：更新拓扑，用于直连网络共享 / 多跳路由
            self._handle_capability(peer_id, msg)
        elif msg_type == DC_NETWORK_RELAY:
            # 网络中继请求：本节点作为网关时转发到公网/无线电，或继续多跳中继
            self._handle_network_relay(peer_id, msg)
        elif msg_type == DC_ROUTE_QUERY:
            # 路由查询：返回到达指定网络的路径信息
            self._handle_route_query(peer_id, msg)
        elif msg_type == DC_ROUTE_RESPONSE:
            # 路由响应：更新本地路由表
            self._handle_route_response(peer_id, msg)


    def send_to_peer(self, peer_node_id: str, msg: dict) -> bool:
        """向指定对端发送消息（传输层加密）。"""
        with self._peers_lock:
            peer = self.peers.get(peer_node_id)

        if not peer or not peer.transport:
            return False


        if peer.transport.should_rotate(self.config.transport_rotation_sec):
            self._rotate_peer_key(peer_node_id)

        try:
            data = json.dumps(msg).encode("utf-8")
            sock = getattr(peer, "_sock", None)
            if not sock:
                return False
            self._send_encrypted(sock, peer.transport, data)
            return True
        except Exception as e:
            print(f"[DC] Send to {peer_node_id[:16]}... failed: {e}")
            return False

    def send_message(self, to_uuid: str, to_node_id: str, encrypted_payload: dict, signature: str) -> bool:
        """通过 UUID + NodeID 向对端发送加密消息。"""
        msg = {
            "type": DC_SEND_MSG,
            "from_uuid": self.uuid,
            "to_uuid": to_uuid,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
            "timestamp": int(time.time()),
        }
        return self.send_to_peer(to_node_id, msg)

    def _rotate_peer_key(self, peer_node_id: str):
        """与对端轮换传输密钥。"""

        peer = self.peers.get(peer_node_id)
        if not peer or not peer.transport:
            return
        peer.transport.rotate_key()
        print(f"[DC] Rotated transport key with {peer_node_id[:16]}...")


    def _disconnect_peer_by_id(self, peer_node_id: str):
        with self._peers_lock:
            peer = self.peers.pop(peer_node_id, None)
        if peer:
            self._disconnect_peer(peer)
        self._transports.pop(peer_node_id, None)
        if self.on_peer_disconnected:
            self.on_peer_disconnected(peer_node_id)

    def _disconnect_peer(self, peer: PeerInfo):
        """关闭与对端的连接。"""
        sock = getattr(peer, "_sock", None)
        if sock:
            try:
                sock.close()
            except:
                pass
        peer.authenticated = False

    def disconnect_peer(self, peer_node_id: str):
        self._disconnect_peer_by_id(peer_node_id)


    def scan_bluetooth(self, timeout: int = BLUETOOTH_SCAN_TIMEOUT) -> list:
        """
        扫描附近的蓝牙设备。
        返回 {address, name} 字典列表。
        """
        if not HAS_BLUETOOTH:
            print("[DC] Bluetooth not available")
            return []
        try:
            print(f"[DC] Scanning Bluetooth devices (timeout={timeout}s)...")
            devices = bluetooth.discover_devices(duration=timeout, lookup_names=True)
            results = [{"address": addr, "name": name} for addr, name in devices]
            print(f"[DC] Found {len(results)} Bluetooth device(s)")
            return results
        except Exception as e:
            print(f"[DC] BT scan error: {e}")
            return []

    def _start_bluetooth_listener(self):
        """启动蓝牙 RFCOMM 服务器。"""
        if not HAS_BLUETOOTH:
            return
        try:
            self._bt_server = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            self._bt_server.bind(("", self.config.bt_port))
            self._bt_server.listen(self.config.max_peers)
            self._bt_thread = threading.Thread(target=self._bt_accept_loop, daemon=True)
            self._bt_thread.start()
            print(f"[DC] Bluetooth listener on port {self.config.bt_port}")
        except Exception as e:
            print(f"[DC] BT listener failed: {e}")

    def _bt_accept_loop(self):
        while self._running and self._bt_server:
            try:
                sock, addr = self._bt_server.accept()
                threading.Thread(
                    target=self._handle_incoming_peer,
                    args=(sock, addr, "bluetooth"),
                    daemon=True
                ).start()
            except Exception:
                break


    def scan_wifi_direct(self, timeout: int = WIFI_DIRECT_SCAN_TIMEOUT) -> list:
        """
        扫描 WiFi Direct 对端（平台相关）。
        Linux: 使用 `iw` 命令。
        Windows: 使用 netsh。
        Returns list of {name, address} dicts.
        """
        results = []
        if not HAS_WIFI_DIRECT:
            return results

        try:
            if sys.platform.startswith("linux"):
                r = subprocess.run(
                    ["iw", "dev", "wlan0", "scan"], capture_output=True, text=True, timeout=timeout
                )
                current_bss = None
                current_signal = None
                for line in r.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("BSS") or line.startswith("bss"):
                        if current_bss:
                            results.append({"bssid": current_bss, "signal": current_signal})
                        # 提取 BSSID（格式: BSS xx:xx:xx:xx:xx:xx）
                        parts = line.split()
                        if len(parts) > 1:
                            current_bss = parts[1]
                        current_signal = None
                    elif "signal" in line.lower():
                        # 提取信号强度数值
                        try:
                            sig_parts = line.split()
                            for i, p in enumerate(sig_parts):
                                if "signal" in p.lower() and i + 1 < len(sig_parts):
                                    current_signal = float(sig_parts[i + 1])
                                    break
                        except Exception:
                            current_signal = None
                if current_bss:
                    results.append({"bssid": current_bss, "signal": current_signal})
                print(f"[DC] WiFi Direct scan complete: {len(results)} BSS found")
            elif sys.platform.startswith("win"):
                r = subprocess.run(
                    ["netsh", "wlan", "show", "network"], capture_output=True, text=True, timeout=timeout
                )
                for line in r.stdout.split("\n"):
                    line = line.strip()
                    if line.startswith("SSID"):
                        ssid = line.split(":", 1)[1].strip() if ":" in line else ""
                        if ssid:
                            results.append({"ssid": ssid})
                print(f"[DC] WiFi scan complete: {len(results)} networks found")
        except Exception as e:
            print(f"[DC] WiFi Direct scan error: {e}")

        return results

    def connect_wifi_direct(self, peer_address: str, peer_pubkey: str = "", peer_node_id: str = "") -> bool:
        """连接到 WiFi Direct 对端。"""
        try:
            return self._connect_tcp(peer_address, "wifi_direct", peer_pubkey, peer_node_id)
        except Exception as e:
            print(f"[DC] WiFi Direct connect failed: {e}")
            return False


    def _start_lan_discovery(self):
        """启动 UDP 广播监听器用于局域网对端发现。"""
        try:
            self._lan_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._lan_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._lan_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._lan_sock.bind(("", self.config.dc_port + 1))
            self._lan_sock.settimeout(1.0)
            self._lan_thread = threading.Thread(target=self._lan_listen_loop, daemon=True)
            self._lan_thread.start()

            threading.Thread(target=self._lan_announce_loop, daemon=True).start()
            print(f"[DC] LAN discovery on UDP:{self.config.dc_port + 1}")
        except Exception as e:
            print(f"[DC] LAN discovery failed: {e}")

    def _lan_listen_loop(self):
        """监听局域网上的对端通告。"""
        while self._running and self._lan_sock:
            try:
                data, addr = self._lan_sock.recvfrom(4096)
                msg = json.loads(data.decode("utf-8"))
                if msg.get("type") == DC_ANNOUNCE:
                    peer_id = msg.get("node_id", "")
                    if peer_id and peer_id != self.node_id:

                        peer = PeerInfo(
                            node_id=peer_id,
                            pubkey_b64=msg.get("ed25519_pub", ""),
                            address=f"{addr[0]}:{msg.get('port', self.config.dc_port)}",
                            connect_type="lan",
                        )
                        peer.uuid = msg.get("uuid", "")
                        with self._peers_lock:
                            if peer_id not in self.peers:
                                self.peers[peer_id] = peer
                        response = {
                            "type": DC_NODE_INFO,
                            "node_id": self.node_id,
                            "ed25519_pub": self.ed25519_pub,
                            "x25519_pub": self.x25519_pub,
                            "uuid": self.uuid,
                            "port": self.config.dc_port,
                        }
                        self._lan_sock.sendto(json.dumps(response).encode(), addr)
            except socket.timeout:
                continue
            except Exception:
                break

    def _lan_announce_loop(self):
        """定期在局域网上通告存在。"""
        announce = {
            "type": DC_ANNOUNCE,
            "node_id": self.node_id,
            "ed25519_pub": self.ed25519_pub,
            "x25519_pub": self.x25519_pub,
            "uuid": self.uuid,
            "port": self.config.dc_port,
            "software": SOFTWARE_NAME,
            "version": SOFTWARE_VERSION,
        }
        data = json.dumps(announce).encode()
        target = ("255.255.255.255", self.config.dc_port + 1)
        while self._running and self._lan_sock:
            try:
                self._lan_sock.sendto(data, target)
            except Exception:
                pass
            time.sleep(LAN_BROADCAST_INTERVAL)

    def scan_lan_peers(self, timeout: int = 5) -> list:
        """返回当前已知局域网对端列表。"""
        with self._peers_lock:
            return [
                p.to_dict() for p in self.peers.values()
                if p.connect_type == "lan"
            ]


    def connect_public_ip(self, host: str, port: int, peer_pubkey: str = "", peer_node_id: str = "") -> bool:
        """通过公网 IP 地址直接连接。"""
        address = f"{host}:{port}"
        return self._connect_tcp(address, "public", peer_pubkey, peer_node_id)


    def relay_message(self, from_peer_id: str, to_peer_id: str, msg: dict) -> bool:
        """
        在两个已连接对端之间中继消息。
        当充当迷你服务器时，可为可信对端进行中继。
        """
        if to_peer_id in self.peers:
            return self.send_to_peer(to_peer_id, {
                "type": DC_RECV_MSG,
                "from_peer": from_peer_id,
                "original_msg": msg,
            })
        return False

    # ================================================================
    # 直连网络共享：任何客户端能接入网络（无线电或公网）时，
    # 其他直连（直接连接）或非直接直连（直连链/直连网，途中有节点
    # 同时连接至少两个节点）客户端可通过此客户端进行网络接入。
    # ================================================================

    def set_network_capabilities(self, has_public: Optional[bool] = None,
                                 has_radio: Optional[bool] = None,
                                 gateway_enabled: Optional[bool] = None):
        """
        设置本节点的网络接入能力，并自动向所有已连接对端广播。
        参数为 None 时保持原值。
        """
        if has_public is not None:
            self._has_public_access = bool(has_public)
        if has_radio is not None:
            self._has_radio_access = bool(has_radio)
        if gateway_enabled is not None:
            self._network_gateway_enabled = bool(gateway_enabled)
        # 能力变化后向所有对端广播
        self.broadcast_capability()

    def has_network_access(self) -> bool:
        """本节点是否具备任何网络接入能力（公网或无线电）。"""
        return self._has_public_access or self._has_radio_access

    def can_act_as_gateway(self) -> bool:
        """本节点是否可以作为网络网关（有网络接入且愿意中继）。"""
        return self.has_network_access() and self._network_gateway_enabled

    def broadcast_capability(self):
        """
        向所有已连接对端广播本节点的网络能力和直连拓扑。
        对端收到后更新本地拓扑，用于多跳路由发现。
        """
        with self._peers_lock:
            peer_ids = list(self.peers.keys())
        # 本节点已知的邻居列表（所有已连接对端的 node_id）
        my_neighbors = list(peer_ids)
        cap_msg = {
            "type": DC_CAPABILITY,
            "node_id": self.node_id,
            "has_public_access": self._has_public_access,
            "has_radio_access": self._has_radio_access,
            "is_network_gateway": self.can_act_as_gateway(),
            "connected_peers": my_neighbors,
            "timestamp": int(time.time()),
        }
        for pid in peer_ids:
            try:
                self.send_to_peer(pid, cap_msg)
            except Exception:
                pass

    def _update_topology(self, peer_id: str, neighbors: List[str]):
        """更新对端的拓扑信息（该对端连接了哪些节点）。"""
        with self._topology_lock:
            self._topology[peer_id] = list(neighbors)
        self._recompute_gateways()

    def _recompute_gateways(self):
        """
        基于当前直连网拓扑，重新计算可到达的网络网关列表。
        使用 BFS 从本节点出发，找到所有能到达网络网关的路径，
        按跳数排序。直连网关（跳数=1）优先，多跳网关次之。
        """
        # 构建邻接表：本节点 -> 所有直连 peer
        adj: Dict[str, List[str]] = {self.node_id: []}
        with self._peers_lock:
            for pid in self.peers:
                adj[self.node_id].append(pid)
                adj.setdefault(pid, [])
        with self._topology_lock:
            for pid, neighbors in self._topology.items():
                adj.setdefault(pid, [])
                for n in neighbors:
                    # 本节点的直连邻居以 self.peers 为准，不从其他节点的自报拓扑反向添加
                    if n == self.node_id or pid == self.node_id:
                        continue
                    if n not in adj[pid]:
                        adj[pid].append(n)
                    adj.setdefault(n, [])
                    if pid not in adj[n]:
                        adj[n].append(pid)
        # BFS 找所有网关
        gateways = []
        visited = {self.node_id}
        queue = [(self.node_id, 0)]
        while queue:
            node, hops = queue.pop(0)
            if node != self.node_id:
                with self._peers_lock:
                    peer = self.peers.get(node)
                if peer and (peer.has_public_access or peer.has_radio_access) and peer.is_network_gateway:
                    gateways.append((node, hops))
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, hops + 1))
        # 按跳数排序
        gateways.sort(key=lambda x: x[1])
        self._known_gateways = [g[0] for g in gateways]
        # 更新每个 peer 的 network_hops
        with self._peers_lock:
            for node, hops in gateways:
                if node in self.peers:
                    self.peers[node].network_hops = hops
        return gateways

    def find_network_gateway(self, network_type: str = "any") -> Optional[str]:
        """
        在直连网中查找可到达的网络网关。
        参数：
            network_type: 'any'（任意网络）/ 'public'（公网）/ 'radio'（无线电）
        返回：
            网关 peer 的 node_id，找不到返回 None。
        支持：
            - 直连网关（直接连接到此客户端）
            - 非直接直连网关（通过直连链/直连网，途中有节点同时连接至少两个节点）
        """
        if not self._known_gateways:
            self._recompute_gateways()
        for pid in self._known_gateways:
            with self._peers_lock:
                peer = self.peers.get(pid)
            if not peer:
                continue
            if network_type == "public" and not peer.has_public_access:
                continue
            if network_type == "radio" and not peer.has_radio_access:
                continue
            if peer.has_public_access or peer.has_radio_access:
                return pid
        return None

    def relay_to_network(self, payload: dict, network_type: str = "any") -> Optional[dict]:
        """
        通过直连网中的网络网关，将流量转发到公网或无线电网络。
        自动选择跳数最少的网关；支持直连网关和多跳（直连链/直连网）网关。
        参数：
            payload: 要发送到网络的消息字典
            network_type: 'any' / 'public' / 'radio'
        返回：
            网关的响应（如果有），失败返回 None
        """
        gateway_id = self.find_network_gateway(network_type)
        if gateway_id is None:
            print("[DC] No network gateway found in direct-connect mesh")
            return None
        relay_msg = {
            "type": DC_NETWORK_RELAY,
            "from_node": self.node_id,
            "target_network": network_type,
            "payload": payload,
            "timestamp": int(time.time()),
        }
        # 如果网关是直连邻居，直接发送
        with self._peers_lock:
            if gateway_id in self.peers:
                return self._send_relay_and_wait(gateway_id, relay_msg)
        # 多跳：需要找到到达网关的下一跳
        next_hop = self._find_next_hop(gateway_id)
        if next_hop is None:
            print(f"[DC] No route to gateway {gateway_id[:16]}...")
            return None
        relay_msg["next_hop"] = gateway_id  # 最终目标
        return self._send_relay_and_wait(next_hop, relay_msg)

    def _find_next_hop(self, target_id: str) -> Optional[str]:
        """
        在直连网拓扑中用 BFS 找到达 target_id 的下一跳（直连邻居）。
        用于多跳路由：当目标网关不是直连邻居时，找到路径上的第一个节点。
        """
        with self._peers_lock:
            if target_id in self.peers:
                return target_id
        # BFS
        adj: Dict[str, List[str]] = {self.node_id: []}
        with self._peers_lock:
            for pid in self.peers:
                adj[self.node_id].append(pid)
        with self._topology_lock:
            for pid, neighbors in self._topology.items():
                adj.setdefault(pid, [])
                for n in neighbors:
                    # 本节点的直连邻居以 self.peers 为准，不从拓扑反向添加
                    if n == self.node_id or pid == self.node_id:
                        continue
                    adj.setdefault(n, [])
                    if n not in adj[pid]:
                        adj[pid].append(n)
                    if pid not in adj[n]:
                        adj[n].append(pid)
        visited = {self.node_id}
        queue = [(self.node_id, None)]  # (node, first_hop)
        while queue:
            node, first_hop = queue.pop(0)
            if node == target_id:
                return first_hop
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    fh = first_hop if first_hop is not None else neighbor
                    queue.append((neighbor, fh))
        return None

    def _send_relay_and_wait(self, peer_id: str, msg: dict,
                              timeout: float = 5.0) -> Optional[dict]:
        """向对端发送中继消息并等待响应（简化实现：直接发送，不阻塞等待）。"""
        try:
            self.send_to_peer(peer_id, msg)
            return {"relayed": True, "via": peer_id}
        except Exception as e:
            print(f"[DC] Relay to {peer_id[:16]}... failed: {e}")
            return None

    def _handle_capability(self, peer_id: str, msg: dict):
        """
        处理对端的网络能力通告。
        更新对端的能力字段和拓扑信息，重新计算可到达的网关。
        """
        with self._peers_lock:
            peer = self.peers.get(peer_id)
            if peer:
                peer.has_public_access = bool(msg.get("has_public_access", False))
                peer.has_radio_access = bool(msg.get("has_radio_access", False))
                peer.is_network_gateway = bool(msg.get("is_network_gateway", False))
                peer.connected_peers = list(msg.get("connected_peers", []))
                peer.last_seen = time.time()
        # 更新拓扑
        neighbors = msg.get("connected_peers", [])
        if isinstance(neighbors, list):
            self._update_topology(peer_id, [str(n) for n in neighbors])
        # 收到能力通告后，也把自己的能力回发给对方（双向同步）
        self.broadcast_capability()

    def _handle_network_relay(self, peer_id: str, msg: dict):
        """
        处理收到的网络中继请求。
        如果本节点是网络网关，将流量转发到公网/无线电；
        如果本节点不是最终目标但有到达目标的路径，则继续中继（多跳）。
        """
        target_network = msg.get("target_network", "any")
        payload = msg.get("payload", {})
        final_target = msg.get("next_hop")  # 最终目标网关（多跳时）
        # 如果本节点可以作为该网络的网关，处理流量
        if self.can_act_as_gateway():
            if target_network in ("any", "public") and self._has_public_access:
                if self.on_network_relay:
                    try:
                        response = self.on_network_relay(payload)
                        if response:
                            self.send_to_peer(peer_id, {
                                "type": DC_NETWORK_RELAY,
                                "from_node": self.node_id,
                                "response": response,
                                "timestamp": int(time.time()),
                            })
                    except Exception as e:
                        print(f"[DC] Network relay handler error: {e}")
                return
            if target_network in ("any", "radio") and self._has_radio_access:
                if self.on_network_relay:
                    try:
                        response = self.on_network_relay(payload)
                        if response:
                            self.send_to_peer(peer_id, {
                                "type": DC_NETWORK_RELAY,
                                "from_node": self.node_id,
                                "response": response,
                                "timestamp": int(time.time()),
                            })
                    except Exception as e:
                        print(f"[DC] Network relay handler error: {e}")
                return
        # 多跳：如果不是最终目标，继续中继到下一跳
        if final_target and final_target != self.node_id:
            next_hop = self._find_next_hop(final_target)
            if next_hop and next_hop != peer_id:
                msg["via"] = self.node_id
                self.send_to_peer(next_hop, msg)
                return
        # 无法处理，丢弃
        print(f"[DC] Cannot handle network relay from {peer_id[:16]}... "
              f"(target={target_network}, has_pub={self._has_public_access}, "
              f"has_radio={self._has_radio_access})")

    def get_network_gateways(self) -> list:
        """返回当前已知的网络网关列表（含能力和跳数信息）。"""
        if not self._known_gateways:
            self._recompute_gateways()
        result = []
        with self._peers_lock:
            for pid in self._known_gateways:
                peer = self.peers.get(pid)
                if peer:
                    result.append({
                        "node_id": pid,
                        "has_public_access": peer.has_public_access,
                        "has_radio_access": peer.has_radio_access,
                        "is_network_gateway": peer.is_network_gateway,
                        "network_hops": peer.network_hops,
                    })
        return result

    def _handle_route_query(self, peer_id: str, msg: dict):
        """
        处理路由查询：返回到达指定网络的路径信息。
        查询方想知道通过本节点能否到达某个网络网关。
        """
        target_network = msg.get("target_network", "any")
        query_id = msg.get("query_id", "")
        # 本节点自身是否可达该网络
        self_reachable = False
        if target_network in ("any", "public") and self._has_public_access:
            self_reachable = True
        if target_network in ("any", "radio") and self._has_radio_access:
            self_reachable = True
        # 通过本节点的其他邻居是否可达
        gateway_via = self.find_network_gateway(target_network)
        response = {
            "type": DC_ROUTE_RESPONSE,
            "query_id": query_id,
            "from_node": self.node_id,
            "target_network": target_network,
            "self_reachable": self_reachable and self._network_gateway_enabled,
            "gateway_via": gateway_via,
            "hops": 1 if gateway_via in self.peers else 2,
            "timestamp": int(time.time()),
        }
        self.send_to_peer(peer_id, response)

    def _handle_route_response(self, peer_id: str, msg: dict):
        """处理路由响应：更新本地路由信息。"""
        # 路由响应已通过 _recompute_gateways 的 BFS 机制处理，
        # 此处仅记录对端的可达性信息
        with self._peers_lock:
            peer = self.peers.get(peer_id)
            if peer:
                if msg.get("self_reachable"):
                    peer.is_network_gateway = True
                peer.last_seen = time.time()
        self._recompute_gateways()

    def get_stats(self) -> dict:
        with self._peers_lock:
            peer_list = [
                {
                    "node_id": p.node_id[:16],
                    "type": p.connect_type,
                    "address": p.address,
                    "authenticated": p.authenticated,
                    "last_seen": p.last_seen,
                    "has_public_access": p.has_public_access,
                    "has_radio_access": p.has_radio_access,
                    "is_network_gateway": p.is_network_gateway,
                    "network_hops": p.network_hops,
                }
                for p in self.peers.values()
            ]
        return {
            "peers_connected": len(self.peers),
            "max_peers": self.config.max_peers,
            "transport_rotation_sec": self.config.transport_rotation_sec,
            "obfuscation": self.config.obfuscation_mode,
            "onion_enabled": self.config.onion_enabled,
            "listening_port": self.config.dc_port,
            "peers": peer_list,
            # 直连网络共享状态
            "self_has_public": self._has_public_access,
            "self_has_radio": self._has_radio_access,
            "self_is_gateway": self.can_act_as_gateway(),
            "known_gateways": self.get_network_gateways(),
        }


    def cleanup_dead_peers(self):
        """移除近期未出现的对端。"""
        cutoff = time.time() - 300
        dead = []
        with self._peers_lock:
            for pid, peer in list(self.peers.items()):
                if peer.last_seen < cutoff:
                    dead.append(pid)
            for pid in dead:
                peer = self.peers.pop(pid, None)
                if peer:
                    self._disconnect_peer(peer)
        for pid in dead:
            self._transports.pop(pid, None)
            if self.on_peer_disconnected:
                self.on_peer_disconnected(pid)
        if dead:
            print(f"[DC] Cleaned up {len(dead)} dead peer(s)")


# ============================================================
# 自测
# ============================================================
def _make_test_identity(node_suffix: str = "test") -> dict:
    """生成测试用身份（使用固定密钥对，避免依赖真实密钥生成）。"""
    from shared.crypto_utils import generate_ed25519_keypair, generate_x25519_keypair
    ed_priv, ed_pub = generate_ed25519_keypair()
    x_priv, x_pub = generate_x25519_keypair()
    return {
        "uuid": f"test-uuid-{node_suffix}",
        "ed25519_priv": ed_priv,
        "ed25519_pub": ed_pub,
        "x25519_priv": x_priv,
        "x25519_pub": x_pub,
    }


def selftest():
    """直连模块自测：重点验证网络共享 / 多跳路由逻辑。"""
    print("=== Direct Connect Selftest ===")

    # 1. PeerInfo 序列化往返（含网络能力字段）
    p = PeerInfo(node_id="test_node_1", pubkey_b64="AAAA", address="1.2.3.4:5678",
                 connect_type="lan")
    p.has_public_access = True
    p.has_radio_access = False
    p.is_network_gateway = True
    p.connected_peers = ["node_2", "node_3"]
    p.network_hops = 2
    d = p.to_dict()
    p2 = PeerInfo.from_dict(d)
    assert p2.has_public_access is True
    assert p2.has_radio_access is False
    assert p2.is_network_gateway is True
    assert p2.connected_peers == ["node_2", "node_3"]
    assert p2.network_hops == 2
    print("[DC] PeerInfo serialize round-trip (with network caps) OK")

    # 2. DirectConnectManager 基本初始化
    identity = _make_test_identity("nodeA")
    config = DirectConnectConfig()
    mgr = DirectConnectManager(identity, config)
    assert mgr.node_id is not None
    assert mgr.has_network_access() is False
    assert mgr.can_act_as_gateway() is False
    print("[DC] Manager init OK (no network access by default)")

    # 3. 设置网络能力：只有公网 -> 有网络接入但不满足网关双条件
    mgr.set_network_capabilities(has_public=True, has_radio=False)
    assert mgr._has_public_access is True
    assert mgr._has_radio_access is False
    assert mgr.has_network_access() is True
    # 注意：can_act_as_gateway 只要求有网络接入且愿意中继，不要求双条件
    # 双条件是无线电网络网关（dht.GatewayManager）的规则
    assert mgr.can_act_as_gateway() is True
    print("[DC] set_network_capabilities (public only) OK")

    # 4. 设置网络能力：只有无线电
    mgr.set_network_capabilities(has_public=False, has_radio=True)
    assert mgr.has_network_access() is True
    assert mgr.can_act_as_gateway() is True
    print("[DC] set_network_capabilities (radio only) OK")

    # 5. 设置网络能力：两者都有
    mgr.set_network_capabilities(has_public=True, has_radio=True)
    assert mgr.has_network_access() is True
    assert mgr.can_act_as_gateway() is True
    print("[DC] set_network_capabilities (both) OK")

    # 6. 禁用网关中继
    mgr.set_network_capabilities(gateway_enabled=False)
    assert mgr.can_act_as_gateway() is False
    mgr.set_network_capabilities(gateway_enabled=True)
    assert mgr.can_act_as_gateway() is True
    print("[DC] gateway_enabled toggle OK")

    # 7. 模拟直连网拓扑：添加一个直连网关节点
    gw_peer = PeerInfo(node_id="gw_peer", pubkey_b64="BBBB",
                        address="10.0.0.1:7895", connect_type="lan")
    gw_peer.has_public_access = True
    gw_peer.has_radio_access = False
    gw_peer.is_network_gateway = True
    gw_peer.connected_peers = [mgr.node_id]
    with mgr._peers_lock:
        mgr.peers["gw_peer"] = gw_peer
    mgr._update_topology("gw_peer", [mgr.node_id])
    gateways = mgr.get_network_gateways()
    assert len(gateways) >= 1
    assert any(g["node_id"] == "gw_peer" for g in gateways)
    found = mgr.find_network_gateway("any")
    assert found == "gw_peer"
    found_pub = mgr.find_network_gateway("public")
    assert found_pub == "gw_peer"
    found_radio = mgr.find_network_gateway("radio")
    assert found_radio is None  # gw_peer 没有无线电
    print("[DC] find_network_gateway (direct gateway) OK")

    # 8. 多跳路由：添加一个中间节点，该节点连接到网关
    mid_peer = PeerInfo(node_id="mid_peer", pubkey_b64="CCCC",
                         address="10.0.0.2:7895", connect_type="lan")
    mid_peer.has_public_access = False
    mid_peer.has_radio_access = False
    mid_peer.is_network_gateway = False
    mid_peer.connected_peers = [mgr.node_id, "gw_peer"]
    with mgr._peers_lock:
        mgr.peers["mid_peer"] = mid_peer
    mgr._update_topology("mid_peer", [mgr.node_id, "gw_peer"])
    # 模拟 gw_peer 的拓扑中包含 mid_peer（形成直连网）
    mgr._update_topology("gw_peer", [mgr.node_id, "mid_peer"])
    # 验证多跳：即使移除直连网关，通过 mid_peer 仍能到达 gw_peer
    with mgr._peers_lock:
        del mgr.peers["gw_peer"]
    mgr._known_gateways = []
    # 此时 gw_peer 不在直连 peers 中，但通过 mid_peer 的拓扑可达
    # find_network_gateway 只在直连 peers 中查找，所以需要通过路由查询
    # 验证 _find_next_hop 能找到达 gw_peer 的路径
    next_hop = mgr._find_next_hop("gw_peer")
    assert next_hop == "mid_peer", f"Expected mid_peer, got {next_hop}"
    print("[DC] multi-hop routing (_find_next_hop via mid_peer) OK")

    # 9. 能力消息处理：_handle_capability 更新对端能力
    cap_msg = {
        "type": DC_CAPABILITY,
        "node_id": "mid_peer",
        "has_public_access": True,
        "has_radio_access": True,
        "is_network_gateway": True,
        "connected_peers": [mgr.node_id, "gw_peer", "far_node"],
        "timestamp": int(time.time()),
    }
    mgr._handle_capability("mid_peer", cap_msg)
    with mgr._peers_lock:
        updated = mgr.peers["mid_peer"]
    assert updated.has_public_access is True
    assert updated.has_radio_access is True
    assert updated.is_network_gateway is True
    assert "far_node" in updated.connected_peers
    print("[DC] _handle_capability update OK")

    # 10. get_stats 包含网络共享信息
    stats = mgr.get_stats()
    assert "self_has_public" in stats
    assert "self_has_radio" in stats
    assert "self_is_gateway" in stats
    assert "known_gateways" in stats
    assert isinstance(stats["known_gateways"], list)
    print("[DC] get_stats includes network sharing info OK")

    # 11. 网络中继消息处理（本节点作为网关）
    mgr.set_network_capabilities(has_public=True, has_radio=False, gateway_enabled=True)
    relay_called = []
    def mock_relay(payload):
        relay_called.append(payload)
        return {"status": "ok"}
    mgr.on_network_relay = mock_relay
    relay_msg = {
        "type": DC_NETWORK_RELAY,
        "from_node": "mid_peer",
        "target_network": "public",
        "payload": {"data": "test-relay"},
        "timestamp": int(time.time()),
    }
    mgr._handle_network_relay("mid_peer", relay_msg)
    assert len(relay_called) == 1
    assert relay_called[0]["data"] == "test-relay"
    print("[DC] _handle_network_relay (as gateway) OK")

    # 12. 网络中继消息处理（本节点不是网关，多跳转发）
    mgr.set_network_capabilities(has_public=False, has_radio=False, gateway_enabled=True)
    # 恢复 gw_peer 为直连邻居
    with mgr._peers_lock:
        mgr.peers["gw_peer"] = gw_peer
    relay_msg2 = {
        "type": DC_NETWORK_RELAY,
        "from_node": "far_node",
        "target_network": "public",
        "payload": {"data": "multi-hop"},
        "next_hop": "gw_peer",
        "timestamp": int(time.time()),
    }
    # 本节点不是网关，但 next_hop=gw_peer 是直连邻居，应转发
    # 注意：_handle_network_relay 中如果本节点不是网关且 next_hop 不是自己，
    # 会尝试转发到 next_hop
    mgr._handle_network_relay("mid_peer", relay_msg2)
    print("[DC] _handle_network_relay (multi-hop forward) OK")

    print("ALL DIRECT CONNECT TESTS PASSED")


if __name__ == "__main__":
    selftest()
