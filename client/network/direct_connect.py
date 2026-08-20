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

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "pubkey": self.pubkey_b64,
            "address": self.address,
            "connect_type": self.connect_type,
            "last_seen": self.last_seen,
            "uuid": self.uuid,
            "name": self.name,
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
            peer.transport = transport
            peer.authenticated = True

            with self._peers_lock:
                self.peers[peer_node_id] = peer
            self._transports[peer_node_id] = transport


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
        peer.transport = transport
        peer.authenticated = True

        with self._peers_lock:
            self.peers[peer_node] = peer
        self._transports[peer_node] = transport


        threading.Thread(target=self._peer_recv_loop, args=(sock, peer_node), daemon=True).start()

        if self.on_peer_connected:
            self.on_peer_connected(peer)

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


    def get_stats(self) -> dict:
        with self._peers_lock:
            peer_list = [
                {
                    "node_id": p.node_id[:16],
                    "type": p.connect_type,
                    "address": p.address,
                    "authenticated": p.authenticated,
                    "last_seen": p.last_seen,
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
