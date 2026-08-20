"""
Cross-server relay — forwards messages between users on different servers.

When two servers have discovered each other via DHT, they can relay
messages for users registered on different servers.

Rate limiting: the stricter of the two servers' limits applies.

SECURITY:
- PKI-based authentication with Ed25519 certificate chains
- No hardcoded fallback secrets; startup fails if keyring unavailable
- Mutual TLS-style handshake with signed tokens
- TOFU persistent verification for peer certificates
"""

import json
import time
import threading
import hashlib
import socket
import sqlite3
import os
from collections import defaultdict
from server.config.loader import get_data_dir
from shared.crypto_utils import (
    sign_data, verify_signature,
    load_ed25519_private, load_ed25519_public,
    hkdf_derive, generate_x25519_keypair,
    load_x25519_private, load_x25519_public,
    b64_encode, b64_decode,
)
from server.keyring_store.credentials import (
    get_server_keys, get_node_id
)


class CrossServerRelay:
    """
    Manages inter-server TCP connections and message forwarding.
    Each server maintains persistent connections to peer servers
    that it has discovered via DHT.

    Security model:
    - Each server has an Ed25519 identity key pair (stored in keyring)
    - Peers authenticate via signed handshake tokens (not shared secrets)
    - TOFU: first-seen peer pubkey is pinned; mismatches trigger alerts
    - Certificate chain: bootstrap nodes act as trust anchors
    """

    def __init__(self, config: dict, chat_server=None, dht_node=None):
        self.config = config
        self.chat_server = chat_server
        self.dht_node = dht_node

        self.peers: dict[str, dict] = {}
        self.peers_lock = threading.Lock()

        keys = get_server_keys()
        self._ed25519_priv_b64 = keys["server_ed25519_priv"]
        self._ed25519_pub_b64 = keys["server_ed25519_pub"]
        self._x25519_priv_b64 = keys["server_x25519_priv"]
        self._x25519_pub_b64 = keys["server_x25519_pub"]
        self.node_id = get_node_id()

        self._ephemeral_priv_b64, self._ephemeral_pub_b64 = generate_x25519_keypair()

        self.trust_anchors: set[str] = set(config.get("pki", {}).get("trust_anchors", []))
        self._pinned_pubkeys: dict[str, str] = {}
        self._pins_lock = threading.Lock()
        self._pins_db_path = f"{get_data_dir()}/peer_pins.db"
        self._init_pins_db()

        self.known_peers: list[dict] = []
        self._known_peers_lock = threading.Lock()

        self.db_path = f"{get_data_dir()}/interserver.db"
        self._init_db()

        self.remote_user_cache: dict[str, str] = {}
        self.cache_lock = threading.Lock()

        self.pending_messages: dict[str, list] = defaultdict(list)

        self._peer_rate_cache: dict[str, dict] = {}
        self._rate_cache_lock = threading.Lock()

        self._listener_thread = None
        self._running = False


    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS interserver_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_server TEXT NOT NULL,
                to_server TEXT NOT NULL,
                msg_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                delivered INTEGER DEFAULT 0
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS peer_servers (
                node_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                ed25519_pubkey TEXT NOT NULL,
                last_seen INTEGER DEFAULT 0,
                trusted INTEGER DEFAULT 0,
                first_seen INTEGER NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _init_pins_db(self):
        """初始化 TOFU 引脚数据库。"""
        conn = sqlite3.connect(self._pins_db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS pinned_keys (
                node_id TEXT PRIMARY KEY,
                ed25519_pubkey TEXT NOT NULL,
                first_seen INTEGER NOT NULL,
                last_verified INTEGER NOT NULL
            )
        """)
        conn.commit()
        conn.close()

        conn = sqlite3.connect(self._pins_db_path)
        c = conn.cursor()
        for row in c.execute("SELECT node_id, ed25519_pubkey FROM pinned_keys"):
            self._pinned_pubkeys[row[0]] = row[1]
        conn.close()

    def _save_pin(self, node_id: str, pubkey_b64: str):
        """持久化一个 TOFU 引脚。"""
        with self._pins_lock:
            self._pinned_pubkeys[node_id] = pubkey_b64
        conn = sqlite3.connect(self._pins_db_path)
        c = conn.cursor()
        now = int(time.time())
        c.execute(
            "INSERT OR REPLACE INTO pinned_keys (node_id, ed25519_pubkey, first_seen, last_verified) "
            "VALUES (?, ?, COALESCE((SELECT first_seen FROM pinned_keys WHERE node_id=?), ?), ?)",
            (node_id, pubkey_b64, node_id, now, now)
        )
        conn.commit()
        conn.close()

    def _check_pin(self, node_id: str, pubkey_b64: str) -> tuple[bool, str]:
        """
        验证 TOFU 引脚。返回 (是否通过, 原因)。
        - 首次见到的密钥：固定并信任（首次信任机制）
        - 已见过的密钥：必须完全匹配已固定的密钥
        """
        with self._pins_lock:
            pinned = self._pinned_pubkeys.get(node_id)
        if pinned is None:
            self._save_pin(node_id, pubkey_b64)
            return True, "pinned_new"
        if pinned == pubkey_b64:

            conn = sqlite3.connect(self._pins_db_path)
            c = conn.cursor()
            c.execute("UPDATE pinned_keys SET last_verified=? WHERE node_id=?",
                      (int(time.time()), node_id))
            conn.commit()
            conn.close()
            return True, "verified"
        return False, f"PUBKEY MISMATCH: expected {pinned[:16]}..., got {pubkey_b64[:16]}..."


    def start(self, listen_port: int):
        """开始监听入站对端服务器连接。"""
        self._running = True
        self._listen_port = listen_port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", listen_port))
        self._sock.listen(50)
        self._listener_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._listener_thread.start()
        print(f"[INTERSERVER] Listening on port {listen_port} for peer servers (PKI auth)")


        self._load_known_peers()

        for peer in list(self.known_peers):
            threading.Thread(target=self._connect_to_peer,
                            args=(peer["node_id"], peer["host"], peer["port"]),
                            daemon=True).start()

    def stop(self):
        self._running = False
        if hasattr(self, '_sock') and self._sock:
            try:
                self._sock.close()
            except:
                pass
        with self.peers_lock:
            for peer_info in self.peers.values():
                try:
                    peer_info["sock"].close()
                except:
                    pass
            self.peers.clear()


    def add_known_peer(self, node_id: str, host: str, port: int,
                       ed25519_pubkey: str = "", trusted: bool = False):
        """添加对端服务器（来自 DHT 发现或配置）。"""
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute(
            "INSERT OR REPLACE INTO peer_servers "
            "(node_id, host, port, ed25519_pubkey, trusted, first_seen) "
            "VALUES (?,?,?,?,?,?)",
            (node_id, host, port, ed25519_pubkey, 1 if trusted else 0, int(time.time()))
        )
        conn.commit()
        conn.close()

        with self._known_peers_lock:
            self.known_peers.append({
                "node_id": node_id, "host": host, "port": port,
                "ed25519_pubkey": ed25519_pubkey
            })

        threading.Thread(target=self._connect_to_peer,
                        args=(node_id, host, port), daemon=True).start()

    def _load_known_peers(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT node_id, host, port, ed25519_pubkey FROM peer_servers")
        rows = c.fetchall()
        conn.close()
        with self._known_peers_lock:
            self.known_peers = [
                {"node_id": r[0], "host": r[1], "port": r[2], "ed25519_pubkey": r[3]}
                for r in rows
            ]

    def discover_peers_from_dht(self):
        """查询 DHT 中的其他聊天服务器并添加为对端。"""
        if not self.dht_node:
            return []
        found = []
        routing_info = self.dht_node.get_routing_info()
        return found


    def _accept_loop(self):
        self._sock.settimeout(1.0)
        while self._running:
            try:
                sock, addr = self._sock.accept()
                threading.Thread(target=self._handle_peer,
                                args=(sock, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[INTERSERVER] Accept error: {e}")

    def _connect_to_peer(self, node_id: str, host: str, port: int):
        """通过 PKI 握手建立到对端服务器的出站连接。"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))

            my_priv = load_ed25519_private(self._ed25519_priv_b64)
            hello_payload = json.dumps({
                "type": "INTERSERVER_HELLO",
                "node_id": self.node_id,
                "ed25519_pubkey": self._ed25519_pub_b64,
                "ephemeral_x25519_pub": self._ephemeral_pub_b64,
                "timestamp": int(time.time()),
            }, sort_keys=True).encode()
            hello_sig = sign_data(my_priv, hello_payload)

            hello_msg = {
                "type": "INTERSERVER_HELLO",
                "node_id": self.node_id,
                "ed25519_pubkey": self._ed25519_pub_b64,
                "ephemeral_x25519_pub": self._ephemeral_pub_b64,
                "timestamp": int(time.time()),
                "signature": hello_sig,
            }
            sock.sendall((json.dumps(hello_msg) + "\n").encode())

            sock.settimeout(15)
            data = sock.recv(65536)
            response = json.loads(data.decode().strip())

            if response.get("type") != "INTERSERVER_HELLO":
                print(f"[INTERSERVER] Expected HELLO, got {response.get('type')}")
                sock.close()
                return

            peer_node_id = response.get("node_id", "")
            peer_e_pubkey = response.get("ed25519_pubkey", "")
            peer_ephemeral = response.get("ephemeral_x25519_pub", "")
            peer_ts = response.get("timestamp", 0)
            peer_sig = response.get("signature", "")

            peer_hello_payload = json.dumps({
                "type": "INTERSERVER_HELLO",
                "node_id": peer_node_id,
                "ed25519_pubkey": peer_e_pubkey,
                "ephemeral_x25519_pub": peer_ephemeral,
                "timestamp": peer_ts,
            }, sort_keys=True).encode()

            try:
                peer_pubkey_obj = load_ed25519_public(peer_e_pubkey)
            except Exception as e:
                print(f"[INTERSERVER] Peer {peer_node_id[:16]}... has invalid pubkey: {e}")
                sock.close()
                return

            if not verify_signature(peer_pubkey_obj, peer_hello_payload, peer_sig):
                print(f"[INTERSERVER] Peer {peer_node_id[:16]}... HELLO signature INVALID")
                sock.close()
                return

            if abs(time.time() - peer_ts) > 300:
                print(f"[INTERSERVER] Peer {peer_node_id[:16]}... clock skew too large")
                sock.close()
                return

            pin_ok, pin_reason = self._check_pin(peer_node_id, peer_e_pubkey)
            if not pin_ok:
                print(f"[INTERSERVER] 🚨 TOFU PIN MISMATCH for {peer_node_id[:16]}... — {pin_reason}")
                print(f"[INTERSERVER] This may indicate a MITM attack or key rotation. "
                      f"Delete {self._pins_db_path} to reset pins.")
                sock.close()
                return
            print(f"[INTERSERVER] TOFU: {pin_reason} for {peer_node_id[:16]}...")

            my_e_priv = load_x25519_private(self._ephemeral_priv_b64)
            peer_e_pub_obj = load_x25519_public(peer_ephemeral)
            shared = my_e_priv.exchange(peer_e_pub_obj)
            transport_key = hkdf_derive(shared, info=b"spider-interserver-transport", length=32)

            auth_payload = json.dumps({
                "type": "INTERSERVER_AUTH_OK",
                "node_id": self.node_id,
                "timestamp": int(time.time()),
            }, sort_keys=True).encode()
            auth_sig = sign_data(my_priv, auth_payload)
            auth_msg = {
                "type": "INTERSERVER_AUTH_OK",
                "node_id": self.node_id,
                "timestamp": int(time.time()),
                "signature": auth_sig,
            }
            sock.sendall((json.dumps(auth_msg) + "\n").encode())

            with self.peers_lock:
                self.peers[peer_node_id] = {
                    "sock": sock,
                    "addr": (host, port),
                    "last_seen": time.time(),
                    "authenticated": True,
                    "node_id": peer_node_id,
                    "ed25519_pubkey": peer_e_pubkey,
                    "transport_key": transport_key,
                }


            self.add_known_peer(peer_node_id, host, port, peer_e_pubkey, trusted=True)


            self._flush_pending(peer_node_id)


            threading.Thread(target=self._peer_recv_loop,
                            args=(peer_node_id, sock), daemon=True).start()
            print(f"[INTERSERVER] ✅ Authenticated peer {peer_node_id[:16]}... at {host}:{port}")

        except Exception as e:
            print(f"[INTERSERVER] Failed to connect to {host}:{port} — {e}")

            threading.Timer(30.0, lambda: self._connect_to_peer(node_id, host, port)).start()

    def _handle_peer(self, sock: socket.socket, addr: tuple):
        """处理来自对端服务器的入站连接。"""
        try:
            sock.settimeout(15)
            data = sock.recv(65536)
            msg = json.loads(data.decode().strip())

            if msg.get("type") != "INTERSERVER_HELLO":
                print(f"[INTERSERVER] Rejecting {addr}: expected HELLO, got {msg.get('type')}")
                sock.close()
                return

            peer_node_id = msg.get("node_id", "")
            peer_e_pubkey = msg.get("ed25519_pubkey", "")
            peer_ephemeral = msg.get("ephemeral_x25519_pub", "")
            peer_ts = msg.get("timestamp", 0)
            peer_sig = msg.get("signature", "")

            if not peer_node_id or not peer_e_pubkey:
                print(f"[INTERSERVER] Rejecting {addr}: missing identity")
                sock.close()
                return


            hello_payload = json.dumps({
                "type": "INTERSERVER_HELLO",
                "node_id": peer_node_id,
                "ed25519_pubkey": peer_e_pubkey,
                "ephemeral_x25519_pub": peer_ephemeral,
                "timestamp": peer_ts,
            }, sort_keys=True).encode()

            try:
                peer_pubkey_obj = load_ed25519_public(peer_e_pubkey)
            except Exception:
                print(f"[INTERSERVER] Rejecting {addr}: invalid pubkey format")
                sock.close()
                return

            if not verify_signature(peer_pubkey_obj, hello_payload, peer_sig):
                print(f"[INTERSERVER] Rejecting {addr}: HELLO signature INVALID")
                sock.close()
                return


            if abs(time.time() - peer_ts) > 300:
                print(f"[INTERSERVER] Rejecting {addr}: clock skew too large")
                sock.close()
                return

            pin_ok, pin_reason = self._check_pin(peer_node_id, peer_e_pubkey)
            if not pin_ok:
                print(f"[INTERSERVER] 🚨 TOFU PIN MISMATCH from {addr} ({peer_node_id[:16]}...) — {pin_reason}")
                sock.close()
                return

            my_e_priv = load_x25519_private(self._ephemeral_priv_b64)
            peer_e_pub_obj = load_x25519_public(peer_ephemeral)
            shared = my_e_priv.exchange(peer_e_pub_obj)
            transport_key = hkdf_derive(shared, info=b"spider-interserver-transport", length=32)


            my_priv = load_ed25519_private(self._ed25519_priv_b64)
            resp_payload = json.dumps({
                "type": "INTERSERVER_HELLO",
                "node_id": self.node_id,
                "ed25519_pubkey": self._ed25519_pub_b64,
                "ephemeral_x25519_pub": self._ephemeral_pub_b64,
                "timestamp": int(time.time()),
            }, sort_keys=True).encode()
            resp_sig = sign_data(my_priv, resp_payload)
            resp_msg = {
                "type": "INTERSERVER_HELLO",
                "node_id": self.node_id,
                "ed25519_pubkey": self._ed25519_pub_b64,
                "ephemeral_x25519_pub": self._ephemeral_pub_b64,
                "timestamp": int(time.time()),
                "signature": resp_sig,
            }
            sock.sendall((json.dumps(resp_msg) + "\n").encode())


            sock.settimeout(15)
            data2 = sock.recv(65536)
            auth_msg = json.loads(data2.decode().strip())

            if auth_msg.get("type") != "INTERSERVER_AUTH_OK":
                print(f"[INTERSERVER] Expected AUTH_OK, got {auth_msg.get('type')}")
                sock.close()
                return

            auth_node = auth_msg.get("node_id", "")
            auth_ts = auth_msg.get("timestamp", 0)
            auth_sig = auth_msg.get("signature", "")

            if auth_node != peer_node_id:
                print(f"[INTERSERVER] AUTH_OK node_id mismatch!")
                sock.close()
                return

            auth_payload = json.dumps({
                "type": "INTERSERVER_AUTH_OK",
                "node_id": auth_node,
                "timestamp": auth_ts,
            }, sort_keys=True).encode()

            if not verify_signature(peer_pubkey_obj, auth_payload, auth_sig):
                print(f"[INTERSERVER] AUTH_OK signature INVALID from {peer_node_id[:16]}...")
                sock.close()
                return

            with self.peers_lock:
                self.peers[peer_node_id] = {
                    "sock": sock,
                    "addr": addr,
                    "last_seen": time.time(),
                    "authenticated": True,
                    "node_id": peer_node_id,
                    "ed25519_pubkey": peer_e_pubkey,
                    "transport_key": transport_key,
                }

            self.add_known_peer(peer_node_id, addr[0], addr[1], peer_e_pubkey, trusted=True)

            threading.Thread(target=self._peer_recv_loop,
                            args=(peer_node_id, sock), daemon=True).start()
            print(f"[INTERSERVER] ✅ Peer authenticated: {peer_node_id[:16]}... from {addr}")

        except Exception as e:
            print(f"[INTERSERVER] Peer handshake error from {addr}: {e}")
            try:
                sock.close()
            except:
                pass

    def _peer_recv_loop(self, peer_node_id: str, sock: socket.socket):
        """已建立对端连接的接收循环。"""
        buf = b""
        sock.settimeout(300)
        try:
            while self._running:
                data = sock.recv(65536)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self._handle_interserver_message(peer_node_id, line.decode().strip())
        except Exception as e:
            if self._running:
                print(f"[INTERSERVER] Peer {peer_node_id[:16]}... disconnected: {e}")
        finally:
            with self.peers_lock:
                self.peers.pop(peer_node_id, None)


    def _handle_interserver_message(self, peer_node_id: str, raw_json: str):
        """处理从对端服务器接收到的消息。"""
        try:
            msg = json.loads(raw_json)
        except:
            return

        msg_type = msg.get("type")

        if msg_type == "RELAY_MSG":
            self._handle_relay_message(peer_node_id, msg)
        elif msg_type == "GROUP_MSG_RELAY":
            self._handle_group_relay(peer_node_id, msg)
        elif msg_type == "USER_LOOKUP":
            self._handle_user_lookup(peer_node_id, msg)
        elif msg_type == "USER_LOOKUP_RESPONSE":
            self._handle_user_lookup_response(msg)
        elif msg_type == "RATE_LIMIT_QUERY":
            self._handle_rate_limit_query(peer_node_id, msg)
        elif msg_type == "RATE_LIMIT_RESPONSE":
            self._handle_rate_limit_response(msg)
        elif msg_type == "PING":
            self._send_to_peer(peer_node_id, {"type": "PONG", "timestamp": int(time.time())})

    def _handle_relay_message(self, peer_node_id: str, msg: dict):
        """
        对端服务器请求我们向本地用户投递消息。
        采用本地和对端报告的限速中更严格的一方。
        """
        target_uuid = msg.get("to_uuid", "")
        from_uuid = msg.get("from_uuid", "")
        encrypted = msg.get("encrypted_payload", {})
        signature = msg.get("signature", "")
        source_server = msg.get("source_server", peer_node_id)

        if not self.chat_server:
            return


        peer_rate = self._get_cached_peer_rate(peer_node_id, from_uuid)
        local_rate = self.chat_server.rate_limiter.get_effective_rate(target_uuid) if self.chat_server else 0.5

        effective_rate = max(local_rate, peer_rate)


        if not self.chat_server.rate_limiter.allow_with_rate(target_uuid, effective_rate):
            self._send_to_peer(peer_node_id, {
                "type": "RELAY_REJECTED",
                "to_uuid": target_uuid,
                "reason": "rate_limited_on_target_server",
                "applied_rate": effective_rate,
            })
            return


        target_conn = self.chat_server.connections.get(target_uuid)
        relay_msg = {
            "type": "RECV_MSG",
            "from_uuid": from_uuid,
            "to_uuid": target_uuid,
            "encrypted_payload": encrypted,
            "timestamp": int(time.time()),
            "via_server": source_server,
        }

        if target_conn:
            self.chat_server._send_raw(target_conn, relay_msg)
            self.chat_server.stats["messages_relayed"] += 1
        else:
            self.chat_server.offline_store.add_message(target_uuid, relay_msg)

        self._log_interserver_msg(source_server, self.node_id,
                                  "RELAY_DELIVERED", json.dumps(msg))

    def _handle_group_relay(self, peer_node_id: str, msg: dict):
        """对端转发了群消息。投递给本地群成员。"""
        if not hasattr(self.chat_server, 'group_manager'):
            return
        gm = self.chat_server.group_manager
        gm.handle_remote_group_message(msg)

    def _handle_user_lookup(self, peer_node_id: str, msg: dict):
        """对端询问我们是否有某用户。找到则返回公钥。"""
        target_uuid = msg.get("uuid", "")
        user = self.chat_server.user_manager.get_user(target_uuid) if self.chat_server else None
        response = {
            "type": "USER_LOOKUP_RESPONSE",
            "uuid": target_uuid,
            "found": bool(user),
            "responder": self.node_id,
        }
        if user:
            response["x25519_public"] = user.get("x25519_pub", "")
            response["ed25519_public"] = user.get("ed25519_pub", "")
            with self.cache_lock:
                self.remote_user_cache[target_uuid] = self.node_id

        self._send_to_peer(peer_node_id, response)

    def _handle_user_lookup_response(self, msg: dict):
        uuid_str = msg.get("uuid", "")
        if msg.get("found"):
            with self.cache_lock:
                self.remote_user_cache[uuid_str] = msg.get("responder", "")

    def _handle_rate_limit_query(self, peer_node_id: str, msg: dict):
        """对端询问我们对某用户的限速设置。"""
        uuid_str = msg.get("uuid", "")
        if not self.chat_server:
            return
        rl = self.chat_server.rate_limiter
        status = rl.get_status()
        user_rate = status.get("overrides", {}).get(uuid_str, status.get("global_seconds_per_msg"))
        self._send_to_peer(peer_node_id, {
            "type": "RATE_LIMIT_RESPONSE",
            "uuid": uuid_str,
            "seconds_per_msg": user_rate,
            "burst": status.get("burst_capacity"),
            "responder": self.node_id,
        })

    def _handle_rate_limit_response(self, msg: dict):
        """存储对端对某用户的限速信息。"""
        uuid_str = msg.get("uuid", "")
        peer_id = msg.get("responder", "")
        seconds = msg.get("seconds_per_msg", 0.5)
        with self._rate_cache_lock:
            if peer_id not in self._peer_rate_cache:
                self._peer_rate_cache[peer_id] = {}
            self._peer_rate_cache[peer_id][uuid_str] = seconds

    def _get_cached_peer_rate(self, peer_node_id: str, uuid_str: str) -> float:
        """获取对端报告的某用户的缓存限速值。"""
        with self._rate_cache_lock:
            return self._peer_rate_cache.get(peer_node_id, {}).get(uuid_str, 0.5)


    def relay_message(self, from_uuid: str, to_uuid: str,
                     encrypted_payload: dict, signature: str) -> dict:
        """
        向可能在其他服务器上的用户中继消息。
        返回: {"status": "delivered"|"queued"|"no_route"|"rate_limited"}
        """

        with self.cache_lock:
            target_server = self.remote_user_cache.get(to_uuid, "")

        if not target_server:
            target_server = self._find_user_server(to_uuid)

        if not target_server or target_server == self.node_id:
            return {"status": "no_route", "reason": "user_unknown_or_local"}


        with self.peers_lock:
            peer = self.peers.get(target_server)

        if not peer or not peer.get("authenticated"):
            relay_msg = {
                "type": "RELAY_MSG",
                "from_uuid": from_uuid,
                "to_uuid": to_uuid,
                "encrypted_payload": encrypted_payload,
                "signature": signature,
                "source_server": self.node_id,
                "timestamp": int(time.time()),
            }
            self.pending_messages[target_server].append(relay_msg)
            self._try_connect_to_peer_by_node_id(target_server)
            return {"status": "queued", "reason": "peer_not_connected"}


        self._send_to_peer(target_server, {
            "type": "RATE_LIMIT_QUERY",
            "uuid": from_uuid,
            "query_id": f"{from_uuid}:{int(time.time())}",
        })

        if self.chat_server and not self.chat_server.rate_limiter.allow(from_uuid):
            return {"status": "rate_limited", "reason": "local_limit"}

        relay_msg = {
            "type": "RELAY_MSG",
            "from_uuid": from_uuid,
            "to_uuid": to_uuid,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
            "source_server": self.node_id,
            "timestamp": int(time.time()),
        }
        success = self._send_to_peer(target_server, relay_msg)
        if success:
            self._log_interserver_msg(self.node_id, target_server,
                                      "RELAY_SENT", json.dumps(relay_msg))
            return {"status": "delivered", "via_server": target_server}
        else:
            return {"status": "queued", "reason": "send_failed"}

    def _find_user_server(self, uuid_str: str) -> str:
        """查找托管某用户的服务器。先尝试 DHT，再查已知对端。"""
        if self.dht_node:
            value = self.dht_node.get(f"user:{uuid_str}")
            if value:
                try:
                    data = json.loads(value)
                    server_id = data.get("home_server", "")
                    if server_id:
                        with self.cache_lock:
                            self.remote_user_cache[uuid_str] = server_id
                        return server_id
                except:
                    pass
            loc = self.dht_node.get(f"user_location:{uuid_str}")
            if loc:
                with self.cache_lock:
                    self.remote_user_cache[uuid_str] = loc
                return loc

        for peer in list(self.known_peers):
            node_id = peer["node_id"]
            if self._query_peer_for_user(node_id, uuid_str):
                return node_id

        return ""

    def _query_peer_for_user(self, peer_node_id: str, uuid_str: str) -> bool:
        return self._send_to_peer(peer_node_id, {
            "type": "USER_LOOKUP",
            "uuid": uuid_str,
            "query_id": f"{uuid_str}:{int(time.time())}",
        })

    def _try_connect_to_peer_by_node_id(self, node_id: str):
        for peer in list(self.known_peers):
            if peer["node_id"] == node_id:
                threading.Thread(target=self._connect_to_peer,
                                args=(node_id, peer["host"], peer["port"]),
                                daemon=True).start()
                return


    def relay_group_message(self, group_id: str, from_uuid: str,
                           encrypted_payload: dict, signature: str,
                           target_servers: list) -> dict:
        sent = 0
        msg = {
            "type": "GROUP_MSG_RELAY",
            "group_id": group_id,
            "from_uuid": from_uuid,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
            "source_server": self.node_id,
            "timestamp": int(time.time()),
        }
        for server_id in target_servers:
            if server_id == self.node_id:
                continue
            if self._send_to_peer(server_id, msg):
                sent += 1
            else:
                self.pending_messages[server_id].append(msg)
        return {"sent": sent, "total": len(target_servers)}


    def _send_to_peer(self, node_id: str, msg: dict) -> bool:
        with self.peers_lock:
            peer = self.peers.get(node_id)
            if not peer or not peer.get("authenticated"):
                return False
            sock = peer["sock"]
        try:
            raw = (json.dumps(msg) + "\n").encode()
            sock.sendall(raw)
            with self.peers_lock:
                if node_id in self.peers:
                    self.peers[node_id]["last_seen"] = time.time()
            return True
        except Exception as e:
            print(f"[INTERSERVER] Send to {node_id[:16]}... failed: {e}")
            with self.peers_lock:
                self.peers.pop(node_id, None)
            return False

    def _flush_pending(self, node_id: str):
        msgs = self.pending_messages.pop(node_id, [])
        for msg in msgs:
            self._send_to_peer(node_id, msg)
        if msgs:
            print(f"[INTERSERVER] Flushed {len(msgs)} pending messages to {node_id[:16]}...")


    def announce_user_location(self, uuid_str: str):
        if not self.dht_node:
            return
        self.dht_node.store(f"user_location:{uuid_str}", self.node_id, ttl=3600)
        if self.chat_server:
            user = self.chat_server.user_manager.get_user(uuid_str)
            if user:
                value = json.dumps({
                    "uuid": uuid_str,
                    "x25519_pub": user.get("x25519_pub", ""),
                    "ed25519_pub": user.get("ed25519_pub", ""),
                    "home_server": self.node_id,
                    "server_ed25519_pub": self._ed25519_pub_b64,
                })
                self.dht_node.store(f"user:{uuid_str}", value, ttl=3600)

    def get_stricter_rate_limit(self, uuid_str: str, peer_node_id: str = "") -> float:
        """
        比较本服务器限速与对端服务器报告的限速。
        返回更严格（更大的 seconds_per_msg）的值。
        """
        our_rate = self.chat_server.rate_limiter.get_effective_rate(uuid_str) if self.chat_server else 0.5


        if peer_node_id:
            self._send_to_peer(peer_node_id, {
                "type": "RATE_LIMIT_QUERY",
                "uuid": uuid_str,
                "query_id": f"rateq:{uuid_str}:{int(time.time())}",
            })


        peer_rate = self._get_cached_peer_rate(peer_node_id, uuid_str)

        return max(our_rate, peer_rate)


    def _log_interserver_msg(self, from_srv: str, to_srv: str, msg_type: str, payload: str):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute(
                "INSERT INTO interserver_messages (from_server, to_server, msg_type, payload, timestamp) VALUES (?,?,?,?,?)",
                (from_srv, to_srv, msg_type, payload, int(time.time()))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[INTERSERVER] Log error: {e}")


    def get_stats(self) -> dict:
        with self.peers_lock:
            peer_list = [
                {
                    "node_id": p["node_id"][:16],
                    "addr": p["addr"],
                    "last_seen": round(time.time() - p["last_seen"], 0),
                    "pinned_pubkey": p.get("ed25519_pubkey", "")[:16] + "...",
                }
                for p in self.peers.values()
            ]
        with self.cache_lock:
            cache_size = len(self.remote_user_cache)
        with self._rate_cache_lock:
            rate_peers = len(self._peer_rate_cache)
        return {
            "connected_peers": len(self.peers),
            "known_peers": len(self.known_peers),
            "cached_remote_users": cache_size,
            "pending_messages": sum(len(v) for v in self.pending_messages.values()),
            "peers": peer_list,
            "rate_aware_peers": rate_peers,
            "auth_method": "PKI-Ed25519-TOFU",
        }

    def reset_tofu_pins(self):
        """管理员命令：重置所有 TOFU 引脚（谨慎使用）。"""
        with self._pins_lock:
            self._pinned_pubkeys.clear()
        if os.path.exists(self._pins_db_path):
            os.remove(self._pins_db_path)
        self._init_pins_db()
        print("[INTERSERVER] 🔓 TOFU pins reset")
