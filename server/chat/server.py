"""
聊天 TCP 服务器 — 处理客户端连接、消息中继、注册、回执。
"""

import socket
import ssl
import threading
import json
import time
import base64
import hashlib
import sqlite3
import os
from collections import defaultdict, OrderedDict

from shared.protocol import *
from shared.crypto_utils import (
    verify_signature, load_ed25519_public,
    sign_data, node_id_from_pubkey
)
from server.config.loader import get_data_dir
from server.chat.relay import MessageRelay
from server.chat.offline import OfflineStore
from server.chat.group import GroupManager
from server.chat.cross_server import CrossServerRelay
from server.user.manager import UserManager
from server.rate_limit.token_bucket import RateLimiter
from server.admin.auth import AdminAuth
from server.admin.commands import AdminCommandHandler
from server.config.loader import load_config
from server.keyring_store.credentials import (
    get_server_keys, verify_admin_pin, get_node_id
)
from server.keyring_store import get_keyring_service


class ClientConnection:
    """表示已连接的客户端。"""

    def __init__(self, sock: socket.socket, addr: tuple):
        self.sock = sock
        self.addr = addr
        self.uuid = None
        self.x25519_pub = None
        self.ed25519_pub = None
        self.node_id = None
        self.authenticated = False
        self.last_seen = time.time()
        self.send_lock = threading.Lock()
        self.compromised = False
        self._nonce_cache: OrderedDict = OrderedDict()
        # 已读回执开关（默认开启）
        self.read_receipts_enabled = True


class ChatServer:
    """TCP 聊天主服务器。"""

    def __init__(self, config: dict):
        self.config = config
        self.host = "0.0.0.0"
        self.port = config.get("tcp_port", DEFAULT_TCP_PORT)

        self.user_manager = UserManager(config)
        self.relay = MessageRelay(self)
        self.group_manager = GroupManager(config, chat_server=self)
        self.offline_store = OfflineStore(config)
        self.rate_limiter = RateLimiter(config)
        self.admin_auth = AdminAuth(config)
        self.admin_handler = AdminCommandHandler(self, config)
        self.cross_server = None

        keys = get_server_keys()
        self.server_x25519_priv = None
        self.server_x25519_pub = keys["server_x25519_pub"]
        self.server_ed25519_priv_b64 = keys["server_ed25519_priv"]
        self.server_ed25519_pub = keys["server_ed25519_pub"]
        self.node_id = get_node_id()

        self.connections: dict[str, ClientConnection] = {}
        self.sock_by_addr: dict = {}
        self.lock = threading.Lock()

        self._nonce_db_path = os.path.join(get_data_dir(), "replay_nonces.db")
        self._init_nonce_db()
        self.nonce_lock = threading.Lock()
        self.recent_nonces: OrderedDict = OrderedDict()
        self._NONCE_CACHE_MAX = 10000
        self._REPLAY_WINDOW = REPLAY_WINDOW_SEC

        # 每个消息的发送方追踪：server_msg_id → from_uuid
        self.msg_sender_map: dict[str, str] = {}
        self.msg_lock = threading.Lock()

        # 消息计数器（用于生成 server_msg_id）
        self._msg_counter = 0
        self._msg_counter_lock = threading.Lock()

        self.stats = {
            "total_connections": 0,
            "messages_relayed": 0,
            "bytes_sent": 0,
            "bytes_recv": 0,
            "cross_server_relayed": 0,
            "group_messages": 0,
            "delivery_receipts_sent": 0,
            "read_receipts_forwarded": 0,
            "start_time": time.time(),
        }

        self._sock = None
        self._running = False

    def _gen_server_msg_id(self) -> str:
        """生成唯一的服务器消息 ID。"""
        with self._msg_counter_lock:
            self._msg_counter += 1
            return f"smid_{int(time.time())}_{self._msg_counter}"

    def _init_nonce_db(self):
        db_dir = os.path.dirname(self._nonce_db_path)
        os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(self._nonce_db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS seen_nonces (
                nonce_hash TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                uuid TEXT NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON seen_nonces(timestamp)")
        conn.commit()
        conn.close()
        self._cleanup_old_nonces()

    def _cleanup_old_nonces(self):
        cutoff = int(time.time()) - self._REPLAY_WINDOW * 2
        conn = sqlite3.connect(self._nonce_db_path)
        c = conn.cursor()
        c.execute("DELETE FROM seen_nonces WHERE timestamp < ?", (cutoff,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            print(f"[REPLAY] Cleaned {deleted} old nonces from DB")

    def _check_and_store_nonce(self, nonce_str: str, uuid_str: str) -> bool:
        with self.nonce_lock:
            if nonce_str in self.recent_nonces:
                return False
            if len(self.recent_nonces) >= self._NONCE_CACHE_MAX:
                trim = self._NONCE_CACHE_MAX // 4
                for _ in range(trim):
                    self.recent_nonces.popitem(last=False)

        nonce_hash = hashlib.sha256(nonce_str.encode("utf-8")).hexdigest()
        now = int(time.time())
        conn = sqlite3.connect(self._nonce_db_path)
        c = conn.cursor()
        c.execute("SELECT 1 FROM seen_nonces WHERE nonce_hash = ?", (nonce_hash,))
        row = c.fetchone()
        if row:
            conn.close()
            with self.nonce_lock:
                self.recent_nonces[nonce_str] = now
                self.recent_nonces.move_to_end(nonce_str)
            return False

        c.execute(
            "INSERT INTO seen_nonces (nonce_hash, timestamp, uuid) VALUES (?, ?, ?)",
            (nonce_hash, now, uuid_str)
        )
        if now % 100 < 2:
            cutoff = now - self._REPLAY_WINDOW * 2
            c.execute("DELETE FROM seen_nonces WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()

        with self.nonce_lock:
            self.recent_nonces[nonce_str] = now
            self.recent_nonces.move_to_end(nonce_str)

        return True

    # ===== 启动 / 停止 =====

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(100)
        self._running = True

        print(f"[CHAT] TCP server listening on {self.host}:{self.port}")
        print(f"[CHAT] NodeID: {self.node_id}")

        threading.Thread(target=self._maintenance_loop, daemon=True).start()

        while self._running:
            try:
                client_sock, addr = self._sock.accept()
                threading.Thread(target=self._handle_client, args=(client_sock, addr), daemon=True).start()
                self.stats["total_connections"] += 1
            except Exception as e:
                if self._running:
                    print(f"[CHAT] Accept error: {e}")

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except:
                pass
        with self.lock:
            for conn in self.connections.values():
                try:
                    conn.sock.close()
                except:
                    pass

    # ===== 客户端处理 =====

    def _handle_client(self, sock: socket.socket, addr: tuple):
        conn = ClientConnection(sock, addr)
        self.sock_by_addr[id(sock)] = conn
        buf = b""

        try:
            sock.settimeout(300)
            while self._running:
                try:
                    data = sock.recv(65536)
                    if not data:
                        break
                    self.stats["bytes_recv"] += len(data)
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        if line.strip():
                            self._process_message(conn, line.decode("utf-8"))
                except socket.timeout:
                    self._send_raw(conn, {"type": PING, "timestamp": int(time.time())})
                except Exception as e:
                    print(f"[CHAT] Client error from {addr}: {e}")
                    break
        finally:
            self._disconnect_client(conn)

    def _process_message(self, conn: ClientConnection, raw_json: str):
        try:
            msg = json.loads(raw_json)
        except json.JSONDecodeError:
            self._send_error(conn, "Invalid JSON")
            return

        msg_type = msg.get("type")
        conn.last_seen = time.time()

        ts = msg.get("timestamp", 0)
        if abs(time.time() - ts) > REPLAY_WINDOW_SEC:
            self._send_error(conn, "Message too old or from future")
            return

        # 路由分发
        if msg_type == REGISTER:
            self._handle_register(conn, msg)
        elif msg_type == LOGIN:
            self._handle_login(conn, msg)
        elif msg_type == SEND_MSG:
            self._handle_send_message(conn, msg)
        elif msg_type == QUERY_PUBKEY:
            self._handle_query_pubkey(conn, msg)
        elif msg_type == STORE_PUBKEY:
            self._handle_store_pubkey(conn, msg)
        elif msg_type == COMPROMISED:
            self._handle_compromised(conn, msg)
        elif msg_type == STORE_DEADMAN_MSG:
            self._handle_store_deadman(conn, msg)
        elif msg_type == ADMIN_AUTH:
            self._handle_admin_auth(conn, msg)
        elif msg_type == ADMIN_CMD:
            self._handle_admin_cmd(conn, msg)
        elif msg_type == SEARCH_CONTACTS:
            self._handle_search(conn, msg)
        elif msg_type == LOOKUP_USER:
            self._handle_lookup_user(conn, msg)
        elif msg_type == CREATE_GROUP:
            self._handle_create_group(conn, msg)
        elif msg_type == JOIN_GROUP:
            self._handle_join_group(conn, msg)
        elif msg_type == LEAVE_GROUP:
            self._handle_leave_group(conn, msg)
        elif msg_type == GROUP_ADD_MEMBER:
            self._handle_group_add_member(conn, msg)
        elif msg_type == GROUP_REMOVE_MEMBER:
            self._handle_group_remove_member(conn, msg)
        elif msg_type == SEND_GROUP_MSG:
            self._handle_send_group_message(conn, msg)
        elif msg_type == LIST_MY_GROUPS:
            self._handle_list_my_groups(conn, msg)
        elif msg_type == GET_GROUP_INFO:
            self._handle_get_group_info(conn, msg)
        elif msg_type == SEARCH_GROUPS:
            self._handle_search_groups(conn, msg)
        elif msg_type == FEDERATE_GROUP:
            self._handle_federate_group(conn, msg)
        elif msg_type == DELIVERY_RECEIPT:
            self._handle_delivery_receipt(conn, msg)
        elif msg_type == READ_RECEIPT:
            self._handle_read_receipt(conn, msg)
        elif msg_type == READ_RECEIPT_DISABLED:
            self._handle_read_receipt_disabled(conn, msg)
        elif msg_type == PING:
            self._send_raw(conn, {"type": PONG, "timestamp": int(time.time())})
        elif msg_type == PONG:
            conn.last_seen = time.time()
        else:
            self._send_error(conn, f"Unknown message type: {msg_type}")

    # ===== 注册 / 登录 =====

    def _handle_register(self, conn: ClientConnection, msg: dict):
        uuid_str = msg.get("uuid", "")
        x_pub = msg.get("x25519_public", "")
        e_pub = msg.get("ed25519_public", "")
        signature = msg.get("signature", "")

        if not uuid_str or not x_pub or not e_pub:
            self._send_error(conn, "Missing required fields for REGISTER")
            return

        sig_data = json.dumps({
            "type": REGISTER, "uuid": uuid_str,
            "x25519_public": x_pub, "ed25519_public": e_pub,
        }, sort_keys=True).encode()

        try:
            e_pub_key = load_ed25519_public(e_pub)
            if not verify_signature(e_pub_key, sig_data, signature):
                self._send_error(conn, "Signature verification failed")
                return
        except Exception as e:
            self._send_error(conn, f"Key parsing error: {e}")
            return

        if self.user_manager.is_banned(uuid_str):
            self._send_error(conn, "This UUID is banned")
            return

        client_version = msg.get("version", 0)
        min_version = self.config.get("user_management", {}).get("min_client_version", "1.0.0")
        if client_version < 1:
            self._send_error(conn, f"Client version too old. Min: {min_version}")
            return

        max_conn = self.config.get("user_management", {}).get("max_connections", 1000)
        with self.lock:
            active = len(self.connections)
        if active >= max_conn:
            self._send_error(conn, "Server full")
            return

        self.user_manager.register_user(uuid_str, x_pub, e_pub, conn.addr[0])

        if hasattr(self, 'dht_node') and self.dht_node:
            value = json.dumps({
                "uuid": uuid_str, "x25519_pub": x_pub, "ed25519_pub": e_pub,
                "host": conn.addr[0], "last_seen": int(time.time()),
            })
            self.dht_node.store(f"user:{uuid_str}", value)

        self._send_raw(conn, {"type": "REGISTER_OK", "uuid": uuid_str})
        print(f"[CHAT] Registered: {uuid_str[:16]}... from {conn.addr}")

    def _handle_login(self, conn: ClientConnection, msg: dict):
        uuid_str = msg.get("uuid", "")
        e_pub = msg.get("ed25519_public", "")
        signature = msg.get("signature", "")
        nonce = msg.get("nonce", "")

        if not uuid_str:
            self._send_error(conn, "Missing UUID")
            return

        if nonce:
            if not self._check_and_store_nonce(nonce, uuid_str):
                self._send_error(conn, "Replay detected — nonce already used")
                return

        user = self.user_manager.get_user(uuid_str)
        if not user:
            self._send_error(conn, "UUID not registered. Please register first.")
            return

        db_e_pub = user.get("ed25519_pub", "")
        if not db_e_pub:
            self._send_error(conn, "No public key on file for this UUID")
            return

        sig_data = json.dumps({
            "type": LOGIN, "uuid": uuid_str, "ed25519_public": db_e_pub,
            "nonce": nonce,
        }, sort_keys=True).encode()

        try:
            e_pub_key = load_ed25519_public(db_e_pub)
            if not verify_signature(e_pub_key, sig_data, signature):
                self._send_error(conn, "Signature verification failed")
                print(f"[CHAT] 🚫 Login signature INVALID for {uuid_str[:16]}...")
                return
        except Exception as e:
            self._send_error(conn, f"Key parsing error: {e}")
            return

        if self.user_manager.is_banned(uuid_str):
            self._send_error(conn, "This UUID is banned")
            return

        if e_pub and e_pub != db_e_pub:
            print(f"[CHAT] ⚠️ Client-provided pubkey differs from stored for {uuid_str[:16]}...")

        conn.uuid = uuid_str
        conn.ed25519_pub = db_e_pub
        conn.x25519_pub = user.get("x25519_pub", "")
        conn.authenticated = True

        # 读取用户偏好（已读回执开关）
        conn.read_receipts_enabled = user.get("read_receipts_enabled", True)

        with self.lock:
            if uuid_str in self.connections:
                old = self.connections[uuid_str]
                try:
                    old.sock.close()
                except:
                    pass
            self.connections[uuid_str] = conn

        self.user_manager.update_last_seen(uuid_str, conn.addr[0])

        offline = self.offline_store.get_messages(uuid_str)
        if offline:
            self._send_raw(conn, {"type": OFFLINE_QUEUE, "messages": offline})
            self.offline_store.clear_messages(uuid_str)

        self._send_raw(conn, {"type": "LOGIN_OK", "uuid": uuid_str})
        print(f"[CHAT] Login: {uuid_str[:16]}... from {conn.addr}")

    # ===== 核心：消息发送 + 回执 =====

    def _handle_send_message(self, conn: ClientConnection, msg: dict):
        """处理 SEND_MSG，立即发送送达回执给发送方。"""
        if not conn.authenticated:
            self._send_error(conn, "Not authenticated")
            return

        to_uuid = msg.get("to_uuid", "")
        encrypted = msg.get("encrypted_payload", {})
        signature = msg.get("signature", "")
        client_msg_id = msg.get("client_msg_id", "")

        if not to_uuid:
            self._send_error(conn, "Missing to_uuid")
            return

        if not self.rate_limiter.allow(conn.uuid):
            self._send_raw(conn, {"type": RATE_LIMITED, "reason": "Too many messages"})
            return

        # 验证签名
        env = {"type": SEND_MSG, "to_uuid": to_uuid, "encrypted_payload": encrypted}
        env_sig_data = json.dumps(env, sort_keys=True).encode()
        try:
            e_pub_key = load_ed25519_public(conn.ed25519_pub)
            if not verify_signature(e_pub_key, env_sig_data, signature):
                self._send_error(conn, "Signature verification failed")
                return
        except:
            self._send_error(conn, "Signature error")
            return

        if self.user_manager.is_blocked(conn.uuid, to_uuid):
            self._send_error(conn, "Recipient is blocked")
            return

        # 生成服务器消息 ID
        server_msg_id = self._gen_server_msg_id()

        # 记录发送方映射
        with self.msg_lock:
            self.msg_sender_map[server_msg_id] = conn.uuid

        target_conn = self.connections.get(to_uuid)

        if target_conn:
            # 在线 → 立即转发 + 发送送达回执
            relay_msg = {
                "type": RECV_MSG,
                "from_uuid": conn.uuid,
                "to_uuid": to_uuid,
                "encrypted_payload": encrypted,
                "timestamp": int(time.time()),
                "server_msg_id": server_msg_id,
                "client_msg_id": client_msg_id,
            }
            self._send_raw(target_conn, relay_msg)
            self.stats["messages_relayed"] += 1

            # 🔔 立即给发送方发送「送达回执」
            self._send_raw(conn, {
                "type": DELIVERY_RECEIPT,
                "server_msg_id": server_msg_id,
                "client_msg_id": client_msg_id,
                "to_uuid": to_uuid,
                "timestamp": int(time.time()),
                "status": "delivered",
            })
            self.stats["delivery_receipts_sent"] += 1

            # 检查接收方是否关闭了已读回执
            if not target_conn.read_receipts_enabled:
                self._send_raw(conn, {
                    "type": READ_RECEIPT_DISABLED,
                    "server_msg_id": server_msg_id,
                    "client_msg_id": client_msg_id,
                    "to_uuid": to_uuid,
                    "reason": "对方已关闭已读回执功能",
                })

            self._send_raw(conn, {"type": SEND_OK, "timestamp": int(time.time())})

        else:
            # 离线 → 存入离线队列
            target_user = self.user_manager.get_user(to_uuid)
            if target_user:
                relay_msg = {
                    "type": RECV_MSG,
                    "from_uuid": conn.uuid,
                    "to_uuid": to_uuid,
                    "encrypted_payload": encrypted,
                    "timestamp": int(time.time()),
                    "server_msg_id": server_msg_id,
                    "client_msg_id": client_msg_id,
                }
                self.offline_store.add_message(to_uuid, relay_msg)
                self.stats["messages_relayed"] += 1

                # 离线也算「已送达」（服务器已接收并存储）
                self._send_raw(conn, {
                    "type": DELIVERY_RECEIPT,
                    "server_msg_id": server_msg_id,
                    "client_msg_id": client_msg_id,
                    "to_uuid": to_uuid,
                    "timestamp": int(time.time()),
                    "status": "queued_offline",
                })
                self.stats["delivery_receipts_sent"] += 1

                self._send_raw(conn, {"type": SEND_OK,
                                      "timestamp": int(time.time()),
                                      "queued": "offline"})
            else:
                if self.cross_server:
                    result = self.cross_server.relay_message(
                        conn.uuid, to_uuid, encrypted, signature
                    )
                    if result.get("status") == "delivered":
                        self.stats["cross_server_relayed"] += 1
                        self._send_raw(conn, {
                            "type": DELIVERY_RECEIPT,
                            "server_msg_id": server_msg_id,
                            "client_msg_id": client_msg_id,
                            "to_uuid": to_uuid,
                            "timestamp": int(time.time()),
                            "status": "delivered_cross_server",
                        })
                        self._send_raw(conn, {"type": SEND_OK,
                                              "timestamp": int(time.time()),
                                              "via": "cross_server"})
                    elif result.get("status") == "queued":
                        self._send_raw(conn, {"type": SEND_OK,
                                              "timestamp": int(time.time()),
                                              "queued": result.get("reason", "pending")})
                    elif result.get("status") == "rate_limited":
                        self._send_raw(conn, {"type": RATE_LIMITED,
                                              "reason": "Cross-server rate limit"})
                    else:
                        self._send_error(conn, f"User not found: {to_uuid}")
                else:
                    self._send_error(conn, f"User not found: {to_uuid}")

    # ===== 回执处理 =====

    def _handle_delivery_receipt(self, conn: ClientConnection, msg: dict):
        """
        接收方发来的「送达确认」（确认已收到 RECV_MSG）。
        这里服务器作为中转，将回执转发给原始发送方。
        """
        server_msg_id = msg.get("server_msg_id", "")
        from_uuid = msg.get("from_uuid", "")  # 原始发送方
        timestamp = msg.get("timestamp", int(time.time()))

        if not from_uuid:
            # 从映射中查找
            with self.msg_lock:
                from_uuid = self.msg_sender_map.get(server_msg_id, "")

        if from_uuid:
            sender_conn = self.connections.get(from_uuid)
            if sender_conn:
                self._send_raw(sender_conn, {
                    "type": DELIVERY_RECEIPT,
                    "server_msg_id": server_msg_id,
                    "timestamp": timestamp,
                    "status": "delivered",
                })
                self.stats["delivery_receipts_sent"] += 1

    def _handle_read_receipt(self, conn: ClientConnection, msg: dict):
        """
        接收方发来的「已读回执」。
        转发给原始发送方。
        """
        server_msg_id = msg.get("server_msg_id", "")
        client_msg_id = msg.get("client_msg_id", "")
        from_uuid = msg.get("from_uuid", "")

        if not from_uuid:
            with self.msg_lock:
                from_uuid = self.msg_sender_map.get(server_msg_id, "")

        if from_uuid:
            sender_conn = self.connections.get(from_uuid)
            if sender_conn:
                self._send_raw(sender_conn, {
                    "type": READ_RECEIPT,
                    "server_msg_id": server_msg_id,
                    "client_msg_id": client_msg_id,
                    "from_uuid": conn.uuid,
                    "timestamp": int(time.time()),
                })
                self.stats["read_receipts_forwarded"] += 1
                print(f"[CHAT] 📖 Read receipt: {server_msg_id} → {from_uuid[:16]}...")

    def _handle_read_receipt_disabled(self, conn: ClientConnection, msg: dict):
        """
        接收方通知服务器其已读回执已关闭。
        服务器转发通知给发送方。
        """
        server_msg_id = msg.get("server_msg_id", "")
        from_uuid = msg.get("from_uuid", "")

        if not from_uuid:
            with self.msg_lock:
                from_uuid = self.msg_sender_map.get(server_msg_id, "")

        if from_uuid:
            sender_conn = self.connections.get(from_uuid)
            if sender_conn:
                self._send_raw(sender_conn, {
                    "type": READ_RECEIPT_DISABLED,
                    "server_msg_id": server_msg_id,
                    "reason": msg.get("reason", "对方已关闭已读回执"),
                    "timestamp": int(time.time()),
                })

    # ===== 公钥查询 =====

    def _handle_query_pubkey(self, conn: ClientConnection, msg: dict):
        target_uuid = msg.get("target_uuid", "")
        if not target_uuid:
            self._send_error(conn, "Missing target_uuid")
            return

        value = None
        if hasattr(self, 'dht_node') and self.dht_node:
            value = self.dht_node.get(f"user:{target_uuid}")

        if not value:
            user = self.user_manager.get_user(target_uuid)
            if user:
                value = json.dumps(user)

        if value:
            try:
                data = json.loads(value)
                self._send_raw(conn, {
                    "type": "PUBKEY_RESULT",
                    "uuid": target_uuid,
                    "x25519_public": data.get("x25519_pub", ""),
                    "ed25519_public": data.get("ed25519_pub", ""),
                })
                return
            except:
                pass

        self._send_error(conn, f"Public key for {target_uuid} not found")

    def _handle_store_pubkey(self, conn: ClientConnection, msg: dict):
        if not conn.authenticated:
            self._send_error(conn, "Not authenticated")
            return
        if hasattr(self, 'dht_node') and self.dht_node:
            value = json.dumps({
                "uuid": conn.uuid,
                "x25519_pub": conn.x25519_pub,
                "ed25519_pub": conn.ed25519_pub,
            })
            self.dht_node.store(f"user:{conn.uuid}", value)
            self._send_raw(conn, {"type": "STORE_OK"})
        else:
            self._send_error(conn, "DHT not available")

    # ===== 胁迫 / 管理员 =====

    def _handle_compromised(self, conn: ClientConnection, msg: dict):
        uuid_str = msg.get("uuid", "")
        signature = msg.get("signature", "")
        if not uuid_str:
            return
        self.user_manager.mark_compromised(uuid_str)
        print(f"[CHAT] ⚠️ COMPROMISED: {uuid_str[:16]}...")
        with self.lock:
            if uuid_str in self.connections:
                try:
                    self.connections[uuid_str].sock.close()
                except:
                    pass
                del self.connections[uuid_str]
        self._send_raw(conn, {"type": "COMPROMISED_ACK", "uuid": uuid_str})

    def _handle_store_deadman(self, conn: ClientConnection, msg: dict):
        """
        处理客户端存储死人开关警告消息的请求。
        消息字段：uuid, recipient_uuid, message_text, grace_period_sec
        服务器将其作为特殊离线消息存储，覆盖该用户上一条旧的警告消息。
        暂时不推送给任何用户，等到期用户未登录时再触发。
        """
        uuid_str = msg.get("uuid", "")
        recipient_uuid = msg.get("recipient_uuid", "")
        message_text = msg.get("message_text", "")
        grace_period_sec = int(msg.get("grace_period_sec", 7 * 86400))
        if not uuid_str or not recipient_uuid or not message_text:
            self._send_error(conn, "Missing uuid/recipient_uuid/message_text")
            return
        if grace_period_sec < 3600:
            grace_period_sec = 3600  # 最少1小时
        self.offline_store.store_deadman_message(
            uuid_str, recipient_uuid, message_text, grace_period_sec
        )
        print(f"[CHAT] 📝 Deadman message stored: {uuid_str[:16]}... -> {recipient_uuid[:16]}... "
              f"(grace={grace_period_sec // 86400}d)")
        self._send_raw(conn, {"type": DEADMAN_ACK, "uuid": uuid_str, "stored": True})

    def _handle_admin_auth(self, conn: ClientConnection, msg: dict):
        pin = msg.get("pin", "")
        signature = msg.get("signature", "")
        if not pin:
            self._send_raw(conn, {"type": ADMIN_AUTH_FAIL, "reason": "No PIN"})
            return
        if not verify_admin_pin(pin):
            self._send_raw(conn, {"type": ADMIN_AUTH_FAIL, "reason": "Wrong PIN"})
            return
        token = self.admin_auth.create_session(conn.addr[0])
        self._send_raw(conn, {"type": ADMIN_AUTH_OK, "token": token})
        print(f"[ADMIN] Authenticated from {conn.addr}")

    def _handle_admin_cmd(self, conn: ClientConnection, msg: dict):
        token = msg.get("token", "")
        command = msg.get("command", "")
        params = msg.get("params", {})
        if not self.admin_auth.validate_session(token):
            self._send_raw(conn, {"type": ADMIN_AUTH_FAIL, "reason": "Invalid/expired token"})
            return
        result = self.admin_handler.execute(command, params, conn)
        self._send_raw(conn, {"type": CMD_RESULT, "result": result})

    # ===== 搜索 / 查找 =====

    def _handle_search(self, conn: ClientConnection, msg: dict):
        query = msg.get("query", "").strip()
        scope = msg.get("scope", "local")
        if not query:
            self._send_raw(conn, {"type": "SEARCH_RESULT", "results": []})
            return
        results = []
        if scope in ("local", "server"):
            users = self.user_manager.search_users(query)
            results.extend(users)
        if scope == "global" and hasattr(self, 'dht_node') and self.dht_node:
            try:
                for k in list(self.dht_node._store.keys()):
                    if k.startswith("user_location:"):
                        uuid_part = k.replace("user_location:", "")
                        if query.lower() in uuid_part.lower():
                            raw = self.dht_node.get(k)
                            if raw:
                                try:
                                    ud = json.loads(raw)
                                    ud["uuid"] = uuid_part
                                    ud["location"] = "dht"
                                    results.append(ud)
                                except Exception:
                                    pass
            except Exception as e:
                print(f"[CHAT] DHT global search error: {e}")
        self._send_raw(conn, {"type": "SEARCH_RESULT", "results": results})

    def _handle_lookup_user(self, conn: ClientConnection, msg: dict):
        query = msg.get("query", "").strip()
        results = []
        if hasattr(self, 'dht_node') and self.dht_node:
            try:
                for k in list(self.dht_node._store.keys()):
                    if k.startswith("user_location:"):
                        uuid_part = k.replace("user_location:", "")
                        if query.lower() in uuid_part.lower():
                            raw = self.dht_node.get(k)
                            if raw:
                                try:
                                    ud = json.loads(raw)
                                    ud["uuid"] = uuid_part
                                    ud["location"] = "dht"
                                    results.append(ud)
                                except:
                                    pass
            except Exception as e:
                print(f"[CHAT] DHT lookup error: {e}")
        self._send_raw(conn, {"type": LOOKUP_USER_RESULT, "query": query, "results": results})

    # ===== 群组 =====

    def _handle_create_group(self, conn: ClientConnection, msg: dict):
        name = msg.get("name", "")
        members = msg.get("members", [])
        federated = msg.get("federated", False)
        if not name:
            self._send_raw(conn, {"type": GROUP_CREATE_RESULT, "status": "error", "reason": "No name"})
            return
        result = self.group_manager.create_group(name, conn.uuid, members, federated)
        self._send_raw(conn, {"type": GROUP_CREATE_RESULT, "status": "created",
                              "group_id": result.get("group_id", ""), "name": name})

    def _handle_join_group(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        result = self.group_manager.join_group(group_id, conn.uuid)
        self._send_raw(conn, {"type": "JOIN_GROUP_RESULT", "result": result})

    def _handle_leave_group(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        result = self.group_manager.leave_group(group_id, conn.uuid)
        self._send_raw(conn, {"type": "LEAVE_GROUP_RESULT", "result": result})

    def _handle_group_add_member(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        target = msg.get("target_uuid", "")
        result = self.group_manager.add_member(group_id, conn.uuid, target)
        self._send_raw(conn, {"type": "GROUP_ADD_RESULT", "result": result})

    def _handle_group_remove_member(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        target = msg.get("target_uuid", "")
        result = self.group_manager.remove_member(group_id, conn.uuid, target)
        self._send_raw(conn, {"type": "GROUP_REMOVE_RESULT", "result": result})

    def _handle_send_group_message(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        encrypted = msg.get("encrypted_payload", {})
        signature = msg.get("signature", "")
        if not self.rate_limiter.allow(conn.uuid):
            self._send_raw(conn, {"type": RATE_LIMITED, "reason": "Too many messages"})
            return
        result = self.group_manager.send_message(group_id, conn.uuid, encrypted, signature)
        if result.get("ok"):
            self.stats["group_messages"] += 1
            self._send_raw(conn, {"type": SEND_OK, "timestamp": int(time.time())})
        else:
            self._send_error(conn, result.get("reason", "Group send failed"))

    def _handle_list_my_groups(self, conn: ClientConnection, msg: dict):
        groups = self.group_manager.list_my_groups(conn.uuid)
        self._send_raw(conn, {"type": GROUP_LIST_RESULT, "groups": groups})

    def _handle_get_group_info(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        info = self.group_manager.get_group_info(group_id)
        self._send_raw(conn, {"type": GROUP_INFO_RESULT, "group": info.get("group", {}),
                              "members": info.get("members", [])})

    def _handle_search_groups(self, conn: ClientConnection, msg: dict):
        query = msg.get("query", "").strip()
        results = self.group_manager.search_groups(query)
        self._send_raw(conn, {"type": GROUP_SEARCH_RESULT, "results": results})

    def _handle_federate_group(self, conn: ClientConnection, msg: dict):
        group_id = msg.get("group_id", "")
        target_server = msg.get("target_server", "")
        result = self.group_manager.federate_group(group_id, target_server)
        self._send_raw(conn, {"type": "FEDERATE_RESULT", "result": result})

    # ===== 维护 =====

    def _maintenance_loop(self):
        while self._running:
            time.sleep(60)
            try:
                self.offline_store.cleanup_expired()
                self._check_and_trigger_deadman()
                with self.lock:
                    dead = []
                    for uuid_str, c in self.connections.items():
                        if time.time() - c.last_seen > 600:
                            dead.append(uuid_str)
                    for uuid_str in dead:
                        try:
                            self.connections[uuid_str].sock.close()
                        except:
                            pass
                        del self.connections[uuid_str]
                        print(f"[CHAT] Timeout: {uuid_str[:16]}...")
                self.admin_auth.cleanup_sessions()
                with self.nonce_lock:
                    if len(self.recent_nonces) > 10000:
                        self.recent_nonces.clear()
            except Exception as e:
                print(f"[CHAT] Maintenance error: {e}")

    def _check_and_trigger_deadman(self):
        """检查所有已过期的死人开关消息并触发。"""
        try:
            expired = self.offline_store.get_expired_deadman_messages()
            for entry in expired:
                self._trigger_deadman(entry)
        except Exception as e:
            print(f"[CHAT] Deadman check error: {e}")

    def _trigger_deadman(self, entry: dict):
        """
        触发死人开关：先把警告消息推送给预定收件人，再执行胁迫密码的同款操作。
        这样哪怕客户端炸了，警告消息也能按时发送。
        """
        uuid_str = entry["uuid"]
        recipient_uuid = entry["recipient_uuid"]
        message_text = entry["message_text"]
        now = int(time.time())
        server_msg_id = self._gen_server_msg_id()

        print(f"[CHAT] 💀 DEADMAN TRIGGERED: {uuid_str[:16]}... -> {recipient_uuid[:16]}...")

        # 第一步：构造警告消息并推送给收件人（在线直接发，离线存为离线消息）
        warning_msg = {
            "type": RECV_MSG,
            "from_uuid": uuid_str,
            "to_uuid": recipient_uuid,
            "encrypted_payload": {},
            "timestamp": now,
            "server_msg_id": server_msg_id,
            "client_msg_id": f"deadman-{uuid_str[:8]}-{now}",
            "deadman_warning": True,
            "system_message": message_text,
        }

        target_conn = self.connections.get(recipient_uuid)
        if target_conn:
            self._send_raw(target_conn, warning_msg)
            print(f"[CHAT] 📨 Deadman warning delivered online to {recipient_uuid[:16]}...")
        else:
            target_user = self.user_manager.get_user(recipient_uuid)
            if target_user:
                self.offline_store.add_message(recipient_uuid, warning_msg)
                print(f"[CHAT] 📨 Deadman warning stored offline for {recipient_uuid[:16]}...")

        # 标记死人开关已触发（防止重复触发）
        self.offline_store.mark_deadman_triggered(uuid_str)

        # 第二步：执行胁迫密码的同款操作 — 标记为泄露/封禁 + 断开连接
        self.user_manager.mark_compromised(uuid_str)
        with self.lock:
            if uuid_str in self.connections:
                try:
                    self.connections[uuid_str].sock.close()
                except:
                    pass
                del self.connections[uuid_str]
        print(f"[CHAT] ⚠️ User marked COMPROMISED (deadman): {uuid_str[:16]}...")

    def _disconnect_client(self, conn: ClientConnection):
        try:
            conn.sock.close()
        except:
            pass
        with self.lock:
            if conn.uuid and conn.uuid in self.connections:
                if self.connections[conn.uuid] is conn:
                    del self.connections[conn.uuid]
        # 清理消息映射
        with self.msg_lock:
            to_remove = [k for k, v in self.msg_sender_map.items() if v == conn.uuid]
            for k in to_remove:
                del self.msg_sender_map[k]

    # ===== 工具方法 =====

    def _send_raw(self, conn: ClientConnection, msg: dict):
        """向指定客户端发送 JSON 消息（线程安全）。"""
        if not conn or not conn.sock:
            return
        raw = json.dumps(msg) + "\n"
        try:
            with conn.send_lock:
                conn.sock.sendall(raw.encode("utf-8"))
                self.stats["bytes_sent"] += len(raw)
        except Exception as e:
            print(f"[CHAT] Send error to {conn.addr}: {e}")

    def _send_error(self, conn: ClientConnection, message: str):
        self._send_raw(conn, {"type": ERROR_MSG, "message": message})
        print(f"[CHAT] Error sent: {message}")
