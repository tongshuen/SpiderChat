"""
与聊天服务器通信的 TCP 客户端。
处理连接、发送/接收 JSON 消息和回调（含回执）。
"""

import socket
import json
import threading
import base64
import time
import hashlib
from shared.protocol import *


class TCPClient:
    """与服务器的持久 TCP 连接。"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None
        self.connected = False
        self._recv_thread = None
        self._stop = False

        # 回调
        self.on_message = None
        self.on_admin_result = None
        self.on_offline_queue = None
        self.on_broadcast = None
        self.on_error = None
        self.on_disconnect = None
        self.on_register_ok = None
        self.on_login_ok = None
        self.on_pubkey_result = None
        self.on_rate_limited = None
        self.on_compromised_ack = None
        self.on_deadman_ack = None
        self.on_group_message = None
        self.on_group_event = None
        self.on_lookup_result = None
        self.on_group_list_result = None
        self.on_group_info_result = None
        self.on_group_search_result = None
        self.on_group_create_result = None
        # 回执回调
        self.on_delivery_receipt = None
        self.on_read_receipt = None
        self.on_read_receipt_disabled = None

    # ===== 连接管理 =====

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.connected = True
        self._stop = False
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def disconnect(self):
        self._stop = True
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.on_disconnect:
            self.on_disconnect()

    def _recv_loop(self):
        buf = b""
        while not self._stop and self.sock:
            try:
                data = self.sock.recv(65536)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if line.strip():
                        self._handle_message(line.decode("utf-8"))
            except Exception as e:
                if not self._stop:
                    if self.on_error:
                        self.on_error(str(e))
                break
        self.connected = False
        if self.on_disconnect and not self._stop:
            self.on_disconnect()

    # ===== 消息分发 =====

    def _handle_message(self, raw_json: str):
        try:
            msg = json.loads(raw_json)
        except json.JSONDecodeError:
            return

        msg_type = msg.get("type")

        # 回执优先匹配
        if msg_type == DELIVERY_RECEIPT:
            if self.on_delivery_receipt:
                self.on_delivery_receipt(msg)
            return
        elif msg_type == READ_RECEIPT:
            if self.on_read_receipt:
                self.on_read_receipt(msg)
            return
        elif msg_type == READ_RECEIPT_DISABLED:
            if self.on_read_receipt_disabled:
                self.on_read_receipt_disabled(msg)
            return

        # 标准消息
        if msg_type == RECV_MSG:
            if self.on_message:
                self.on_message(msg)
        elif msg_type == OFFLINE_QUEUE:
            if self.on_offline_queue:
                self.on_offline_queue(msg.get("messages", []))
        elif msg_type == ADMIN_AUTH_OK:
            if self.on_admin_result:
                self.on_admin_result({"type": "auth_ok", "token": msg.get("token")})
        elif msg_type == ADMIN_AUTH_FAIL:
            if self.on_admin_result:
                self.on_admin_result({"type": "auth_fail", "reason": msg.get("reason")})
        elif msg_type == CMD_RESULT:
            if self.on_admin_result:
                self.on_admin_result(msg.get("result"))
        elif msg_type == RATE_LIMITED:
            if self.on_rate_limited:
                self.on_rate_limited(msg.get("reason", ""))
        elif msg_type == BROADCAST:
            if self.on_broadcast:
                self.on_broadcast(msg)
        elif msg_type == ERROR_MSG:
            if self.on_error:
                self.on_error(msg.get("message", "Unknown error"))
        elif msg_type == "REGISTER_OK":
            if self.on_register_ok:
                self.on_register_ok(msg)
        elif msg_type == "LOGIN_OK":
            if self.on_login_ok:
                self.on_login_ok(msg)
        elif msg_type == "PUBKEY_RESULT":
            if self.on_pubkey_result:
                self.on_pubkey_result(msg)
        elif msg_type == "COMPROMISED_ACK":
            if self.on_compromised_ack:
                self.on_compromised_ack(msg)
        elif msg_type == DEADMAN_ACK:
            if self.on_deadman_ack:
                self.on_deadman_ack(msg)
        elif msg_type == GROUP_EVENT:
            if self.on_group_event:
                self.on_group_event(msg)
        elif msg_type == GROUP_MSG:
            if self.on_group_message:
                self.on_group_message(msg)
        elif msg_type == LOOKUP_USER_RESULT:
            if self.on_lookup_result:
                self.on_lookup_result(msg)
        elif msg_type == GROUP_LIST_RESULT:
            if self.on_group_list_result:
                self.on_group_list_result(msg)
        elif msg_type == GROUP_INFO_RESULT:
            if self.on_group_info_result:
                self.on_group_info_result(msg)
        elif msg_type == GROUP_SEARCH_RESULT:
            if self.on_group_search_result:
                self.on_group_search_result(msg)
        elif msg_type == GROUP_CREATE_RESULT:
            if self.on_group_create_result:
                self.on_group_create_result(msg)

    # ===== 发送方法 =====

    def send(self, msg: dict):
        if not self.sock or not self.connected:
            raise RuntimeError("Not connected")
        raw = json.dumps(msg) + "\n"
        self.sock.sendall(raw.encode("utf-8"))

    def register(self, uuid_str: str, x_pub_b64: str, e_pub_b64: str, signature: str):
        self.send({
            "type": REGISTER,
            "version": PROTOCOL_VERSION,
            "uuid": uuid_str,
            "x25519_public": x_pub_b64,
            "ed25519_public": e_pub_b64,
            "signature": signature,
        })

    def login(self, uuid_str: str, e_pub_b64: str, signature: str):
        self.send({
            "type": LOGIN,
            "version": PROTOCOL_VERSION,
            "uuid": uuid_str,
            "ed25519_public": e_pub_b64,
            "signature": signature,
        })

    def send_message(self, to_uuid: str, encrypted_payload: dict,
                     signature: str, client_msg_id: str = ""):
        """发送消息（带客户端消息 ID 用于回执追踪）。"""
        msg = {
            "type": SEND_MSG,
            "version": PROTOCOL_VERSION,
            "to_uuid": to_uuid,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
        }
        if client_msg_id:
            msg["client_msg_id"] = client_msg_id
        self.send(msg)

    def query_pubkey(self, target_uuid: str):
        self.send({
            "type": QUERY_PUBKEY,
            "version": PROTOCOL_VERSION,
            "target_uuid": target_uuid,
        })

    def send_compromised(self, uuid_str: str, signature: str):
        self.send({
            "type": COMPROMISED,
            "version": PROTOCOL_VERSION,
            "uuid": uuid_str,
            "signature": signature,
        })

    def send_deadman_message(self, uuid_str: str, recipient_uuid: str,
                              message_text: str, grace_period_sec: int):
        """
        发送死人开关警告消息到服务器存储。
        服务器将其作为特殊离线消息存储，覆盖旧的，到期用户未登录时触发。
        """
        self.send({
            "type": STORE_DEADMAN_MSG,
            "version": PROTOCOL_VERSION,
            "uuid": uuid_str,
            "recipient_uuid": recipient_uuid,
            "message_text": message_text,
            "grace_period_sec": grace_period_sec,
        })

    def admin_auth(self, pin: str, signature: str):
        self.send({
            "type": ADMIN_AUTH,
            "version": PROTOCOL_VERSION,
            "pin": pin,
            "signature": signature,
        })

    def admin_cmd(self, token: str, command: str, params: dict = None):
        self.send({
            "type": ADMIN_CMD,
            "version": PROTOCOL_VERSION,
            "token": token,
            "command": command,
            "params": params or {},
        })

    def search_contacts(self, query: str, scope: str = "local"):
        self.send({
            "type": SEARCH_CONTACTS,
            "version": PROTOCOL_VERSION,
            "query": query,
            "scope": scope,
        })

    def ping(self):
        self.send({"type": PING, "timestamp": int(time.time())})

    def send_raw_json(self, msg: dict):
        """发送任意 JSON（用于回执等）。"""
        self.send(msg)
