"""
跨服务器联系人发现和群聊 — 客户端。

处理:
- 跨服务器添加联系人（通过 DHT/代理查找用户位置）
- 加入/创建联邦群组
- 向不同服务器上的用户发送消息
"""

import json
import time
import threading
from shared.protocol import *


class CrossServerClient:
    """
    跨服务器操作的客户端辅助函数。
    客户端与自己的服务器通信，由服务器代理跨服务器请求。
    """

    def __init__(self, tcp_client, identity: dict):
        self.tcp = tcp_client
        self.identity = identity
        self.uuid = identity["uuid"]
        self.contact_server_map: dict[str, str] = {}
        self.pending_lookups: dict[str, callable] = {}
        self.lock = threading.Lock()


    def lookup_remote_contact(self, uuid_or_query: str, callback=None):
        """
        请求本服务器查找用户（可能在其他服务器上）。
        服务器将检查 DHT 和已知对端。
        """
        self.tcp.send({
            "type": "LOOKUP_USER",
            "version": PROTOCOL_VERSION,
            "query": uuid_or_query,
            "from_uuid": self.uuid,
        })
        if callback:
            self.pending_lookups[uuid_or_query] = callback

    def handle_lookup_response(self, msg: dict):
        """处理来自服务器的 LOOKUP_USER_RESULT。"""
        query = msg.get("query", "")
        results = msg.get("results", [])
        with self.lock:
            for r in results:
                uuid_str = r.get("uuid", "")
                server_id = r.get("server_node_id", "")
                if uuid_str:
                    self.contact_server_map[uuid_str] = server_id
            callback = self.pending_lookups.pop(query, None)
        if callback:
            callback(results)


    def send_cross_server_message(self, to_uuid: str, encrypted_payload: dict,
                                  signature: str) -> bool:
        """
        向可能在其他服务器上的用户发送消息。
    服务器处理路由；客户端只需包含目标 UUID。
        Server will relay via inter-server protocol if needed.
        """
        try:
            self.tcp.send_message(to_uuid, encrypted_payload, signature)
            return True
        except Exception as e:
            print(f"[CROSS] Send failed: {e}")
            return False


    def create_group(self, name: str, member_uuids: list,
                     federated: bool = False, callback=None) -> bool:
        """请求服务器创建群组。"""
        self.tcp.send({
            "type": "CREATE_GROUP",
            "version": PROTOCOL_VERSION,
            "name": name,
            "members": member_uuids,
            "federated": federated,
            "from_uuid": self.uuid,
        })
        if callback:
            self._pending_create_group = callback
        return True

    def join_group(self, group_id: str, callback=None) -> bool:
        """请求加入群组（可能在其他服务器上）。"""
        self.tcp.send({
            "type": "JOIN_GROUP",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "from_uuid": self.uuid,
        })
        if callback:
            self._pending_join = callback
        return True

    def leave_group(self, group_id: str) -> bool:
        self.tcp.send({
            "type": "LEAVE_GROUP",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "from_uuid": self.uuid,
        })
        return True

    def add_to_group(self, group_id: str, target_uuid: str) -> bool:
        """向群组添加成员（仅群主/管理员）。"""
        self.tcp.send({
            "type": "GROUP_ADD_MEMBER",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "target_uuid": target_uuid,
            "from_uuid": self.uuid,
        })
        return True

    def remove_from_group(self, group_id: str, target_uuid: str) -> bool:
        self.tcp.send({
            "type": "GROUP_REMOVE_MEMBER",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "target_uuid": target_uuid,
            "from_uuid": self.uuid,
        })
        return True

    def send_group_message(self, group_id: str, encrypted_payload: dict,
                          signature: str) -> bool:
        """向群组发送消息。"""
        self.tcp.send({
            "type": "SEND_GROUP_MSG",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "encrypted_payload": encrypted_payload,
            "signature": signature,
            "from_uuid": self.uuid,
        })
        return True

    def list_my_groups(self) -> bool:
        self.tcp.send({
            "type": "LIST_MY_GROUPS",
            "version": PROTOCOL_VERSION,
            "from_uuid": self.uuid,
        })
        return True

    def get_group_info(self, group_id: str) -> bool:
        self.tcp.send({
            "type": "GET_GROUP_INFO",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "from_uuid": self.uuid,
        })
        return True

    def search_groups(self, query: str, scope: str = "global") -> bool:
        """按名称搜索群组。scope: local / global（通过 DHT）。"""
        self.tcp.send({
            "type": "SEARCH_GROUPS",
            "version": PROTOCOL_VERSION,
            "query": query,
            "scope": scope,
            "from_uuid": self.uuid,
        })
        return True

    def federate_group(self, group_id: str, target_server_node_id: str) -> bool:
        """将群组链接到远程服务器以实现跨服务器联邦。"""
        self.tcp.send({
            "type": "FEDERATE_GROUP",
            "version": PROTOCOL_VERSION,
            "group_id": group_id,
            "target_server": target_server_node_id,
            "from_uuid": self.uuid,
        })
        return True


    def handle_group_message(self, msg: dict):
        """处理接收到的 GROUP_MSG — 存储并显示。"""
        group_id = msg.get("group_id", "")
        from_uuid = msg.get("from_uuid", "")
        encrypted = msg.get("encrypted_payload", {})
        timestamp = msg.get("timestamp", int(time.time()))
        sender_server = msg.get("sender_server", "")


        if sender_server:
            with self.lock:
                self.contact_server_map[from_uuid] = sender_server

        return {
            "group_id": group_id,
            "from_uuid": from_uuid,
            "encrypted_payload": encrypted,
            "timestamp": timestamp,
        }

    def handle_group_event(self, msg: dict) -> dict:
        """处理 GROUP_EVENT（成员加入/离开、创建等）。"""
        return msg
