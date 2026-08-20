"""
消息中继 — 在在线用户之间转发加密消息。
离线消息委托给 OfflineStore。
消息送达时向发送方发送送达回执（DELIVERY_RECEIPT）。
"""

import json
import time
import uuid as uuid_module
from shared.protocol import *

class MessageRelay:
    """处理聊天消息的实际中继逻辑。"""

    def __init__(self, chat_server):
        self.server = chat_server

    def relay_message(self, from_uuid: str, to_uuid: str,
                     encrypted_payload: dict, signature: str,
                     original_timestamp: int = None) -> dict:
        """
        将加密消息从 from_uuid 转发给 to_uuid。
        如果接收方在线，立即投递并发送送达回执给发送方。
        返回状态字典，包含 server_msg_id 用于客户端追踪。
        """
        target_conn = self.server.connections.get(to_uuid)
        msg_id = str(uuid_module.uuid4())

        if target_conn:
            # 接收方在线，立即投递
            msg = {
                "type": RECV_MSG,
                "from_uuid": from_uuid,
                "to_uuid": to_uuid,
                "encrypted_payload": encrypted_payload,
                "timestamp": int(time.time()),
                "server_msg_id": msg_id,
            }
            self.server._send_raw(target_conn, msg)
            self.server.stats["messages_relayed"] += 1

            # 向发送方发送送达回执
            self._send_delivery_receipt(from_uuid, to_uuid, msg_id,
                                        encrypted_payload.get("timestamp", int(time.time())))

            return {"status": "delivered", "msg_id": msg_id,
                    "timestamp": msg["timestamp"]}
        else:
            # 接收方离线，存入离线队列
            offline_msg = {
                "type": RECV_MSG,
                "from_uuid": from_uuid,
                "to_uuid": to_uuid,
                "encrypted_payload": encrypted_payload,
                "timestamp": int(time.time()),
                "server_msg_id": msg_id,
            }
            self.server.offline_store.add_message(to_uuid, offline_msg)
            return {"status": "queued_offline", "msg_id": msg_id,
                    "timestamp": int(time.time())}

    def _send_delivery_receipt(self, from_uuid: str, to_uuid: str,
                                msg_id: str, original_ts: int):
        """
        向发送方发送 DELIVERY_RECEIPT，通知消息已送达接收方。
        """
        sender_conn = self.server.connections.get(from_uuid)
        if not sender_conn:
            return  # 发送方已离线，无需回执

        receipt = {
            "type": DELIVERY_RECEIPT,
            "to_uuid": to_uuid,
            "msg_id": msg_id,
            "original_timestamp": original_ts,
            "delivered_at": int(time.time()),
        }
        self.server._send_raw(sender_conn, receipt)

    def deliver_offline_queue(self, uuid: str, conn):
        """
        用户登录时发送所有排队的离线消息。
        对每条消息，同时向原始发送方补发送达回执。
        """
        messages = self.server.offline_store.get_messages(uuid)
        delivered_count = 0
        for msg in messages:
            self.server._send_raw(conn, msg)
            delivered_count += 1

            # 补发送达回执给原始发送方
            from_uuid = msg.get("from_uuid", "")
            msg_id = msg.get("server_msg_id", "")
            if from_uuid and msg_id:
                self._send_delivery_receipt(
                    from_uuid, uuid, msg_id,
                    msg.get("encrypted_payload", {}).get("timestamp", int(time.time()))
                )

        if delivered_count > 0:
            self.server.offline_store.clear_messages(uuid)
        return delivered_count
