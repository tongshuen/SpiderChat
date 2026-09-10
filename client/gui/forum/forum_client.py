"""
论坛网络客户端 — 封装 TCPClient 发送论坛消息。
"""

import time
import secrets
from shared.protocol import *


class ForumClient:
    """论坛消息发送封装。"""

    def __init__(self, tcp_client):
        self.tcp = tcp_client
        self._pending = {}
        self._callbacks = {}

    def _request_id(self):
        return f"forum_{secrets.token_hex(8)}"

    def _send(self, msg_type: str, **kwargs) -> str:
        rid = self._request_id()
        msg = {"type": msg_type, "request_id": rid, **kwargs}
        self.tcp.send(msg)
        return rid

    # ===== 服务器卡片 =====

    def request_server_info(self):
        """请求服务器卡片（无需认证）。"""
        return self._send(SERVER_INFO_REQUEST)

    # ===== 帖子 =====

    def create_post(self, title: str, content: str, tags: list,
                    author_signature: str = "", author_pubkey: str = ""):
        return self._send(POST_CREATE, title=title, content=content,
                          tags=tags, author_signature=author_signature,
                          author_pubkey=author_pubkey)

    def get_post(self, post_id: str):
        return self._send(POST_GET, id=post_id)

    def list_posts(self, sort: str = "hot", limit: int = 20, offset: int = 0,
                    tag: str = "", author_uuid: str = ""):
        return self._send(POST_LIST, sort=sort, limit=limit, offset=offset,
                          tag=tag, author_uuid=author_uuid)

    def delete_post(self, post_id: str):
        return self._send(POST_DELETE, id=post_id)

    def edit_post(self, post_id: str, title: str, content: str, tags: list,
                  author_signature: str = ""):
        return self._send(POST_EDIT, id=post_id, title=title, content=content,
                          tags=tags, author_signature=author_signature)

    def search_posts(self, query: str, limit: int = 20, offset: int = 0):
        return self._send(POST_SEARCH, query=query, limit=limit, offset=offset)

    def hot_ranking(self, limit: int = 20):
        return self._send(POST_HOT_RANKING, limit=limit)

    def why_ranked(self, post_id: str):
        return self._send(POST_WHY_RANKED, id=post_id)

    # ===== 评论 =====

    def create_comment(self, post_id: str, content: str, parent_id: str = "",
                       author_signature: str = "", author_pubkey: str = ""):
        return self._send(COMMENT_CREATE, post_id=post_id, content=content,
                          parent_id=parent_id, author_signature=author_signature,
                          author_pubkey=author_pubkey)

    def list_comments(self, post_id: str):
        return self._send(COMMENT_LIST, post_id=post_id)

    def delete_comment(self, comment_id: str):
        return self._send(COMMENT_DELETE, id=comment_id)

    def edit_comment(self, comment_id: str, content: str, author_signature: str = ""):
        return self._send(COMMENT_EDIT, id=comment_id, content=content,
                          author_signature=author_signature)

    # ===== 投票 =====

    def cast_vote(self, target_type: str, target_id: str, value: int):
        return self._send(VOTE_CAST, target_type=target_type, target_id=target_id, value=value)

    def get_vote(self, target_type: str, target_id: str):
        return self._send(VOTE_GET, target_type=target_type, target_id=target_id)

    # ===== 负载 =====

    def load_status(self):
        return self._send(LOAD_STATUS_REQUEST)

    # ===== 目录 =====

    def directory_query(self):
        return self._send(SERVER_DIRECTORY_QUERY)

    def known_hosts(self):
        return self._send(SERVER_KNOWN_HOSTS)

    # ===== 通知 =====

    def list_notifications(self):
        return self._send(NOTIFICATION_LIST)

    def mark_notification_read(self, notif_id: int = 0):
        return self._send(NOTIFICATION_MARK_READ, id=notif_id)

    # ===== 举报 =====

    def submit_report(self, target_type: str, target_id: str, reason: str):
        return self._send(REPORT_SUBMIT, target_type=target_type, target_id=target_id, reason=reason)

    # ===== 草稿 =====

    def save_draft(self, title: str, content: str, tags: list, draft_type: str = "post",
                   reply_to: str = "", draft_id: str = ""):
        return self._send(DRAFT_SAVE, id=draft_id, title=title, content=content,
                          tags=tags, draft_type=draft_type, reply_to=reply_to)

    def list_drafts(self):
        return self._send(DRAFT_LIST)

    def delete_draft(self, draft_id: str):
        return self._send(DRAFT_DELETE, id=draft_id)

    # ===== 论坛资料 =====

    def get_forum_profile(self, uuid: str = ""):
        return self._send(FORUM_PROFILE_GET, uuid=uuid)

    def block_user(self, uuid: str):
        return self._send(FORUM_PROFILE_BLOCK, uuid=uuid)

    def unblock_user(self, uuid: str):
        return self._send(FORUM_PROFILE_UNBLOCK, uuid=uuid)
