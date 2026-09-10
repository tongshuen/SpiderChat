"""
论坛消息处理器 — 挂钩到 ChatServer._process_message。

处理所有论坛相关消息类型：
POST_*, COMMENT_*, VOTE_*, SERVER_*, LOAD_*, CROSS_SERVER_*, NOTIFICATION_*, REPORT_*, DRAFT_*, FORUM_PROFILE_*

帖子附作者和服务器双层 Ed25519 签名。
所有请求带 nonce+timestamp，服务端重放保护。
错误响应格式 {"type":"ERROR","code":"...","message":"...","request_id":"..."}。
"""

import json
import time
import secrets
import threading
from server.forum.database import get_forum_db, now_ts
from server.forum import posts as posts_mod
from server.forum import comments as comments_mod
from server.forum import votes as votes_mod
from server.forum import server_card as server_card_mod
from server.forum import online as online_mod
from server.forum import rate_limit as rate_limit_mod
from server.forum import cross_server as cross_server_mod
from shared.crypto_utils import sign_data, load_ed25519_private
from shared.protocol import *


class ForumHandler:
    """论坛消息处理器。"""

    def __init__(self, chat_server):
        self.chat_server = chat_server
        self.node_id = chat_server.node_id
        self.server_priv_b64 = chat_server.server_ed25519_priv_b64
        self.server_pub_b64 = chat_server.server_ed25519_pub
        self.config = chat_server.config
        self.max_online = self.config.get("max_online", 100)
        self.heat_reference = self.config.get("heat_reference", 50.0)
        self.server_name = self.config.get("server_name", "Spider")
        self.server_tags = self.config.get("server_tags", ["安全的通信"])
        self.show_exact_online = self.config.get("show_exact_online", True)

        # 后台热度重算线程
        self._hot_recalc_thread = None
        self._running = False
        self._start_background_tasks()

    def _start_background_tasks(self):
        """启动后台任务（热度重算 5-10 分钟）。"""
        self._running = True
        self._hot_recalc_thread = threading.Thread(target=self._background_loop, daemon=True)
        self._hot_recalc_thread.start()

    def _background_loop(self):
        """后台循环：热度重算 + 负载更新。"""
        while self._running:
            try:
                posts_mod.recalc_hot_scores(limit=500)
                rate_limit_mod.update_load(self.max_online)
            except Exception:
                pass
            time.sleep(300)  # 5 分钟

    def stop(self):
        self._running = False

    def _sign_server(self, data: dict) -> str:
        """服务器签名。"""
        sign_content = json.dumps(data, sort_keys=True)
        priv = load_ed25519_private(self.server_priv_b64)
        return sign_data(priv, sign_content.encode())

    def _send_error(self, conn, code: str, message: str, request_id: str = ""):
        """发送错误响应。"""
        self.chat_server._send_raw(conn, {
            "type": ERROR_MSG,
            "code": code,
            "message": message,
            "request_id": request_id,
        })

    def _get_conn_uuid(self, conn) -> str:
        return getattr(conn, "uuid", "") or ""

    def _is_admin(self, conn) -> bool:
        return getattr(conn, "is_admin", False)

    def handle(self, conn, msg: dict) -> bool:
        """
        处理论坛消息。返回 True 表示已处理，False 表示非论坛消息。
        """
        msg_type = msg.get("type", "")
        request_id = msg.get("request_id", "")

        # 服务器信息请求（无需认证）
        if msg_type == SERVER_INFO_REQUEST:
            self._handle_server_info_request(conn)
            return True

        # 以下需要认证
        uuid_str = self._get_conn_uuid(conn)
        if not uuid_str and msg_type not in (SERVER_INFO_REQUEST,):
            self._send_error(conn, "AUTH_REQUIRED", "请先登录", request_id)
            return True

        # 负载限流检查
        is_admin = self._is_admin(conn)
        action_map = {
            POST_CREATE: "post", POST_EDIT: "post",
            COMMENT_CREATE: "post", COMMENT_EDIT: "post",
            POST_SEARCH: "search", POST_LIST: "search",
            POST_HOT_RANKING: "search",
            REGISTER: "register", LOGIN: "login",
        }
        action = action_map.get(msg_type, "message")
        allowed, delay, reason = rate_limit_mod.is_allowed(action, is_admin)
        if not allowed:
            self._send_error(conn, "RATE_LIMITED", reason, request_id)
            return True
        if delay > 0:
            time.sleep(delay)

        # 标记在线
        online_mod.mark_online(uuid_str, is_admin)

        # 路由
        handlers = {
            POST_CREATE: self._handle_post_create,
            POST_GET: self._handle_post_get,
            POST_LIST: self._handle_post_list,
            POST_DELETE: self._handle_post_delete,
            POST_EDIT: self._handle_post_edit,
            POST_SEARCH: self._handle_post_search,
            POST_HOT_RANKING: self._handle_post_hot_ranking,
            POST_WHY_RANKED: self._handle_post_why_ranked,
            COMMENT_CREATE: self._handle_comment_create,
            COMMENT_LIST: self._handle_comment_list,
            COMMENT_DELETE: self._handle_comment_delete,
            COMMENT_EDIT: self._handle_comment_edit,
            VOTE_CAST: self._handle_vote_cast,
            VOTE_GET: self._handle_vote_get,
            LOAD_STATUS_REQUEST: self._handle_load_status,
            SERVER_DIRECTORY_QUERY: self._handle_directory_query,
            SERVER_KNOWN_HOSTS: self._handle_known_hosts,
            NOTIFICATION_LIST: self._handle_notification_list,
            NOTIFICATION_MARK_READ: self._handle_notification_mark_read,
            REPORT_SUBMIT: self._handle_report_submit,
            DRAFT_SAVE: self._handle_draft_save,
            DRAFT_LIST: self._handle_draft_list,
            DRAFT_DELETE: self._handle_draft_delete,
            FORUM_PROFILE_GET: self._handle_forum_profile_get,
            FORUM_PROFILE_BLOCK: self._handle_forum_profile_block,
            FORUM_PROFILE_UNBLOCK: self._handle_forum_profile_unblock,
            CROSS_POST_FETCH: self._handle_cross_post_fetch,
        }

        handler = handlers.get(msg_type)
        if handler:
            try:
                handler(conn, msg, request_id)
            except Exception as e:
                self._send_error(conn, "INTERNAL_ERROR", str(e), request_id)
            return True

        return False

    # ===== 服务器卡片 =====

    def _handle_server_info_request(self, conn):
        """SERVER_INFO_REQUEST — 无需认证，返回服务器卡片。"""
        online_count = online_mod.get_online_count() if self.show_exact_online else -1

        # 读取默认头像
        avatar_b64 = ""
        try:
            import os
            from client.utils.config import get_data_dir
            avatar_path = os.path.join(get_data_dir(), "..", "..", "assets", "default_avatar.png")
            if os.path.exists(avatar_path):
                import base64
                with open(avatar_path, "rb") as f:
                    avatar_b64 = base64.b64encode(f.read()).decode()
        except Exception:
            pass

        card = server_card_mod.build_server_card(
            node_id=self.node_id,
            name=self.server_name,
            avatar_b64=avatar_b64,
            tags=self.server_tags,
            host=self.config.get("server_host", "0.0.0.0"),
            tcp_port=self.chat_server.port,
            dht_port=self.config.get("dht_port", 7892),
            online_count=online_count,
            max_online=self.max_online,
            heat_reference=self.heat_reference,
            public_key=self.server_pub_b64,
            protocol_version=PROTOCOL_VERSION,
            software_version=SOFTWARE_VERSION,
            server_priv_key_b64=self.server_priv_b64,
        )
        self.chat_server._send_raw(conn, {"type": SERVER_INFO_RESPONSE, "card": card})

    # ===== 帖子 =====

    def _handle_post_create(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        title = msg.get("title", "")
        content = msg.get("content", "")
        tags = msg.get("tags", [])
        author_sig = msg.get("author_signature", "")
        author_pubkey = msg.get("author_pubkey", "")

        ok, err = posts_mod.validate_post(title, content, tags)
        if not ok:
            self._send_error(conn, "INVALID_POST", err, request_id)
            return

        # 服务器签名
        post_data = {
            "title": title.strip(), "content": content,
            "tags": ",".join(t.strip() for t in tags if t.strip()),
            "author_uuid": uuid_str,
        }
        server_sig = self._sign_server(post_data)

        post = posts_mod.create_post(
            node_id=self.node_id, author_uuid=uuid_str,
            title=title, content=content, tags=tags,
            author_signature=author_sig, server_signature=server_sig,
            author_pubkey=author_pubkey,
        )
        self.chat_server._send_raw(conn, {"type": POST_CREATE_RESULT, "post": post, "request_id": request_id})

    def _handle_post_get(self, conn, msg, request_id):
        post_id = msg.get("id", "")
        # 跨服寻址
        post, source, error = cross_server_mod.resolve_post(
            post_id, self.node_id,
            dht_store=getattr(self.chat_server, "store", None),
            cross_server_conn=getattr(self.chat_server, "cross_server", None),
        )
        if error:
            self._send_error(conn, "POST_NOT_FOUND", error, request_id)
            return
        self.chat_server._send_raw(conn, {"type": POST_GET_RESULT, "post": post, "source": source, "request_id": request_id})

    def _handle_post_list(self, conn, msg, request_id):
        sort = msg.get("sort", "hot")
        limit = min(int(msg.get("limit", 20)), 100)
        offset = int(msg.get("offset", 0))
        tag = msg.get("tag", "")
        author = msg.get("author_uuid", "")
        posts = posts_mod.list_posts(sort=sort, limit=limit, offset=offset, tag=tag, author_uuid=author)
        self.chat_server._send_raw(conn, {"type": POST_LIST_RESULT, "posts": posts, "request_id": request_id})

    def _handle_post_delete(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        post_id = msg.get("id", "")
        is_admin = self._is_admin(conn)
        ok = posts_mod.delete_post(post_id, deleted_by=uuid_str, is_admin=is_admin)
        if not ok:
            self._send_error(conn, "DELETE_FAILED", "删除失败（无权限或帖子不存在）", request_id)
            return
        self.chat_server._send_raw(conn, {"type": POST_DELETE_RESULT, "success": True, "request_id": request_id})

    def _handle_post_edit(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        post_id = msg.get("id", "")
        title = msg.get("title", "")
        content = msg.get("content", "")
        tags = msg.get("tags", [])
        author_sig = msg.get("author_signature", "")

        ok, err = posts_mod.validate_post(title, content, tags)
        if not ok:
            self._send_error(conn, "INVALID_POST", err, request_id)
            return

        post_data = {"title": title.strip(), "content": content, "tags": ",".join(tags)}
        server_sig = self._sign_server(post_data)

        post = posts_mod.edit_post(post_id, uuid_str, title, content, tags, author_sig, server_sig)
        if not post:
            self._send_error(conn, "EDIT_FAILED", "编辑失败", request_id)
            return
        self.chat_server._send_raw(conn, {"type": POST_EDIT_RESULT, "post": post, "request_id": request_id})

    def _handle_post_search(self, conn, msg, request_id):
        query = msg.get("query", "")
        limit = min(int(msg.get("limit", 20)), 100)
        offset = int(msg.get("offset", 0))
        posts = posts_mod.search_posts(query, limit=limit, offset=offset)
        self.chat_server._send_raw(conn, {"type": POST_SEARCH_RESULT, "posts": posts, "query": query, "request_id": request_id})

    def _handle_post_hot_ranking(self, conn, msg, request_id):
        limit = min(int(msg.get("limit", 20)), 100)
        posts = posts_mod.list_posts(sort="hot", limit=limit)
        self.chat_server._send_raw(conn, {"type": POST_HOT_RANKING_RESULT, "posts": posts, "request_id": request_id})

    def _handle_post_why_ranked(self, conn, msg, request_id):
        post_id = msg.get("id", "")
        breakdown = posts_mod.why_ranked(post_id)
        if not breakdown:
            self._send_error(conn, "POST_NOT_FOUND", "帖子不存在", request_id)
            return
        self.chat_server._send_raw(conn, {"type": POST_WHY_RANKED_RESULT, "breakdown": breakdown, "request_id": request_id})

    # ===== 评论 =====

    def _handle_comment_create(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        post_id = msg.get("post_id", "")
        content = msg.get("content", "")
        parent_id = msg.get("parent_id", "")
        author_sig = msg.get("author_signature", "")
        author_pubkey = msg.get("author_pubkey", "")

        comment_data = {"post_id": post_id, "content": content, "author_uuid": uuid_str}
        server_sig = self._sign_server(comment_data)

        comment = comments_mod.create_comment(
            self.node_id, post_id, uuid_str, content, parent_id,
            author_sig, server_sig, author_pubkey,
        )
        if not comment:
            self._send_error(conn, "COMMENT_FAILED", "评论失败", request_id)
            return
        self.chat_server._send_raw(conn, {"type": COMMENT_CREATE_RESULT, "comment": comment, "request_id": request_id})

    def _handle_comment_list(self, conn, msg, request_id):
        post_id = msg.get("post_id", "")
        result = comments_mod.list_comments(post_id)
        self.chat_server._send_raw(conn, {"type": COMMENT_LIST_RESULT, **result, "request_id": request_id})

    def _handle_comment_delete(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        comment_id = msg.get("id", "")
        is_admin = self._is_admin(conn)
        ok = comments_mod.delete_comment(comment_id, uuid_str, is_admin)
        if not ok:
            self._send_error(conn, "DELETE_FAILED", "删除失败", request_id)
            return
        self.chat_server._send_raw(conn, {"type": COMMENT_DELETE_RESULT, "success": True, "request_id": request_id})

    def _handle_comment_edit(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        comment_id = msg.get("id", "")
        content = msg.get("content", "")
        author_sig = msg.get("author_signature", "")
        server_sig = self._sign_server({"content": content})
        comment = comments_mod.edit_comment(comment_id, uuid_str, content, author_sig, server_sig)
        if not comment:
            self._send_error(conn, "EDIT_FAILED", "编辑失败", request_id)
            return
        self.chat_server._send_raw(conn, {"type": COMMENT_EDIT_RESULT, "comment": comment, "request_id": request_id})

    # ===== 投票 =====

    def _handle_vote_cast(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        target_type = msg.get("target_type", "post")
        target_id = msg.get("target_id", "")
        value = int(msg.get("value", 0))
        result = votes_mod.cast_vote(uuid_str, target_type, target_id, value)
        self.chat_server._send_raw(conn, {"type": VOTE_CAST_RESULT, **result, "request_id": request_id})

    def _handle_vote_get(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        target_type = msg.get("target_type", "post")
        target_id = msg.get("target_id", "")
        value = votes_mod.get_user_vote(uuid_str, target_type, target_id)
        self.chat_server._send_raw(conn, {"type": VOTE_GET_RESULT, "value": value, "request_id": request_id})

    # ===== 负载 =====

    def _handle_load_status(self, conn, msg, request_id):
        status = rate_limit_mod.get_current_status()
        status["online_count"] = online_mod.get_online_count() if self.show_exact_online else -1
        status["max_online"] = self.max_online
        status["heat_level"] = server_card_mod.calculate_heat_level(status["online_count"], self.heat_reference)
        status["heat_level_text"] = server_card_mod.heat_level_text(status["heat_level"])
        self.chat_server._send_raw(conn, {"type": LOAD_STATUS, **status, "request_id": request_id})

    # ===== 目录 =====

    def _handle_directory_query(self, conn, msg, request_id):
        servers = server_card_mod.list_known_servers()
        self.chat_server._send_raw(conn, {"type": SERVER_DIRECTORY_RESULT, "servers": servers, "request_id": request_id})

    def _handle_known_hosts(self, conn, msg, request_id):
        servers = server_card_mod.list_known_servers()
        self.chat_server._send_raw(conn, {"type": SERVER_KNOWN_HOSTS, "servers": servers, "request_id": request_id})

    # ===== 跨服 =====

    def _handle_cross_post_fetch(self, conn, msg, request_id):
        """服→服：按 ID 拉取帖子。"""
        post_id = msg.get("post_id", "")
        post = posts_mod.get_post(post_id)
        if not post:
            self._send_error(conn, "POST_NOT_FOUND", "帖子不存在", request_id)
            return
        self.chat_server._send_raw(conn, {"type": CROSS_POST_FETCH_RESULT, "post": post, "request_id": request_id})

    # ===== 通知 =====

    def _handle_notification_list(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        db = get_forum_db()
        rows = db.execute("""
            SELECT * FROM notifications WHERE user_uuid=? ORDER BY created_at DESC LIMIT 50
        """, (uuid_str,)).fetchall()
        self.chat_server._send_raw(conn, {"type": NOTIFICATION_LIST_RESULT, "notifications": [dict(r) for r in rows], "request_id": request_id})

    def _handle_notification_mark_read(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        notif_id = msg.get("id", 0)
        db = get_forum_db()
        if notif_id:
            db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_uuid=?", (notif_id, uuid_str))
        else:
            db.execute("UPDATE notifications SET is_read=1 WHERE user_uuid=?", (uuid_str,))
        db.commit()
        self.chat_server._send_raw(conn, {"type": NOTIFICATION_PUSH, "success": True, "request_id": request_id})

    # ===== 举报 =====

    def _handle_report_submit(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        target_type = msg.get("target_type", "")
        target_id = msg.get("target_id", "")
        reason = msg.get("reason", "")
        db = get_forum_db()
        ts = now_ts()
        db.execute("""
            INSERT INTO reports (reporter_uuid, target_type, target_id, reason, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (uuid_str, target_type, target_id, reason, ts))
        db.commit()
        self.chat_server._send_raw(conn, {"type": REPORT_SUBMIT_RESULT, "success": True, "request_id": request_id})

    # ===== 草稿 =====

    def _handle_draft_save(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        draft_id = msg.get("id", f"draft:{secrets.token_hex(16)}")
        title = msg.get("title", "")
        content = msg.get("content", "")
        tags = ",".join(msg.get("tags", []))
        draft_type = msg.get("draft_type", "post")
        reply_to = msg.get("reply_to", "")
        ts = now_ts()
        db = get_forum_db()
        db.execute("""
            INSERT OR REPLACE INTO drafts (id, user_uuid, title, content, tags, draft_type, reply_to, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (draft_id, uuid_str, title, content, tags, draft_type, reply_to, ts))
        db.commit()
        self.chat_server._send_raw(conn, {"type": DRAFT_SAVE, "id": draft_id, "success": True, "request_id": request_id})

    def _handle_draft_list(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        db = get_forum_db()
        rows = db.execute("SELECT * FROM drafts WHERE user_uuid=? ORDER BY updated_at DESC", (uuid_str,)).fetchall()
        self.chat_server._send_raw(conn, {"type": DRAFT_LIST_RESULT, "drafts": [dict(r) for r in rows], "request_id": request_id})

    def _handle_draft_delete(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        draft_id = msg.get("id", "")
        db = get_forum_db()
        db.execute("DELETE FROM drafts WHERE id=? AND user_uuid=?", (draft_id, uuid_str))
        db.commit()
        self.chat_server._send_raw(conn, {"type": DRAFT_DELETE, "success": True, "request_id": request_id})

    # ===== 论坛用户资料 =====

    def _handle_forum_profile_get(self, conn, msg, request_id):
        target_uuid = msg.get("uuid", self._get_conn_uuid(conn))
        db = get_forum_db()
        # 聚合多服数据
        post_count = db.execute("SELECT COUNT(*) as c FROM posts WHERE author_uuid=? AND deleted=0", (target_uuid,)).fetchone()["c"]
        comment_count = db.execute("SELECT COUNT(*) as c FROM comments WHERE author_uuid=? AND deleted=0", (target_uuid,)).fetchone()["c"]
        total_upvotes = db.execute("SELECT COALESCE(SUM(upvotes),0) as s FROM posts WHERE author_uuid=? AND deleted=0", (target_uuid,)).fetchone()["s"]
        prefs = db.execute("SELECT * FROM user_preferences WHERE user_uuid=?", (target_uuid,)).fetchone()
        self.chat_server._send_raw(conn, {
            "type": FORUM_PROFILE_RESULT,
            "uuid": target_uuid,
            "post_count": post_count,
            "comment_count": comment_count,
            "total_upvotes": total_upvotes,
            "preferences": dict(prefs) if prefs else {},
            "request_id": request_id,
        })

    def _handle_forum_profile_block(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        target_uuid = msg.get("uuid", "")
        db = get_forum_db()
        ts = now_ts()
        row = db.execute("SELECT blocked_users FROM user_preferences WHERE user_uuid=?", (uuid_str,)).fetchone()
        blocked = row["blocked_users"].split(",") if row and row["blocked_users"] else []
        if target_uuid not in blocked:
            blocked.append(target_uuid)
        if row:
            db.execute("UPDATE user_preferences SET blocked_users=?, updated_at=? WHERE user_uuid=?",
                      (",".join(blocked), ts, uuid_str))
        else:
            db.execute("""
                INSERT INTO user_preferences (user_uuid, blocked_users, created_at, updated_at)
                VALUES (?, ?, ?, ?)
            """, (uuid_str, ",".join(blocked), ts, ts))
        db.commit()
        self.chat_server._send_raw(conn, {"type": FORUM_PROFILE_BLOCK, "success": True, "request_id": request_id})

    def _handle_forum_profile_unblock(self, conn, msg, request_id):
        uuid_str = self._get_conn_uuid(conn)
        target_uuid = msg.get("uuid", "")
        db = get_forum_db()
        ts = now_ts()
        row = db.execute("SELECT blocked_users FROM user_preferences WHERE user_uuid=?", (uuid_str,)).fetchone()
        if row and row["blocked_users"]:
            blocked = [u for u in row["blocked_users"].split(",") if u != target_uuid]
            db.execute("UPDATE user_preferences SET blocked_users=?, updated_at=? WHERE user_uuid=?",
                      (",".join(blocked), ts, uuid_str))
            db.commit()
        self.chat_server._send_raw(conn, {"type": FORUM_PROFILE_UNBLOCK, "success": True, "request_id": request_id})
