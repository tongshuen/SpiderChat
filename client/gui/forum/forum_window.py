"""
论坛主窗口 — 帖子列表、帖子详情、发帖、评论、投票、搜索、服务器卡片。

发帖页顶部醒目警示：帖子评论明文存储，管理员可查看删除导出，
等同于公开发布，不可否认，敏感信息请移步私聊。
"""

import customtkinter as ctk
from tkinter import messagebox
import time
from client.gui.forum.forum_client import ForumClient
from shared.protocol import *


class ForumWindow(ctk.CTkToplevel):
    """论坛主窗口。"""

    def __init__(self, master, tcp_client, user_uuid: str, user_pubkey: str = ""):
        super().__init__(master)
        self.title("Spider 论坛")
        self.geometry("900x700")
        self.minsize(700, 500)

        self.tcp = tcp_client
        self.forum = ForumClient(tcp_client)
        self.user_uuid = user_uuid
        self.user_pubkey = user_pubkey
        self.current_posts = []
        self.current_post = None
        self.current_comments = {"roots": [], "replies": {}}
        self.search_mode = False
        self.current_sort = "hot"

        # 注册消息回调
        self._setup_callbacks()

        self._build_ui()
        self._load_posts()

    def _setup_callbacks(self):
        """注册论坛消息回调。"""
        handler_map = {
            POST_LIST_RESULT: self._on_post_list,
            POST_GET_RESULT: self._on_post_get,
            POST_CREATE_RESULT: self._on_post_create,
            POST_DELETE_RESULT: self._on_post_delete,
            POST_EDIT_RESULT: self._on_post_edit,
            POST_SEARCH_RESULT: self._on_post_search,
            POST_HOT_RANKING_RESULT: self._on_post_list,
            POST_WHY_RANKED_RESULT: self._on_why_ranked,
            COMMENT_LIST_RESULT: self._on_comment_list,
            COMMENT_CREATE_RESULT: self._on_comment_create,
            COMMENT_DELETE_RESULT: self._on_comment_delete,
            VOTE_CAST_RESULT: self._on_vote_cast,
            VOTE_GET_RESULT: self._on_vote_get,
            SERVER_INFO_RESPONSE: self._on_server_info,
            LOAD_STATUS: self._on_load_status,
            SERVER_DIRECTORY_RESULT: self._on_directory,
            NOTIFICATION_LIST_RESULT: self._on_notifications,
            DRAFT_LIST_RESULT: self._on_drafts,
            FORUM_PROFILE_RESULT: self._on_profile,
            ERROR_MSG: self._on_error,
        }
        if hasattr(self.tcp, "add_callback"):
            for msg_type, cb in handler_map.items():
                self.tcp.add_callback(msg_type, cb)

    def _build_ui(self):
        """构建 UI。"""
        # 顶部工具栏
        toolbar = ctk.CTkFrame(self, height=50)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))

        ctk.CTkLabel(toolbar, text="Spider 论坛", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=10)

        # 搜索框
        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(toolbar, textvariable=self.search_var, width=200, placeholder_text="搜索帖子（本服）")
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<Return>", lambda e: self._do_search())

        ctk.CTkButton(toolbar, text="搜索", width=60, command=self._do_search).pack(side="left", padx=2)
        ctk.CTkButton(toolbar, text="全部", width=60, command=self._show_all).pack(side="left", padx=2)

        # 排序
        self.sort_var = ctk.StringVar(value="hot")
        sort_menu = ctk.CTkOptionMenu(toolbar, values=["hot", "new", "top"],
                                        variable=self.sort_var, width=80,
                                        command=lambda v: self._change_sort(v))
        sort_menu.pack(side="left", padx=10)

        # 发帖按钮
        ctk.CTkButton(toolbar, text="+ 发帖", width=80, fg_color="#2ecc71",
                      command=self._open_create_post).pack(side="right", padx=10)

        # 服务器状态标签
        self.status_label = ctk.CTkLabel(toolbar, text="", font=ctk.CTkFont(size=12))
        self.status_label.pack(side="right", padx=5)

        # 主内容区：左侧帖子列表，右侧帖子详情
        main = ctk.CTkFrame(self)
        main.pack(fill="both", expand=True, padx=10, pady=5)

        # 左侧帖子列表
        left = ctk.CTkFrame(main, width=350)
        left.pack(side="left", fill="y", padx=(0, 5))
        left.pack_propagate(False)

        ctk.CTkLabel(left, text="帖子列表", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)

        self.post_list_frame = ctk.CTkScrollableFrame(left)
        self.post_list_frame.pack(fill="both", expand=True, padx=5, pady=5)

        # 右侧帖子详情
        right = ctk.CTkFrame(main)
        right.pack(side="left", fill="both", expand=True, padx=(5, 0))

        self.detail_frame = ctk.CTkScrollableFrame(right)
        self.detail_frame.pack(fill="both", expand=True, padx=5, pady=5)

        ctk.CTkLabel(self.detail_frame, text="选择左侧帖子查看详情",
                     font=ctk.CTkFont(size=14)).pack(pady=50)

        # 底部状态栏
        self.bottom_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=11))
        self.bottom_label.pack(fill="x", padx=10, pady=(0, 5))

        # 请求服务器信息
        self.forum.request_server_info()
        self.forum.load_status()

    # ===== 帖子列表 =====

    def _load_posts(self):
        self.forum.list_posts(sort=self.current_sort, limit=50)

    def _change_sort(self, sort):
        self.current_sort = sort
        self.search_mode = False
        self._load_posts()

    def _do_search(self):
        query = self.search_var.get().strip()
        if not query:
            self._show_all()
            return
        self.search_mode = True
        self.forum.search_posts(query, limit=50)
        self.bottom_label.configure(text=f"搜索: {query}")

    def _show_all(self):
        self.search_mode = False
        self.search_var.set("")
        self._load_posts()
        self.bottom_label.configure(text="")

    def _on_post_list(self, msg):
        posts = msg.get("posts", [])
        self.current_posts = posts
        self._render_post_list(posts)

    def _on_post_search(self, msg):
        posts = msg.get("posts", [])
        self.current_posts = posts
        self._render_post_list(posts)

    def _render_post_list(self, posts):
        for w in self.post_list_frame.winfo_children():
            w.destroy()

        if not posts:
            ctk.CTkLabel(self.post_list_frame, text="暂无帖子").pack(pady=20)
            return

        for post in posts:
            self._render_post_item(post)

    def _render_post_item(self, post):
        frame = ctk.CTkFrame(self.post_list_frame, corner_radius=6)
        frame.pack(fill="x", pady=3, padx=2)

        title = ctk.CTkLabel(frame, text=post.get("title", "")[:50],
                             font=ctk.CTkFont(size=13, weight="bold"), anchor="w")
        title.pack(fill="x", padx=8, pady=(6, 2))
        title.bind("<Button-1>", lambda e, p=post: self._open_post(p))

        meta = ctk.CTkLabel(frame,
            text=f"↑{post.get('upvotes',0)} ↓{post.get('downvotes',0)} | 💬{post.get('comment_count',0)} | {self._fmt_time(post.get('created_at',0))}",
            font=ctk.CTkFont(size=11), anchor="w", text_color="gray")
        meta.pack(fill="x", padx=8, pady=(0, 6))
        meta.bind("<Button-1>", lambda e, p=post: self._open_post(p))

        if post.get("tags"):
            tag_label = ctk.CTkLabel(frame, text=f"#{post['tags'].replace(',', ' #')}",
                                     font=ctk.CTkFont(size=10), text_color="#3498db", anchor="w")
            tag_label.pack(fill="x", padx=8, pady=(0, 4))

    # ===== 帖子详情 =====

    def _open_post(self, post):
        self.current_post = post
        self.forum.get_post(post["id"])
        self.forum.list_comments(post["id"])

    def _on_post_get(self, msg):
        post = msg.get("post")
        if post:
            self.current_post = post
            self._render_post_detail(post)

    def _render_post_detail(self, post):
        for w in self.detail_frame.winfo_children():
            w.destroy()

        # 标题
        ctk.CTkLabel(self.detail_frame, text=post.get("title", ""),
                     font=ctk.CTkFont(size=18, weight="bold"), anchor="w", wraplength=500).pack(fill="x", padx=10, pady=(10, 5))

        # 元信息
        meta_text = f"作者: {post.get('author_uuid','')[:16]}... | {self._fmt_time(post.get('created_at',0))}"
        if post.get("edited"):
            meta_text += " (已编辑)"
        ctk.CTkLabel(self.detail_frame, text=meta_text, font=ctk.CTkFont(size=11),
                     text_color="gray", anchor="w").pack(fill="x", padx=10, pady=(0, 5))

        # 正文
        content_frame = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        content_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(content_frame, text=post.get("content", ""),
                     font=ctk.CTkFont(size=13), anchor="w", justify="left",
                     wraplength=520).pack(anchor="w")

        # 投票按钮
        vote_frame = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        vote_frame.pack(fill="x", padx=10, pady=10)

        self.upvote_btn = ctk.CTkButton(vote_frame, text=f"👍 {post.get('upvotes',0)}", width=80,
                                         command=lambda: self._vote("post", post["id"], 1))
        self.upvote_btn.pack(side="left", padx=2)

        self.downvote_btn = ctk.CTkButton(vote_frame, text=f"👎 {post.get('downvotes',0)}", width=80,
                                           fg_color="#e74c3c", command=lambda: self._vote("post", post["id"], -1))
        self.downvote_btn.pack(side="left", padx=2)

        ctk.CTkLabel(vote_frame, text=f"净投票: {post.get('net_votes',0)}",
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=10)

        # 为什么这个排名
        ctk.CTkButton(vote_frame, text="为什么这个排名", width=120, fg_color="gray",
                      command=lambda: self.forum.why_ranked(post["id"])).pack(side="right", padx=2)

        # 操作按钮（作者/管理员）
        if post.get("author_uuid") == self.user_uuid:
            op_frame = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
            op_frame.pack(fill="x", padx=10, pady=5)
            ctk.CTkButton(op_frame, text="编辑", width=60, command=lambda: self._edit_post(post)).pack(side="left", padx=2)
            ctk.CTkButton(op_frame, text="删除", width=60, fg_color="#e74c3c",
                          command=lambda: self._delete_post(post["id"])).pack(side="left", padx=2)

        # 评论区
        ctk.CTkLabel(self.detail_frame, text=f"评论 ({post.get('comment_count',0)})",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(15, 5))

        # 发表评论
        comment_input = ctk.CTkFrame(self.detail_frame)
        comment_input.pack(fill="x", padx=10, pady=5)
        self.comment_text = ctk.CTkTextbox(comment_input, height=60)
        self.comment_text.pack(fill="x", padx=5, pady=5)
        ctk.CTkButton(comment_input, text="发表评论", width=100,
                      command=lambda: self._submit_comment(post["id"])).pack(anchor="e", padx=5, pady=(0, 5))

        # 评论列表容器
        self.comments_container = ctk.CTkFrame(self.detail_frame, fg_color="transparent")
        self.comments_container.pack(fill="x", padx=10, pady=5)
        self._render_comments()

    def _render_comments(self):
        for w in self.comments_container.winfo_children():
            w.destroy()

        roots = self.current_comments.get("roots", [])
        replies = self.current_comments.get("replies", {})

        if not roots:
            ctk.CTkLabel(self.comments_container, text="暂无评论", text_color="gray").pack(pady=10)
            return

        for root in roots:
            self._render_comment(root, self.comments_container, depth=0)
            for reply in replies.get(root["id"], []):
                self._render_comment(reply, self.comments_container, depth=1)

    def _render_comment(self, comment, parent, depth=0):
        frame = ctk.CTkFrame(parent, corner_radius=4)
        frame.pack(fill="x", pady=2, padx=(depth * 20, 0))

        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=6, pady=(4, 0))

        author = comment.get("author_uuid", "")[:12] + "..."
        ctk.CTkLabel(header, text=author, font=ctk.CTkFont(size=11, weight="bold")).pack(side="left")
        ctk.CTkLabel(header, text=f" {self._fmt_time(comment.get('created_at',0))}",
                     font=ctk.CTkFont(size=10), text_color="gray").pack(side="left")
        if comment.get("edited"):
            ctk.CTkLabel(header, text=" (已编辑)", font=ctk.CTkFont(size=10), text_color="orange").pack(side="left")

        ctk.CTkLabel(frame, text=comment.get("content", ""), font=ctk.CTkFont(size=12),
                     anchor="w", justify="left", wraplength=480).pack(anchor="w", padx=6, pady=2)

        # 投票
        vf = ctk.CTkFrame(frame, fg_color="transparent")
        vf.pack(fill="x", padx=6, pady=(0, 4))
        ctk.CTkButton(vf, text=f"👍 {comment.get('net_votes',0)}", width=60, height=24,
                      command=lambda: self._vote("comment", comment["id"], 1)).pack(side="left", padx=2)
        ctk.CTkButton(vf, text="回复", width=50, height=24, fg_color="gray",
                      command=lambda c=comment: self._reply_to(c)).pack(side="left", padx=2)
        if comment.get("author_uuid") == self.user_uuid:
            ctk.CTkButton(vf, text="删除", width=50, height=24, fg_color="#e74c3c",
                          command=lambda cid=comment["id"]: self._delete_comment(cid)).pack(side="left", padx=2)

    # ===== 发帖 =====

    def _open_create_post(self):
        CreatePostDialog(self, self.forum, self.user_uuid, self.user_pubkey)

    def _on_post_create(self, msg):
        post = msg.get("post")
        if post:
            messagebox.showinfo("成功", "帖子发布成功！")
            self._load_posts()

    def _on_post_delete(self, msg):
        if msg.get("success"):
            messagebox.showinfo("成功", "帖子已删除")
            self.current_post = None
            for w in self.detail_frame.winfo_children():
                w.destroy()
            ctk.CTkLabel(self.detail_frame, text="选择左侧帖子查看详情").pack(pady=50)
            self._load_posts()

    def _on_post_edit(self, msg):
        if msg.get("post"):
            messagebox.showinfo("成功", "帖子已更新")
            self._load_posts()

    def _edit_post(self, post):
        CreatePostDialog(self, self.forum, self.user_uuid, self.user_pubkey, edit_post=post)

    def _delete_post(self, post_id):
        if messagebox.askyesno("确认", "确定删除此帖子？"):
            self.forum.delete_post(post_id)

    # ===== 评论 =====

    def _submit_comment(self, post_id):
        content = self.comment_text.get("1.0", "end").strip()
        if not content:
            return
        self.forum.create_comment(post_id, content)
        self.comment_text.delete("1.0", "end")

    def _reply_to(self, comment):
        content = self.comment_text.get("1.0", "end").strip()
        if not content:
            self.comment_text.insert("1.0", f"回复 {comment.get('author_uuid','')[:12]}...: ")
            return
        self.forum.create_comment(self.current_post["id"], content, parent_id=comment["id"])
        self.comment_text.delete("1.0", "end")

    def _on_comment_create(self, msg):
        if msg.get("comment") and self.current_post:
            self.forum.list_comments(self.current_post["id"])

    def _on_comment_delete(self, msg):
        if msg.get("success") and self.current_post:
            self.forum.list_comments(self.current_post["id"])

    def _on_comment_list(self, msg):
        self.current_comments = {"roots": msg.get("roots", []), "replies": msg.get("replies", {})}
        if hasattr(self, "comments_container"):
            self._render_comments()

    # ===== 投票 =====

    def _vote(self, target_type, target_id, value):
        self.forum.cast_vote(target_type, target_id, value)

    def _on_vote_cast(self, msg):
        if msg.get("success") and self.current_post:
            self.forum.get_post(self.current_post["id"])
            self.forum.list_comments(self.current_post["id"])

    def _on_vote_get(self, msg):
        pass

    # ===== 为什么排名 =====

    def _on_why_ranked(self, msg):
        bd = msg.get("breakdown", {})
        if bd:
            text = f"热度分: {bd.get('hot_score',0):.4f}\n\n"
            b = bd.get("breakdown", {})
            text += f"投票分: {b.get('vote_score',0)} ({b.get('vote_detail','')})\n"
            text += f"评论分: {b.get('comment_score',0)} ({b.get('comment_detail','')})\n"
            text += f"时间分: {b.get('time_score',0)} ({b.get('time_detail','')})"
            messagebox.showinfo("为什么这个排名", text)

    # ===== 服务器信息 =====

    def _on_server_info(self, msg):
        card = msg.get("card", {})
        name = card.get("name", "Spider")
        heat = card.get("heat_level", "green")
        heat_text = {"green": "活跃", "yellow": "中等", "orange": "繁忙", "red": "拥挤"}.get(heat, "活跃")
        online = card.get("online_count", -1)
        if online >= 0:
            self.status_label.configure(text=f"{name} | {heat_text} | 在线: {online}/{card.get('max_online',100)}")
        else:
            self.status_label.configure(text=f"{name} | {heat_text}")

    def _on_load_status(self, msg):
        pass

    def _on_directory(self, msg):
        pass

    def _on_notifications(self, msg):
        pass

    def _on_drafts(self, msg):
        pass

    def _on_profile(self, msg):
        pass

    def _on_error(self, msg):
        code = msg.get("code", "")
        message = msg.get("message", "")
        if code and message:
            messagebox.showerror("错误", f"[{code}] {message}")

    @staticmethod
    def _fmt_time(ts):
        if not ts:
            return ""
        try:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(int(ts)))
        except Exception:
            return str(ts)


class CreatePostDialog(ctk.CTkToplevel):
    """发帖/编辑对话框。顶部醒目警示语。"""

    def __init__(self, master, forum: ForumClient, user_uuid: str, user_pubkey: str, edit_post=None):
        super().__init__(master)
        self.title("编辑帖子" if edit_post else "发布新帖")
        self.geometry("650x600")
        self.forum = forum
        self.edit_post = edit_post

        # 醒目警示
        warning = ctk.CTkFrame(self, fg_color="#c0392b", corner_radius=6)
        warning.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(warning, text="⚠ 重要警示",
                     font=ctk.CTkFont(size=14, weight="bold"), text_color="white").pack(pady=(8, 2))
        ctk.CTkLabel(warning,
                     text="帖子和评论以明文存储在服务器上，管理员可查看、删除、导出。\n"
                          "这等同于公开发布，不可否认。敏感信息请移步端到端加密私聊。",
                     font=ctk.CTkFont(size=12), text_color="white", justify="left").pack(padx=10, pady=(0, 8))

        # 标题
        ctk.CTkLabel(self, text="标题", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=10, pady=(5, 2))
        self.title_var = ctk.StringVar(value=edit_post.get("title", "") if edit_post else "")
        ctk.CTkEntry(self, textvariable=self.title_var, height=35).pack(fill="x", padx=10, pady=2)

        # 标签
        ctk.CTkLabel(self, text="标签（逗号分隔，最多5个，每个≤8字符）", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=10, pady=(5, 2))
        self.tags_var = ctk.StringVar(value=edit_post.get("tags", "") if edit_post else "")
        ctk.CTkEntry(self, textvariable=self.tags_var, height=30).pack(fill="x", padx=10, pady=2)

        # 正文
        ctk.CTkLabel(self, text="正文", font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=10, pady=(5, 2))
        self.content_text = ctk.CTkTextbox(self, height=250)
        self.content_text.pack(fill="both", expand=True, padx=10, pady=2)
        if edit_post:
            self.content_text.insert("1.0", edit_post.get("content", ""))

        # 按钮
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="取消", width=80, fg_color="gray", command=self.destroy).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="保存草稿", width=80, fg_color="#f39c12",
                      command=self._save_draft).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="发布" if not edit_post else "更新", width=80,
                      fg_color="#2ecc71", command=self._submit).pack(side="right", padx=5)

    def _submit(self):
        title = self.title_var.get().strip()
        content = self.content_text.get("1.0", "end").strip()
        tags = [t.strip() for t in self.tags_var.get().split(",") if t.strip()]

        if not title or not content:
            messagebox.showwarning("提示", "标题和正文不能为空")
            return

        if self.edit_post:
            self.forum.edit_post(self.edit_post["id"], title, content, tags)
        else:
            self.forum.create_post(title, content, tags, author_pubkey="")
        self.destroy()

    def _save_draft(self):
        title = self.title_var.get().strip()
        content = self.content_text.get("1.0", "end").strip()
        tags = [t.strip() for t in self.tags_var.get().split(",") if t.strip()]
        self.forum.save_draft(title, content, tags)
        messagebox.showinfo("成功", "草稿已保存")
