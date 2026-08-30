"""
Spider 客户端 — 主窗口 (MainWindow)
处理消息显示（含送达/已读回执）、发送、群组、设置。
"""

import sys
import os
import time
import json
import base64
import sqlite3
import threading
from collections import OrderedDict

import customtkinter as ctk
USE_CTK = True

from client.utils.config import load_config, save_config, get_data_dir, get_icon_path
from client.storage.identity import load_identity_file, wipe_all_data
from client.storage.messages import MessageStore, generate_msg_id, STATUS_SENDING, STATUS_DELIVERED, STATUS_READ
from client.network.tcp_client import TCPClient
from client.network.discovery import UDPDiscovery
from client.network.cross_server import CrossServerClient
from client.crypto.keys import (
    generate_keypairs, save_identity, load_identity,
    delete_identity, get_display_name, set_display_name,
    set_avatar, clear_avatar
)
from client.crypto.encrypt import encrypt_message, decrypt_message, encrypt_file_data, decrypt_file_data
from client.crypto.exchange import get_session_key, clear_all_sessions
from client.utils.uuidgen import generate_uuid_v1
from shared.crypto_utils import sign_data, verify_signature, load_ed25519_private
from shared.protocol import *
from tkinter import messagebox, filedialog, simpledialog

# ===== Collection 卡片支持 =====
from client.crypto_collection import (
    is_collection_text, parse_collection, build_collection_text,
    load_crypto_data, match_prefix, short_address,
    CARD_BG_SENT, CARD_BG_RECV, CARD_ACCENT, CARD_TEXT, CARD_SUB,
)


# ===== 回执状态中文映射 =====
RECEIPT_TEXT = {
    "sending": "发送中",
    "delivered": "已送达",
    "read": "已读",
    "queued_offline": "已送达（离线）",
    "failed": "发送失败",
    "delivered_cross_server": "已送达（跨服务器）",
}


class MainWindow:
    """登录成功后的主聊天窗口。"""

    def __init__(self, identity: dict, server_host: str, server_port: int):
        self.identity = identity
        self.uuid = identity["uuid"]
        self.config = load_config()
        self.msg_store = MessageStore()
        # 死人开关管理器（登录/编辑时自动同步警告消息到服务器）
        from client.security.deadman import DeadmanManager
        self.deadman = DeadmanManager(tcp_client=None, get_uuid=lambda: self.uuid)
        self.tcp = TCPClient(server_host, server_port)
        self.deadman.tcp_client = self.tcp
        # 回调绑定
        self.tcp.on_message = self._on_message
        self.tcp.on_offline_queue = self._on_offline_queue
        self.tcp.on_broadcast = self._on_broadcast
        self.tcp.on_error = self._on_error
        self.tcp.on_disconnect = self._on_disconnect
        self.tcp.on_admin_result = self._on_admin_result
        self.tcp.on_pubkey_result = self._on_pubkey_result
        self.tcp.on_rate_limited = self._on_rate_limited
        self.tcp.on_compromised_ack = self._on_compromised_ack
        self.tcp.on_deadman_ack = self._on_deadman_ack
        self.tcp.on_login_ok = self._on_login_ok
        self.tcp.on_group_message = self._on_group_message
        self.tcp.on_group_event = self._on_group_event
        self.tcp.on_lookup_result = self._on_lookup_result
        self.tcp.on_group_list_result = self._on_group_list_result
        self.tcp.on_group_info_result = self._on_group_info_result
        self.tcp.on_group_search_result = self._on_group_search_result
        self.tcp.on_group_create_result = self._on_group_create_result
        # 回执回调
        self.tcp.on_delivery_receipt = self._on_delivery_receipt
        self.tcp.on_read_receipt = self._on_read_receipt
        self.tcp.on_read_receipt_disabled = self._on_read_receipt_disabled

        self.cross_server = CrossServerClient(self.tcp, identity)
        self.discovery = UDPDiscovery(self.config.get("udp_port", DEFAULT_UDP_PORT))
        self.contacts = self._load_contacts_list()
        self.current_contact = None
        self.contact_pubkeys = {}
        self.admin_token = None
        self.is_admin = False
        self.pending_files = {}
        # msg_id → UI 控件引用（用于更新回执状态）
        self._receipt_widgets: dict[str, dict] = {}
        # 已读回执开关
        self.read_receipts_enabled = self.config.get("read_receipts_enabled", True)
        # 可视区域回执数据
        self._message_widgets = []
        self._visible_check_pending = False

        # ===== 安全功能引擎 =====
        try:
            from client.security.ephemeral import EphemeralEngine
            from client.security.vault import MessageVault
            self.ephemeral = EphemeralEngine(self.config)
            self.vault = MessageVault(self.msg_store.db_path,
                                      self.config.get("vault_pin", ""))
            if self.config.get("vault_enabled") and self.config.get("vault_pin"):
                try:
                    self.vault.unlock(self.config["vault_pin"])
                except Exception:
                    self.vault = None
            elif not self.config.get("vault_enabled"):
                self.vault = None
            else:
                self.vault = None
        except Exception:
            self.ephemeral = None
            self.vault = None

        self._build_ui()
        self._connect_and_login()

    # ===== UI 构建 =====
    def _build_ui(self):
        self.root = ctk.CTk()
        self.root.title("Spider🕷")
        self.root.geometry("1000x650")
        ctk.set_appearance_mode("dark")
        self._build_ctk_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._set_window_icon()

    def _set_window_icon(self):
        """设置窗口图标。"""
        try:
            import tkinter as _tk
            icon_path = get_icon_path()
            if os.path.exists(icon_path):
                self.root.iconphoto(False, _tk.PhotoImage(file=icon_path))
        except Exception:
            pass

    def _build_ctk_ui(self):
        # 顶部搜索栏
        top = ctk.CTkFrame(self.root)
        top.pack(side="top", fill="x", padx=5, pady=5)
        self.search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(top, textvariable=self.search_var, placeholder_text="🔍 搜索联系人...")
        search_entry.pack(side="left", fill="x", expand=True, padx=5)
        search_entry.bind("<KeyRelease>", self._on_search_key)
        settings_btn = ctk.CTkButton(top, text="⚙ 设置", width=70, command=self._open_settings)
        settings_btn.pack(side="right", padx=5)

        # 主区域
        main = ctk.CTkFrame(self.root)
        main.pack(side="top", fill="both", expand=True, padx=5, pady=5)
        # 左侧联系人列表
        left = ctk.CTkFrame(main, width=250)
        left.pack(side="left", fill="y", padx=(0, 5))
        left.pack_propagate(False)
        self.contact_frame = ctk.CTkScrollableFrame(left)
        self.contact_frame.pack(fill="both", expand=True)
        self._refresh_contact_list_ctk()

        # 右侧聊天区
        right = ctk.CTkFrame(main)
        right.pack(side="right", fill="both", expand=True)
        self.chat_header = ctk.CTkLabel(right, text="选择一个联系人开始聊天", font=("Arial", 14))
        self.chat_header.pack(side="top", fill="x", pady=5)
        self.chat_scroll = ctk.CTkScrollableFrame(right)
        self.chat_scroll.pack(fill="both", expand=True, padx=5, pady=5)
        canvas = self.chat_scroll._parent_canvas
        canvas.bind("<Configure>", lambda e: self._on_scroll_or_resize())
        canvas.bind("<MouseWheel>", lambda e: self._on_scroll_or_resize())
        canvas.bind("<Button-4>", lambda e: self._on_scroll_or_resize())
        canvas.bind("<Button-5>", lambda e: self._on_scroll_or_resize())

        # 输入区
        input_area = ctk.CTkFrame(right)
        input_area.pack(side="bottom", fill="x", padx=5, pady=5)
        self.msg_var = ctk.StringVar()
        msg_entry = ctk.CTkEntry(input_area, textvariable=self.msg_var, placeholder_text="输入消息...")
        msg_entry.pack(side="left", fill="x", expand=True, padx=5)
        msg_entry.bind("<Return>", lambda e: self._send_text())

        # 📁 文件按钮
        file_btn = ctk.CTkButton(input_area, text="📁", width=40,
                                 fg_color=self.config.get("send_button_color", DEFAULT_BUTTON_COLOR),
                                 command=self._choose_file)
        file_btn.pack(side="left", padx=2)

        # 💸 Collection（加密货币卡片）按钮 —— 新增
        collection_btn = ctk.CTkButton(input_area, text="💸", width=40,
                                       fg_color=self.config.get("send_button_color", DEFAULT_BUTTON_COLOR),
                                       command=self._open_collection_dialog)
        collection_btn.pack(side="left", padx=(0, 5))

        send_btn = ctk.CTkButton(input_area, text="发送", width=70,
                                 fg_color=self.config.get("send_button_color", DEFAULT_BUTTON_COLOR),
                                 command=self._send_text)
        send_btn.pack(side="right", padx=5)

    # ===== 联系人列表 =====
    def _refresh_contact_list_ctk(self):
        for w in self.contact_frame.winfo_children():
            w.destroy()
        for c in self.contacts:
            btn = ctk.CTkButton(
                self.contact_frame, text=c.get("name", c["uuid"][:8]),
                anchor="w", command=lambda cid=c["uuid"]: self._select_contact(cid)
            )
            btn.pack(fill="x", padx=2, pady=1)
            btn.bind("<Button-3>", lambda e, cid=c["uuid"]: self._select_contact(cid))
            btn.bind("<Button-1>", lambda e, cid=c["uuid"]: self._left_click_contact(e, cid))

    def _left_click_contact(self, event, uuid_str: str):
        self._show_contact_menu(uuid_str, event.x_root, event.y_root)

    def _show_contact_menu(self, uuid_str: str, x=None, y=None):
        menu = ctk.CTkToplevel(self.root)
        menu.geometry("200x10")
        menu.withdraw()
        menu.destroy()
        menu = __import__("tkinter").Menu(self.root, tearoff=0)
        contact = self._get_contact(uuid_str)
        name = contact.get("name", uuid_str[:8]) if contact else uuid_str[:8]
        menu.add_command(label=f"📝 编辑备注名 ({name})", command=lambda: self._edit_contact_name(uuid_str))
        menu.add_separator()
        is_blocked = contact.get("blocked", False) if contact else False
        if is_blocked:
            menu.add_command(label="✅ 解拉黑", command=lambda: self._toggle_block(uuid_str, False))
        else:
            menu.add_command(label="🚫 拉黑", command=lambda: self._toggle_block(uuid_str, True))
        menu.add_command(label="🗑 删除联系人", command=lambda: self._delete_contact(uuid_str))
        menu.add_command(label="📤 分享联系人", command=lambda: self._share_contact(uuid_str))
        menu.add_command(label="🔍 搜索聊天记录", command=lambda: self._search_chat_record(uuid_str))
        menu.add_command(label="🧹 删除聊天记录", command=lambda: self._delete_chat_record(uuid_str))
        menu.add_separator()
        menu.add_command(label="✅ 全部标记为已读", command=lambda: self._mark_all_read(uuid_str))
        if x is not None and y is not None:
            menu.post(x, y)
        else:
            menu.post(self.root.winfo_pointerx(), self.root.winfo_pointery())

    def _edit_contact_name(self, uuid_str: str):
        new_name = simpledialog.askstring("编辑备注名", "输入新备注名:", parent=self.root)
        if new_name:
            for c in self.contacts:
                if c["uuid"] == uuid_str:
                    c["name"] = new_name
                    break
            self._save_contacts_list()
            self._refresh_contact_list_ctk()

    def _toggle_block(self, uuid_str: str, blocked: bool):
        for c in self.contacts:
            if c["uuid"] == uuid_str:
                c["blocked"] = blocked
                break
        self._save_contacts_list()

    def _delete_contact(self, uuid_str: str):
        self.contacts = [c for c in self.contacts if c["uuid"] != uuid_str]
        self.contact_pubkeys.pop(uuid_str, None)
        self._save_contacts_list()
        self._refresh_contact_list_ctk()

    def _share_contact(self, uuid_str: str):
        contact = self._get_contact(uuid_str)
        if not contact:
            return
        export = {
            "uuid": uuid_str,
            "name": contact.get("name", ""),
            "x25519_public": contact.get("x25519_public", ""),
            "ed25519_public": contact.get("ed25519_public", ""),
        }
        path = filedialog.asksaveasfilename(defaultextension=".json", parent=self.root)
        if path:
            with open(path, "w") as f:
                json.dump(export, f, indent=2)

    def _search_chat_record(self, uuid_str: str):
        kw = simpledialog.askstring("搜索聊天记录", "输入关键词:", parent=self.root)
        if kw:
            results = self.msg_store.search_messages(uuid_str, kw)
            self._display_search_results(results)

    def _delete_chat_record(self, uuid_str: str):
        self.msg_store.delete_messages(uuid_str)
        if self.current_contact == uuid_str:
            self._clear_chat_display()

    # ===== 搜索 / 选择联系人 =====
    def _on_search_key(self, event):
        query = self.search_var.get().strip()
        if not query:
            self._refresh_contact_list_ctk()
            return
        filtered = [c for c in self.contacts
                    if query.lower() in c.get("name", "").lower()
                    or query.lower() in c["uuid"].lower()]
        for w in self.contact_frame.winfo_children():
            w.destroy()
        for c in filtered:
            btn = ctk.CTkButton(self.contact_frame, text=c.get("name", c["uuid"][:8]),
                                 anchor="w", command=lambda cid=c["uuid"]: self._select_contact(cid))
            btn.pack(fill="x", padx=2, pady=1)
        if len(filtered) < len(self.contacts):
            sep = ctk.CTkLabel(self.contact_frame, text="─" * 20, text_color="gray")
            sep.pack()
            more = ctk.CTkButton(self.contact_frame, text="🔍 搜索局域网联系人...",
                                  fg_color="gray", command=lambda: self._search_lan(query))
            more.pack(fill="x", padx=2, pady=1)
            more2 = ctk.CTkButton(self.contact_frame, text="🌐 搜索服务器联系人...",
                                   fg_color="gray", command=lambda: self._search_server(query))
            more2.pack(fill="x", padx=2, pady=1)

    def _search_lan(self, query: str):
        servers = self.discovery.discover(timeout=3.0)
        for srv in servers:
            try:
                temp_client = TCPClient(srv["host"], srv.get("tcp_port", DEFAULT_TCP_PORT))
                temp_client.connect()
                temp_client.search_contacts(query, scope="lan")
                temp_client.disconnect()
            except Exception:
                pass
        messagebox.showinfo("提示", "已在局域网中搜索，请稍后查看结果")

    def _search_server(self, query: str):
        try:
            self.tcp.search_contacts(query, scope="global" if len(query) >= 8 else "server")
            if len(query) >= 8:
                self.cross_server.lookup_remote_contact(query, callback=self._on_lookup_result)
        except Exception as e:
            self._show_error(f"搜索失败: {e}")

    def _select_contact(self, uuid_str: str):
        self.current_contact = uuid_str
        contact = self._get_contact(uuid_str)
        name = contact.get("name", uuid_str[:8]) if contact else uuid_str[:8]
        self.chat_header.configure(text=f"💬 {name}")
        if uuid_str not in self.contact_pubkeys:
            self._fetch_peer_pubkey(uuid_str)
        self._load_chat_history(uuid_str)

    # ===== 聊天历史 & 显示 =====
    def _load_chat_history(self, uuid_str: str):
        self._clear_chat_display()
        msgs = self.msg_store.get_messages(uuid_str, limit=200)
        for m in msgs:
            if m["is_file"]:
                self._display_file_message(m, m["direction"], msg_id=m.get("msg_id", ""))
            elif is_collection_text(m["text"]):
                # 历史中的 Collection 消息渲染为卡片
                self._display_collection_card(m["text"], m["direction"],
                                              m.get("timestamp", 0),
                                              delivery_status=m.get("delivery_status", "sending"),
                                              msg_id=m.get("msg_id", ""))
            else:
                self._display_text_message(m["text"], m["direction"],
                                           m.get("timestamp", 0),
                                           delivery_status=m.get("delivery_status", "sending"),
                                           msg_id=m.get("msg_id", ""))
        self.msg_store.mark_read(uuid_str)
        self.root.after(200, self._check_visible_messages)

    def _clear_chat_display(self):
        for w in self.chat_scroll.winfo_children():
            w.destroy()
        self._receipt_widgets.clear()
        self._message_widgets.clear()

    # ---------- Collection 卡片渲染 ----------
    def _display_collection_card(self, text: str, direction: str,
                                 timestamp: int = 0,
                                 delivery_status: str = "sending",
                                 msg_id: str = ""):
        """将 Collection 文本渲染为加密货币地址卡片。"""
        parsed = parse_collection(text)
        if not parsed:
            # 解析失败退化成普通文本
            self._display_text_message(text, direction, timestamp, delivery_status, msg_id)
            return

        color = CARD_BG_SENT if direction == "sent" else CARD_BG_RECV
        side = "right" if direction == "sent" else "left"

        outer = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        outer.pack(anchor=side, padx=10, pady=2, fill="x")

        card = ctk.CTkFrame(outer, fg_color=color, corner_radius=10)
        card.pack(side=side, padx=0, pady=0, fill="x", expand=False)

        # 顶部：货币名称（大字）+ 网络标签
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=12, pady=(10, 2))
        ctk.CTkLabel(header, text=f"💰 {parsed['currency']}",
                     font=("Arial", 16, "bold"), text_color=CARD_ACCENT).pack(side="left")
        ctk.CTkLabel(header, text=f"  {parsed['network']}",
                     font=("Arial", 10), text_color=CARD_SUB).pack(side="left", padx=(4, 0))

        # 地址行 + 复制按钮
        addr_row = ctk.CTkFrame(card, fg_color="transparent")
        addr_row.pack(fill="x", padx=12, pady=(2, 2))
        addr_display = short_address(parsed["address"], 10, 8)
        ctk.CTkLabel(addr_row, text=f"📍 {addr_display}",
                     font=("Arial", 10), text_color=CARD_TEXT).pack(side="left")

        copy_addr_btn = ctk.CTkButton(
            addr_row, text="📋", width=32, height=24,
            font=("Arial", 10),
            command=lambda a=parsed["address"]: self._copy_to_clipboard(a, "地址已复制"))
        copy_addr_btn.pack(side="left", padx=(8, 4))

        copy_net_btn = ctk.CTkButton(
            addr_row, text="📋网络", width=52, height=24,
            font=("Arial", 9),
            command=lambda n=parsed["network"]: self._copy_to_clipboard(n, "网络已复制"))
        copy_net_btn.pack(side="left", padx=2)

        # 完整地址提示（鼠标悬停可见）
        ctk.CTkLabel(card, text=f"网络: {parsed['network']}",
                     font=("Arial", 8), text_color="#777777").pack(anchor="w", padx=12, pady=(0, 2))

        # 发送方的回执状态
        if direction == "sent":
            status_text = self._receipt_status_text(delivery_status)
            receipt_label = ctk.CTkLabel(card, text=status_text,
                                         font=("Arial", 9), text_color="#CCCCCC")
            receipt_label.pack(anchor="e", padx=12, pady=(0, 6))
            if msg_id:
                self._receipt_widgets[msg_id] = {"label": receipt_label, "status": delivery_status}
        else:
            time_str = time.strftime("%H:%M", time.localtime(timestamp)) if timestamp else ""
            if time_str:
                ctk.CTkLabel(card, text=time_str, font=("Arial", 9), text_color="#CCCCCC").pack(anchor="e", padx=12, pady=(0, 6))

        # 接收消息加入可见性追踪
        if direction == "recv" and msg_id:
            exist = any(item["msg_id"] == msg_id for item in self._message_widgets)
            if not exist:
                self._message_widgets.append({
                    "widget": outer, "msg_id": msg_id,
                    "receipt_sent": False, "top_seen": False, "bottom_seen": False
                })

        self._scroll_chat_to_bottom()
        return outer

    def _receipt_status_text(self, delivery_status: str) -> str:
        if delivery_status == "read":
            return "✓✓ 已读"
        elif delivery_status == "delivered":
            return "✓ 已送达"
        elif delivery_status == "queued_offline":
            return "✓ 已送达（离线）"
        elif delivery_status == "delivered_cross_server":
            return "✓ 已送达（跨服）"
        elif delivery_status == "failed":
            return "❌ 发送失败"
        return "⏳ 发送中"

    def _copy_to_clipboard(self, text: str, notice: str = "已复制"):
        """跨平台复制到剪贴板（优先 tkinter，回退到 xclip/pbcopy）。"""
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
            self._show_info(f"{notice}: {short_address(text, 8, 6) if len(text) > 24 else text}")
        except Exception:
            try:
                import subprocess
                p = subprocess.Popen(["xclip", "-selection", "clipboard"], stdin=subprocess.PIPE)
                p.communicate(text.encode("utf-8"))
                self._show_info(notice)
            except Exception as e2:
                self._show_error(f"复制失败: {e2}")

    # ---------- 文本 / 文件 消息渲染（原有） ----------
    def _display_text_message(self, text: str, direction: str,
                              timestamp: int = 0,
                              delivery_status: str = "sending",
                              msg_id: str = ""):
        color = (self.config.get("sent_message_color", DEFAULT_SENT_COLOR)
                 if direction == "sent"
                 else self.config.get("recv_message_color", DEFAULT_RECV_COLOR))
        side = "right" if direction == "sent" else "left"
        outer = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        outer.pack(anchor=side, padx=10, pady=2, fill="x")
        bubble = ctk.CTkFrame(outer, fg_color=color)
        bubble.pack(side=side, padx=0, pady=0)
        label = ctk.CTkLabel(bubble, text=text, wraplength=400, text_color="white")
        label.pack(padx=8, pady=(4, 0))
        if direction == "sent":
            receipt_label = ctk.CTkLabel(bubble, text=self._receipt_status_text(delivery_status),
                                         font=("Arial", 9), text_color="#CCCCCC")
            receipt_label.pack(padx=8, pady=(0, 4))
            if msg_id:
                self._receipt_widgets[msg_id] = {"label": receipt_label, "status": delivery_status}
        else:
            time_str = time.strftime("%H:%M", time.localtime(timestamp)) if timestamp else ""
            if time_str:
                ctk.CTkLabel(bubble, text=time_str, font=("Arial", 9), text_color="#CCCCCC").pack(padx=8, pady=(0, 4))
        if direction == "recv" and msg_id:
            exist = any(item["msg_id"] == msg_id for item in self._message_widgets)
            if not exist:
                self._message_widgets.append({
                    "widget": outer, "msg_id": msg_id,
                    "receipt_sent": False, "top_seen": False, "bottom_seen": False
                })
        self._scroll_chat_to_bottom()
        return outer

    def _display_file_message(self, msg: dict, direction: str, msg_id: str = ""):
        color = (self.config.get("sent_message_color", DEFAULT_SENT_COLOR)
                 if direction == "sent"
                 else self.config.get("recv_message_color", DEFAULT_RECV_COLOR))
        side = "right" if direction == "sent" else "left"
        fname = msg.get("filename", "unknown")
        fsize = msg.get("filesize", 0)
        outer = ctk.CTkFrame(self.chat_scroll, fg_color="transparent")
        outer.pack(anchor=side, padx=10, pady=2, fill="x")
        bubble = ctk.CTkFrame(outer, fg_color=color)
        bubble.pack(side=side)
        label = ctk.CTkLabel(bubble, text=f"📎 {fname} ({fsize} bytes)", text_color="white")
        label.pack(padx=8, pady=4)
        btn = ctk.CTkButton(bubble, text="下载", width=60, command=lambda: self._download_file(msg))
        btn.pack(padx=4, pady=2)
        if direction == "sent":
            receipt_label = ctk.CTkLabel(bubble, text=self._receipt_status_text("sending"),
                                         font=("Arial", 9), text_color="#CCCCCC")
            receipt_label.pack(padx=8, pady=(0, 4))
            if msg_id:
                self._receipt_widgets[msg_id] = {"label": receipt_label, "status": "sending"}
        else:
            if msg_id:
                exist = any(item["msg_id"] == msg_id for item in self._message_widgets)
                if not exist:
                    self._message_widgets.append({
                        "widget": outer, "msg_id": msg_id,
                        "receipt_sent": False, "top_seen": False, "bottom_seen": False
                    })
        self._scroll_chat_to_bottom()

    def _scroll_chat_to_bottom(self):
        try:
            self.chat_scroll._parent_canvas.yview_moveto(1.0)
        except Exception:
            pass

    def _update_receipt_display(self, msg_id: str, new_status: str):
        info = self._receipt_widgets.get(msg_id)
        if not info:
            return
        info["status"] = new_status
        label = info["label"]
        if new_status == "read":
            label.configure(text="✓✓ 已读", text_color="#00FF88")
        elif new_status == "delivered":
            label.configure(text="✓ 已送达", text_color="#CCCCCC")
        elif new_status == "queued_offline":
            label.configure(text="✓ 已送达（离线）", text_color="#AAAAAA")
        elif new_status == "delivered_cross_server":
            label.configure(text="✓ 已送达（跨服）", text_color="#AAAAAA")
        elif new_status == "sending":
            label.configure(text="⏳ 发送中", text_color="#FFAAAA")
        elif new_status == "failed":
            label.configure(text="❌ 发送失败", text_color="#FF4444")

    def _display_search_results(self, results: list):
        if not results:
            self._show_info("未找到匹配的记录")
            return
        self._clear_chat_display()
        for r in results:
            text = f"[{r['timestamp']}] {r['text']}"
            self._display_text_message(text, r["direction"])

    # ===== 发送消息 =====
    def _send_text(self):
        text = self.msg_var.get().strip()
        if not text or not self.current_contact:
            return
        peer_uuid = self.current_contact
        if peer_uuid not in self.contact_pubkeys:
            self._show_error("对方公钥尚未获取，请稍候")
            return
        try:
            client_msg_id = generate_msg_id()
            encrypted = encrypt_message(
                text, self.identity["x25519_private"],
                self.contact_pubkeys[peer_uuid]["x25519"],
                self.identity["ed25519_private"], self.uuid, peer_uuid
            )
            env = {
                "type": SEND_MSG, "to_uuid": peer_uuid,
                "encrypted_payload": encrypted, "client_msg_id": client_msg_id,
            }
            sig_data = json.dumps(env, sort_keys=True).encode()
            e_priv = load_ed25519_private(self.identity["ed25519_private"])
            signature = sign_data(e_priv, sig_data)

            self.msg_store.add_message(
                peer_uuid, "sent", text,
                timestamp=encrypted["timestamp"],
                delivery_status="sending", msg_id=client_msg_id,
            )
            # Collection 消息用卡片渲染，其余用文本气泡
            if is_collection_text(text):
                self._display_collection_card(text, "sent",
                                             timestamp=encrypted["timestamp"],
                                             delivery_status="sending",
                                             msg_id=client_msg_id)
            else:
                self._display_text_message(text, "sent",
                                           timestamp=encrypted["timestamp"],
                                           delivery_status="sending",
                                           msg_id=client_msg_id)
            self.tcp.send_message(peer_uuid, encrypted, signature, client_msg_id=client_msg_id)
            self.msg_var.set("")
        except Exception as e:
            self._show_error(f"发送失败: {e}")

    def _choose_file(self):
        if not self.current_contact:
            self._show_error("请先选择一个联系人")
            return
        path = filedialog.askopenfilename(parent=self.root)
        if path:
            self._send_file(path)

    def _send_file(self, filepath: str):
        try:
            with open(filepath, "rb") as f:
                data = f.read()
            fname = os.path.basename(filepath)
            peer_uuid = self.current_contact
            client_msg_id = generate_msg_id()
            nonce_b64, ct_b64 = encrypt_file_data(
                data, self.identity["x25519_private"],
                self.contact_pubkeys[peer_uuid]["x25519"]
            )
            file_payload = {
                "type": "file", "filename": fname, "size": len(data),
                "nonce": nonce_b64, "ciphertext": ct_b64,
                "timestamp": int(time.time()),
            }
            env = {
                "type": SEND_MSG, "to_uuid": peer_uuid,
                "encrypted_payload": file_payload, "client_msg_id": client_msg_id,
            }
            sig_data = json.dumps(env, sort_keys=True).encode()
            e_priv = load_ed25519_private(self.identity["ed25519_private"])
            signature = sign_data(e_priv, sig_data)
            self.msg_store.add_message(
                peer_uuid, "sent", f"[文件] {fname}",
                filename=fname, filesize=len(data), is_file=True,
                delivery_status="sending", msg_id=client_msg_id,
            )
            self._display_file_message({"filename": fname, "filesize": len(data)}, "sent", msg_id=client_msg_id)
            self.tcp.send({
                "type": SEND_MSG, "to_uuid": peer_uuid,
                "encrypted_payload": file_payload, "signature": signature,
                "client_msg_id": client_msg_id,
            })
        except Exception as e:
            self._show_error(f"文件发送失败: {e}")

    def _download_file(self, msg: dict):
        peer_uuid = self.current_contact
        if peer_uuid not in self.contact_pubkeys:
            self._show_error("无法找到对方公钥")
            return
        nonce_b64 = msg.get("nonce", "")
        ct_b64 = msg.get("ciphertext", "")
        if not nonce_b64 or not ct_b64:
            self._show_error("文件数据不完整")
            return
        try:
            data = decrypt_file_data(
                nonce_b64, ct_b64,
                self.identity["x25519_private"],
                self.contact_pubkeys[peer_uuid]["x25519"]
            )
            save_path = filedialog.asksaveasfilename(
                initialfile=msg.get("filename", "download"), parent=self.root)
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(data)
                self._show_info(f"文件已保存到 {save_path}")
        except Exception as e:
            self._show_error(f"文件下载失败: {e}")

    # ===== Collection 按钮 → 构建对话框（含 Tab 补全）=====
    def _open_collection_dialog(self):
        """弹出 Collection 构建对话框：货币 / 地址 / 网络，支持 Tab 补全。"""
        if not self.current_contact:
            self._show_error("请先选择一个联系人")
            return
        win = ctk.CTkToplevel(self.root)
        win.title("💸 发送加密货币地址")
        win.geometry("460x300")
        win.transient(self.root)
        win.grab_set()

        crypto_data = load_crypto_data()
        currencies = crypto_data.get("Cryptocurrency", [])
        networks = crypto_data.get("blockchain", [])

        ctk.CTkLabel(win, text="货币名称:", font=("Arial", 11)).pack(anchor="w", padx=14, pady=(14, 0))
        cur_var = ctk.StringVar()
        cur_entry = ctk.CTkEntry(win, textvariable=cur_var, placeholder_text="如 BTC / USDC / ETH")
        cur_entry.pack(fill="x", padx=14, pady=(2, 6))

        ctk.CTkLabel(win, text="钱包地址:", font=("Arial", 11)).pack(anchor="w", padx=14, pady=(4, 0))
        addr_var = ctk.StringVar()
        addr_entry = ctk.CTkEntry(win, textvariable=addr_var, placeholder_text="粘贴地址…")
        addr_entry.pack(fill="x", padx=14, pady=(2, 6))

        ctk.CTkLabel(win, text="网络/链:", font=("Arial", 11)).pack(anchor="w", padx=14, pady=(4, 0))
        net_var = ctk.StringVar()
        net_entry = ctk.CTkEntry(win, textvariable=net_var, placeholder_text="如 Bitcoin / Solana / Ethereum")
        net_entry.pack(fill="x", padx=14, pady=(2, 10))

        # ---- Tab 补全辅助（同时支持鼠标点击候选）----
        def make_completer(entry, var, name_list):
            listbox = None
            def refresh_listbox():
                nonlocal listbox
                prefix = var.get()
                matches = match_prefix(name_list, prefix)
                if not matches:
                    if listbox:
                        listbox.destroy()
                        listbox = None
                    return
                if listbox is None:
                    listbox = ctk.CTkListbox(win, height=min(len(matches), 5), width=entry.winfo_width())
                    listbox.place(in_=entry, x=0, y=entry.winfo_height() + 2)
                else:
                    listbox.delete(0, "end")
                for m in matches:
                    listbox.insert("end", m)
            def on_tab(event):
                nonlocal listbox
                refresh_listbox()
                if listbox:
                    listbox.focus_set()
                    listbox.select(0)
                return "break"
            def on_key(event):
                if event.keysym in ("Return", "Escape"):
                    if listbox:
                        listbox.destroy()
                        listbox = None
                else:
                    win.after(50, refresh_listbox)
            def on_listbox_select(evt):
                if not listbox:
                    return
                sel = listbox.get(listbox.curselection()) if listbox.curselection() else None
                if sel:
                    var.set(sel)
                    listbox.destroy()
                    # 焦点回到对应 entry 并移动光标到末尾
                    entry.focus_set()
                    entry.icursor("end")
            entry.bind("<Tab>", on_tab)
            var.trace_add("write", lambda *a: win.after(50, refresh_listbox))
            entry.bind("<KeyRelease>", on_key)
            if listbox is not None:
                listbox.bind("<<ListboxSelect>>", on_listbox_select)
            return listbox

        # 为货币和网络分别绑定补全
        make_completer(cur_entry, cur_var, currencies)
        make_completer(net_entry, net_var, networks)

        def do_send():
            cur = cur_var.get().strip()
            addr = addr_var.get().strip()
            net = net_var.get().strip()
            if not cur or not addr or not net:
                self._show_error("请填写货币名称、钱包地址和网络")
                return
            text = build_collection_text(cur, addr, net)
            # 直接走发送流程
            self.msg_var.set(text)
            win.destroy()
            self._send_text()

        ctk.CTkButton(win, text="生成并发送", command=do_send).pack(pady=10)
        cur_entry.focus_set()

    # ===== 已读回执（可视区域）=====
    def _on_scroll_or_resize(self):
        if not self._visible_check_pending:
            self._visible_check_pending = True
            self.root.after(150, self._check_visible_messages)

    def _check_visible_messages(self):
        self._visible_check_pending = False
        if not self.read_receipts_enabled or not self.current_contact:
            return
        try:
            canvas = self.chat_scroll._parent_canvas
            inner = self.chat_scroll._inner_frame
            inner_y = inner.winfo_y()
            canvas_height = canvas.winfo_height()
            if canvas_height <= 0:
                return
            for item in self._message_widgets:
                if item["receipt_sent"]:
                    continue
                widget = item["widget"]
                widget_y = widget.winfo_y()
                widget_height = widget.winfo_height()
                if widget_height <= 0:
                    continue
                canvas_y = inner_y + widget_y
                if canvas_y >= 0 and canvas_y <= canvas_height:
                    item["top_seen"] = True
                bottom_y = canvas_y + widget_height
                if bottom_y >= 0 and bottom_y <= canvas_height:
                    item["bottom_seen"] = True
                if item["top_seen"] and item["bottom_seen"] and not item["receipt_sent"]:
                    self._send_read_receipt(self.current_contact, item["msg_id"])
                    item["receipt_sent"] = True
        except Exception as e:
            print(f"[VISIBLE] Check error: {e}")

    def _mark_all_read(self, contact_uuid: str):
        if not self.read_receipts_enabled:
            self._show_info("已读回执功能已关闭，无法标记")
            return
        db_path = self.msg_store.db_path
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute(
            "SELECT server_msg_id FROM messages WHERE contact_uuid=? AND direction='recv' "
            "AND server_msg_id IS NOT NULL AND delivery_status != 'read'",
            (contact_uuid,))
        rows = c.fetchall()
        conn.close()
        if not rows:
            self._show_info("该联系人没有未读消息")
            return
        server_ids = [row[0] for row in rows]
        count = len(server_ids)
        for sid in server_ids:
            self._send_read_receipt(contact_uuid, sid)
            self.msg_store.update_delivery_status_by_server_id(sid, "read")
            # 阅后即焚：对已读消息按规则触发删除
            if self.ephemeral is not None:
                try:
                    client_mid = self.msg_store.get_msg_id_by_server_id(sid)
                    self.ephemeral.burn_if_matches(
                        contact_uuid, client_mid, "", self.msg_store)
                except Exception:
                    pass
        for item in self._message_widgets:
            if item["msg_id"] in server_ids:
                item["receipt_sent"] = True
                item["top_seen"] = True
                item["bottom_seen"] = True
                self._update_receipt_display(item["msg_id"], "read")
        self._show_info(f"已标记 {count} 条消息为已读")

    def _send_read_receipt(self, from_uuid: str, server_msg_id: str):
        try:
            receipt = {
                "type": READ_RECEIPT, "server_msg_id": server_msg_id,
                "from_uuid": from_uuid, "timestamp": int(time.time()),
            }
            self.tcp.send(receipt)
            # 阅后即焚：对已读消息按规则触发删除
            if self.ephemeral is not None and self.current_contact:
                try:
                    client_mid = self.msg_store.get_msg_id_by_server_id(server_msg_id)
                    self.ephemeral.burn_if_matches(
                        self.current_contact, client_mid, "", self.msg_store)
                except Exception:
                    pass
        except Exception as e:
            print(f"[READ_RECEIPT] Send failed: {e}")

    # ===== 接收消息处理 =====
    def _on_message(self, msg: dict):
        from_uuid = msg.get("from_uuid", "")
        encrypted = msg.get("encrypted_payload", {})
        msg_type = encrypted.get("type", "text")
        server_msg_id = msg.get("server_msg_id", "")
        client_msg_id = msg.get("client_msg_id", "")
        # 死人开关警告消息 — 服务器生成的明文系统消息，无需解密
        if msg.get("deadman_warning"):
            warning_text = msg.get("system_message", "[死人开关警告]")
            display_text = f"⚠️ [死人开关警告] {warning_text}"
            self.msg_store.add_message(
                from_uuid, "recv", display_text,
                delivery_status="delivered", server_msg_id=server_msg_id,
            )
            if self.current_contact == from_uuid:
                self._display_text_message(display_text, "recv", msg_id=server_msg_id)
                self.root.after(100, self._check_visible_messages)
            print(f"[DEADMAN] 收到来自 {from_uuid[:16]}... 的死人开关警告消息")
            return
        if from_uuid not in self.contact_pubkeys:
            self._fetch_peer_pubkey(from_uuid)
        if from_uuid not in self.contact_pubkeys:
            return
        try:
            if msg_type == "file":
                nonce_b64 = encrypted.get("nonce", "")
                ct_b64 = encrypted.get("ciphertext", "")
                if nonce_b64 and ct_b64:
                    data = decrypt_file_data(
                        nonce_b64, ct_b64,
                        self.identity["x25519_private"],
                        self.contact_pubkeys[from_uuid]["x25519"]
                    )
                    fname = encrypted.get("filename", "unknown")
                    if self.config.get("auto_download_files", True):
                        dl_dir = os.path.join(get_data_dir(), "downloads")
                        os.makedirs(dl_dir, exist_ok=True)
                        fp = os.path.join(dl_dir, fname)
                        with open(fp, "wb") as f:
                            f.write(data)
                    self.msg_store.add_message(
                        from_uuid, "recv", f"[文件] {fname}",
                        filename=fname, filesize=len(data), is_file=True,
                        delivery_status="delivered", server_msg_id=server_msg_id,
                    )
                    if self.current_contact == from_uuid:
                        self._display_file_message({"filename": fname, "filesize": len(data)}, "recv", msg_id=server_msg_id)
                        self.root.after(100, self._check_visible_messages)
            else:
                plaintext = decrypt_message(
                    encrypted, self.identity["x25519_private"],
                    self.contact_pubkeys[from_uuid]["x25519"],
                    self.contact_pubkeys[from_uuid]["ed25519"]
                )
                ts = encrypted.get("timestamp", 0)
                self.msg_store.add_message(
                    from_uuid, "recv", plaintext,
                    timestamp=ts, delivery_status="delivered", server_msg_id=server_msg_id,
                )
                if self.current_contact == from_uuid:
                    # Collection 消息渲染为卡片
                    if is_collection_text(plaintext):
                        self._display_collection_card(plaintext, "recv", ts, msg_id=server_msg_id)
                    else:
                        self._display_text_message(plaintext, "recv", ts, msg_id=server_msg_id)
                    self.root.after(100, self._check_visible_messages)
        except Exception as e:
            self._show_error(f"消息解密失败: {e}")

    def _on_offline_queue(self, messages: list):
        for msg in messages:
            self._on_message(msg)

    # ===== 回执处理 =====
    def _on_delivery_receipt(self, msg: dict):
        server_msg_id = msg.get("server_msg_id", "")
        client_msg_id = msg.get("client_msg_id", "")
        status = msg.get("status", "delivered")
        if server_msg_id:
            self.msg_store.update_delivery_status_by_server_id(server_msg_id, status)
        if client_msg_id:
            self.msg_store.update_delivery_status_by_msg_id(client_msg_id, status)
        if client_msg_id:
            self._update_receipt_display(client_msg_id, status)
        print(f"[RECEIPT] ✓ Delivered: {client_msg_id[:16]}... status={status}")

    def _on_read_receipt(self, msg: dict):
        server_msg_id = msg.get("server_msg_id", "")
        client_msg_id = msg.get("client_msg_id", "")
        from_uuid = msg.get("from_uuid", "")
        if server_msg_id:
            self.msg_store.update_delivery_status_by_server_id(server_msg_id, "read")
        if client_msg_id:
            self.msg_store.update_delivery_status_by_msg_id(client_msg_id, "read")
            self._update_receipt_display(client_msg_id, "read")
        print(f"[RECEIPT] ✓✓ Read: {client_msg_id[:16]}... from={from_uuid[:16]}...")

    def _on_read_receipt_disabled(self, msg: dict):
        client_msg_id = msg.get("client_msg_id", "")
        reason = msg.get("reason", "对方已关闭已读回执功能")
        if client_msg_id:
            self._update_receipt_display(client_msg_id, "delivered")
            self._append_system_notice(f"📌 {reason}，不会收到已读回执")
        print(f"[RECEIPT] Read receipts disabled by peer: {reason}")

    def _append_system_notice(self, text: str):
        notice = ctk.CTkLabel(self.chat_scroll, text=text, font=("Arial", 9), text_color="#888888")
        notice.pack(anchor="center", padx=10, pady=2)
        self._scroll_chat_to_bottom()

    # ===== 群组消息 =====
    def _on_group_message(self, msg: dict):
        group_id = msg.get("group_id", "")
        from_uuid = msg.get("from_uuid", "")
        encrypted = msg.get("encrypted_payload", {})
        timestamp = msg.get("timestamp", int(time.time()))
        if from_uuid in self.contact_pubkeys:
            try:
                plaintext = decrypt_message(
                    encrypted, self.identity["x25519_private"],
                    self.contact_pubkeys[from_uuid]["x25519"],
                    self.contact_pubkeys[from_uuid]["ed25519"]
                )
                group_key = f"group:{group_id}"
                self.msg_store.add_message(group_key, "recv", plaintext, timestamp=timestamp)
                if self.current_contact == group_key:
                    self._display_text_message(f"[{from_uuid[:8]}] {plaintext}", "recv", timestamp)
            except Exception as e:
                print(f"[GROUP] Decrypt failed: {e}")
        else:
            self._fetch_peer_pubkey(from_uuid)

    def _on_group_event(self, msg: dict):
        event = msg.get("event", "")
        group_id = msg.get("group_id", "")
        if event == "member_joined":
            self._show_info(f"用户 {msg.get('uuid','')[:8]} 加入了群 {group_id[:8]}")
        elif event == "member_left":
            self._show_info(f"用户 {msg.get('uuid','')[:8]} 离开了群 {group_id[:8]}")
        elif event == "joined":
            self._show_info(f"成功加入群 {group_id[:8]}")
        elif event == "federated":
            self._show_info(f"群 {group_id[:8]} 已与服务器 {msg.get('target_server','')[:16]} 建立联邦")
        elif event == "join_redirect":
            self._show_info(f"群 {group_id[:8]} 在远程服务器上，正在重定向...")

    def _send_group_text(self, group_id: str, text: str):
        if group_id not in [g.get("group_id", "") for g in self._get_my_groups()]:
            self._show_error("你不在该群组中")
            return
        try:
            client_msg_id = generate_msg_id()
            encrypted = encrypt_message(
                text, self.identity["x25519_private"],
                self.identity["x25519_public"],
                self.identity["ed25519_private"], self.uuid, group_id
            )
            env = {
                "type": SEND_GROUP_MSG, "group_id": group_id,
                "encrypted_payload": encrypted, "client_msg_id": client_msg_id,
            }
            sig_data = json.dumps(env, sort_keys=True).encode()
            e_priv = load_ed25519_private(self.identity["ed25519_private"])
            signature = sign_data(e_priv, sig_data)
            self.cross_server.send_group_message(group_id, encrypted, signature)
            group_key = f"group:{group_id}"
            self.msg_store.add_message(group_key, "sent", text,
                                       timestamp=encrypted["timestamp"],
                                       delivery_status="sending", msg_id=client_msg_id)
            self._display_text_message(f"[我] {text}", "sent",
                                        encrypted["timestamp"],
                                        delivery_status="sending", msg_id=client_msg_id)
        except Exception as e:
            self._show_error(f"群消息发送失败: {e}")

    def _get_my_groups(self) -> list:
        if not hasattr(self, '_my_groups'):
            self._my_groups = []
            self.cross_server.list_my_groups()
        return self._my_groups

    def _create_group_dialog(self):
        win = ctk.CTkToplevel(self.root)
        win.title("创建群聊")
        win.geometry("400x300")
        ctk.CTkLabel(win, text="群名称:").pack(pady=(10, 0))
        name_entry = ctk.CTkEntry(win, placeholder_text="输入群名称")
        name_entry.pack(pady=2)
        ctk.CTkLabel(win, text="成员UUID (逗号分隔):").pack(pady=(10, 0))
        members_entry = ctk.CTkEntry(win, placeholder_text="uuid1,uuid2,uuid3")
        members_entry.pack(pady=2)
        fed_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(win, text="跨服务器联邦群", variable=fed_var).pack(pady=10)
        def do_create():
            name = name_entry.get().strip()
            members_raw = members_entry.get().strip()
            members = [m.strip() for m in members_raw.split(",") if m.strip()] if members_raw else []
            if not name:
                self._show_error("请输入群名称")
                return
            self.cross_server.create_group(name, members, federated=fed_var.get())
            win.destroy()
            self._show_info(f"正在创建群 '{name}'...")
        ctk.CTkButton(win, text="创建", command=do_create).pack(pady=10)

    def _search_group_dialog(self):
        query = simpledialog.askstring("搜索群聊", "输入群名称:", parent=self.root)
        if query:
            self.cross_server.search_groups(query, scope="global")

    # ===== 网络事件 =====
    def _on_broadcast(self, msg: dict):
        self._show_info(f"📢 系统广播: {msg.get('text', '')}")

    def _on_error(self, err: str):
        self._show_error(f"网络错误: {err}")

    def _on_disconnect(self):
        self._show_error("与服务器断开连接")

    # ===== 管理员 =====
    def _on_admin_result(self, result: dict):
        if isinstance(result, dict) and result.get("type") == "auth_ok":
            self.admin_token = result.get("token")
            self.is_admin = True
            self._show_info("管理员认证成功")
            self._open_admin_panel()
        elif isinstance(result, dict) and result.get("type") == "auth_fail":
            self._show_error(f"管理员认证失败: {result.get('reason', '')}")
        else:
            self._show_info(f"命令结果: {json.dumps(result, ensure_ascii=False)}")

    def _on_pubkey_result(self, msg: dict):
        uuid_str = msg.get("uuid", "")
        self.contact_pubkeys[uuid_str] = {
            "x25519": msg.get("x25519_public", ""),
            "ed25519": msg.get("ed25519_public", ""),
        }
        self._save_contacts_list()

    def _on_rate_limited(self, reason: str):
        self._show_error(f"消息被限速: {reason}")

    def _on_compromised_ack(self, msg: dict):
        self._show_info("胁迫通知已发送，正在清除本地数据...")
        wipe_all_data()
        self.root.quit()
        sys.exit(0)

    def _on_deadman_ack(self, msg: dict):
        """服务器确认已存储死人开关警告消息。"""
        stored = msg.get("stored", False)
        if stored:
            print("[DEADMAN] 服务器确认：警告消息已存储")
        else:
            print("[DEADMAN] 服务器存储警告消息失败")

    def _on_login_ok(self, msg: dict):
        """登录成功后，自动同步死人开关警告消息到服务器（如果已启用）。"""
        print("[DEADMAN] 登录成功，检查死人开关配置...")
        if self.deadman.is_enabled() and self.deadman.is_config_complete():
            self.deadman.sync_to_server()
        elif self.deadman.is_enabled():
            print("[DEADMAN] 死人开关已启用但配置不完整，请在设置中配置警告消息和收件人")

    def _on_lookup_result(self, msg: dict):
        results = msg.get("results", [])
        query = msg.get("query", "")
        if not results:
            self._show_info(f"未找到匹配 '{query}' 的用户")
            return
        for r in results:
            uuid_str = r.get("uuid", "")
            if uuid_str:
                server_id = r.get("server_node_id", "")
                if server_id:
                    self.cross_server.contact_server_map[uuid_str] = server_id
                pub_x = r.get("x25519_public", "")
                pub_e = r.get("ed25519_public", "")
                name = r.get("name", uuid_str[:8])
                exists = any(c["uuid"] == uuid_str for c in self.contacts)
                if not exists:
                    self.contacts.append({
                        "uuid": uuid_str, "name": name,
                        "x25519_public": pub_x, "ed25519_public": pub_e,
                        "blocked": False, "server_node_id": server_id,
                    })
                if pub_x and pub_e:
                    self.contact_pubkeys[uuid_str] = {"x25519": pub_x, "ed25519": pub_e}
        self._save_contacts_list()
        self._refresh_contact_list_ctk()
        self._show_info(f"找到 {len(results)} 个用户，已添加到联系人")

    def _on_group_list_result(self, msg: dict):
        self._my_groups = msg.get("groups", [])
        self._show_info(f"你加入了 {len(self._my_groups)} 个群聊")

    def _on_group_info_result(self, msg: dict):
        group = msg.get("group", {})
        members = msg.get("members", [])
        info = f"群: {group.get('name','')}\nID: {group.get('group_id','')[:16]}...\n成员数: {len(members)}\n"
        for m in members[:10]:
            info += f"  - {m.get('uuid','')[:16]}... {'👑' if m.get('is_admin') else ''}\n"
        if len(members) > 10:
            info += f"  ... 还有 {len(members)-10} 人"
        self._show_info(info)

    def _on_group_search_result(self, msg: dict):
        results = msg.get("results", [])
        if not results:
            self._show_info("未找到匹配的群聊")
            return
        text = f"找到 {len(results)} 个群聊:\n"
        for g in results:
            text += f"  📢 {g.get('name','')} (ID: {g.get('group_id','')[:8]}...)\n"
        self._show_info(text)

    def _on_group_create_result(self, msg: dict):
        status = msg.get("status", "")
        group_id = msg.get("group_id", "")
        name = msg.get("name", "")
        if status == "created":
            self._show_info(f"群 '{name}' 创建成功!\nID: {group_id[:16]}...")
            self.cross_server.list_my_groups()
        else:
            self._show_error(f"群创建失败: {status}")

    def _fetch_peer_pubkey(self, uuid_str: str):
        try:
            self.tcp.query_pubkey(uuid_str)
        except Exception:
            pass

    # ===== 管理员面板 =====
    def _open_admin_panel(self):
        if not self.is_admin:
            pin = simpledialog.askstring("管理员认证", "输入管理员PIN:", show="*", parent=self.root)
            if pin and len(pin) == 6 and pin.isdigit():
                e_priv = load_ed25519_private(self.identity["ed25519_private"])
                sig_data = f"ADMIN_AUTH:{pin}".encode()
                signature = sign_data(e_priv, sig_data)
                self.tcp.admin_auth(pin, signature)
            return
        self._build_admin_panel_ctk()

    def _build_admin_panel_ctk(self):
        win = ctk.CTkToplevel(self.root)
        win.title("🔧 服务器管理")
        win.geometry("500x600")
        tabview = ctk.CTkTabview(win)
        tabview.pack(fill="both", expand=True, padx=10, pady=10)
        tab_users = tabview.add("用户管理")
        ctk.CTkButton(tab_users, text="查看在线用户", command=lambda: self._admin_cmd(CMD_LIST_ONLINE)).pack(pady=5)
        ctk.CTkButton(tab_users, text="查看所有用户", command=lambda: self._admin_cmd(CMD_LIST_ALL_USERS)).pack(pady=5)
        ctk.CTkLabel(tab_users, text="创建用户:").pack(pady=(10, 0))
        self.admin_create_name = ctk.CTkEntry(tab_users, placeholder_text="用户名")
        self.admin_create_name.pack(pady=2)
        ctk.CTkButton(tab_users, text="创建", command=self._admin_create_user).pack(pady=2)
        ctk.CTkLabel(tab_users, text="封禁用户(UUID):").pack(pady=(10, 0))
        self.admin_ban_uuid = ctk.CTkEntry(tab_users, placeholder_text="UUID")
        self.admin_ban_uuid.pack(pady=2)
        ctk.CTkButton(tab_users, text="封禁", command=lambda: self._admin_cmd(CMD_BAN_USER, {"uuid": self.admin_ban_uuid.get()})).pack(pady=2)
        tab_rate = tabview.add("限速")
        ctk.CTkLabel(tab_rate, text="全局限速(秒/条):").pack(pady=(10, 0))
        self.admin_rate = ctk.CTkEntry(tab_rate, placeholder_text="0.5")
        self.admin_rate.pack(pady=2)
        ctk.CTkButton(tab_rate, text="设置", command=lambda: self._admin_cmd(CMD_SET_RATE_LIMIT, {"seconds": float(self.admin_rate.get() or 0.5)})).pack(pady=5)
        tab_file = tabview.add("文件")
        ctk.CTkLabel(tab_file, text="最大文件(MB):").pack(pady=(10, 0))
        self.admin_maxfile = ctk.CTkEntry(tab_file, placeholder_text="100")
        self.admin_maxfile.pack(pady=2)
        ctk.CTkButton(tab_file, text="设置", command=lambda: self._admin_cmd(CMD_SET_MAX_FILE_SIZE, {"mb": int(self.admin_maxfile.get() or 100)})).pack(pady=5)
        ctk.CTkButton(tab_file, text="清理过期文件", command=lambda: self._admin_cmd(CMD_CLEANUP_FILES)).pack(pady=5)
        tab_dht = tabview.add("DHT网络")
        ctk.CTkButton(tab_dht, text="查看路由表", command=lambda: self._admin_cmd(CMD_DHT_ROUTING_TABLE)).pack(pady=5)
        ctk.CTkButton(tab_dht, text="节点数", command=lambda: self._admin_cmd(CMD_DHT_NODE_COUNT)).pack(pady=5)
        ctk.CTkLabel(tab_dht, text="隐藏模式:").pack(pady=(10, 0))
        ctk.CTkButton(tab_dht, text="开启隐藏", command=lambda: self._admin_cmd(CMD_SET_HIDDEN, {"hidden": True})).pack(pady=2)
        ctk.CTkButton(tab_dht, text="关闭隐藏", command=lambda: self._admin_cmd(CMD_SET_HIDDEN, {"hidden": False})).pack(pady=2)
        tab_sys = tabview.add("系统")
        ctk.CTkButton(tab_sys, text="查看日志", command=lambda: self._admin_cmd(CMD_GET_LOGS, {"lines": 50})).pack(pady=5)
        ctk.CTkButton(tab_sys, text="连接统计", command=lambda: self._admin_cmd(CMD_CONN_STATS)).pack(pady=5)
        ctk.CTkLabel(tab_sys, text="广播通知:").pack(pady=(10, 0))
        self.admin_bcast = ctk.CTkEntry(tab_sys, placeholder_text="广播内容")
        self.admin_bcast.pack(pady=2)
        ctk.CTkButton(tab_sys, text="发送广播", command=lambda: self._admin_cmd(CMD_BROADCAST_MSG, {"text": self.admin_bcast.get()})).pack(pady=2)
        ctk.CTkButton(tab_sys, text="优雅关机", command=lambda: self._admin_cmd(CMD_SHUTDOWN)).pack(pady=(10, 0))

    def _admin_cmd(self, command: str, params: dict = None):
        if not self.admin_token:
            self._show_error("请先认证管理员")
            return
        self.tcp.admin_cmd(self.admin_token, command, params or {})

    def _admin_create_user(self):
        name = self.admin_create_name.get().strip()
        if not name:
            self._show_error("请输入用户名")
            return
        self._admin_cmd(CMD_CREATE_USER, {"name": name})

    # ===== 设置窗口 =====
    def _open_settings(self):
        win = ctk.CTkToplevel(self.root)
        win.title("设置")
        win.geometry("420x680")
        ctk.CTkLabel(win, text="发送消息颜色 (HEX):").pack(pady=(10, 0))
        sent_color = ctk.CTkEntry(win, placeholder_text=self.config.get("sent_message_color", DEFAULT_SENT_COLOR))
        sent_color.pack(pady=2)
        sent_color.insert(0, self.config.get("sent_message_color", DEFAULT_SENT_COLOR))
        ctk.CTkLabel(win, text="接收消息颜色 (HEX):").pack(pady=(10, 0))
        recv_color = ctk.CTkEntry(win, placeholder_text=self.config.get("recv_message_color", DEFAULT_RECV_COLOR))
        recv_color.pack(pady=2)
        recv_color.insert(0, self.config.get("recv_message_color", DEFAULT_RECV_COLOR))
        ctk.CTkLabel(win, text="按钮颜色 (HEX):").pack(pady=(10, 0))
        btn_color = ctk.CTkEntry(win, placeholder_text=self.config.get("send_button_color", DEFAULT_BUTTON_COLOR))
        btn_color.pack(pady=2)
        btn_color.insert(0, self.config.get("send_button_color", DEFAULT_BUTTON_COLOR))
        auto_dl = ctk.BooleanVar(value=self.config.get("auto_download_files", True))
        ctk.CTkCheckBox(win, text="自动下载文件", variable=auto_dl).pack(pady=10)

        ctk.CTkLabel(win, text="── 隐私 ──", font=("Arial", 12, "bold")).pack(pady=(10, 5))
        read_rcpt_var = ctk.BooleanVar(value=self.read_receipts_enabled)
        ctk.CTkCheckBox(win, text="发送已读回执（关闭后不会通知对方你已读消息）", variable=read_rcpt_var).pack(pady=5, padx=10, anchor="w")

        # ===== 死人开关 =====
        ctk.CTkLabel(win, text="── 死人开关 ──", font=("Arial", 12, "bold")).pack(pady=(15, 5))
        deadman_cfg = self.deadman.get_config()
        deadman_enabled_var = ctk.BooleanVar(value=deadman_cfg["enabled"])
        ctk.CTkCheckBox(win, text="启用死人开关（长期未登录时自动发送警告消息）",
                         variable=deadman_enabled_var).pack(pady=2, padx=10, anchor="w")
        ctk.CTkLabel(win, text="警告消息内容：").pack(anchor="w", padx=10, pady=(5, 0))
        deadman_msg_entry = ctk.CTkEntry(win, placeholder_text="输入要发送的警告消息")
        deadman_msg_entry.pack(fill="x", padx=10, pady=2)
        if deadman_cfg["warning_message"]:
            deadman_msg_entry.insert(0, deadman_cfg["warning_message"])
        ctk.CTkLabel(win, text="预定收件人 UUID：").pack(anchor="w", padx=10, pady=(5, 0))
        deadman_recipient_entry = ctk.CTkEntry(win, placeholder_text="输入收件人 UUID")
        deadman_recipient_entry.pack(fill="x", padx=10, pady=2)
        if deadman_cfg["recipient_uuid"]:
            deadman_recipient_entry.insert(0, deadman_cfg["recipient_uuid"])
        grace_row = ctk.CTkFrame(win)
        grace_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(grace_row, text="宽限期（天）：").pack(side="left")
        deadman_grace_entry = ctk.CTkEntry(grace_row, width=80)
        deadman_grace_entry.pack(side="left", padx=5)
        deadman_grace_entry.insert(0, str(deadman_cfg["grace_days"]))
        ctk.CTkLabel(win, text="超过宽限期未登录，服务器将先把警告消息发给收件人，再执行胁迫操作。",
                     font=("Arial", 9), text_color="gray").pack(padx=10, pady=2)

        ctk.CTkLabel(win, text="── 个人资料 ──", font=("Arial", 12, "bold")).pack(pady=(15, 5))
        current_name = get_display_name()
        ctk.CTkLabel(win, text="显示名称 (4-32字节 UTF-8):").pack(anchor="w", padx=10)
        name_entry = ctk.CTkEntry(win, placeholder_text="输入显示名称")
        name_entry.pack(fill="x", padx=10, pady=2)
        if current_name:
            name_entry.insert(0, current_name)
        btn_row = ctk.CTkFrame(win)
        btn_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkButton(btn_row, text="📷 设置头像", width=100, command=self._choose_avatar).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="🗑 清除头像", width=100, command=self._clear_avatar_btn).pack(side="left", padx=5)
        ctk.CTkButton(win, text="保存显示名称", width=120, command=lambda: self._save_display_name(name_entry.get())).pack(pady=5)

        ctk.CTkLabel(win, text="── 群聊 ──", font=("Arial", 12, "bold")).pack(pady=(15, 5))
        ctk.CTkButton(win, text="➕ 创建群聊", command=self._create_group_dialog).pack(pady=2)
        ctk.CTkButton(win, text="🔍 搜索群聊", command=self._search_group_dialog).pack(pady=2)
        ctk.CTkButton(win, text="📋 我的群聊", command=lambda: self.cross_server.list_my_groups()).pack(pady=2)
        ctk.CTkButton(win, text="🔧 管理员登录", command=self._open_admin_panel).pack(pady=5)

        def save():
            self.config["sent_message_color"] = sent_color.get() or DEFAULT_SENT_COLOR
            self.config["recv_message_color"] = recv_color.get() or DEFAULT_RECV_COLOR
            self.config["send_button_color"] = btn_color.get() or DEFAULT_BUTTON_COLOR
            self.config["auto_download_files"] = auto_dl.get()
            self.read_receipts_enabled = read_rcpt_var.get()
            self.config["read_receipts_enabled"] = self.read_receipts_enabled
            # 死人开关配置
            grace_days = 7
            try:
                grace_days = int(deadman_grace_entry.get() or "7")
            except ValueError:
                grace_days = 7
            self.deadman.set_config(
                enabled=deadman_enabled_var.get(),
                warning_message=deadman_msg_entry.get().strip(),
                recipient_uuid=deadman_recipient_entry.get().strip(),
                grace_days=grace_days,
                auto_sync=True,
            )
            self.config = load_config()  # 重新加载以包含 deadman 配置
            save_config(self.config)
            self._show_info("设置已保存")
            win.destroy()
        ctk.CTkButton(win, text="保存全部", command=save).pack(pady=10)

    def _choose_avatar(self):
        path = filedialog.askopenfilename(
            title="选择头像图片",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.webp *.gif"), ("All files", "*.*")],
            parent=self.root)
        if path:
            ok, msg = set_avatar(path)
            self._show_info(msg) if ok else self._show_error(msg)

    def _clear_avatar_btn(self):
        self._show_info("头像已清除") if clear_avatar() else self._show_error("清除头像失败")

    def _save_display_name(self, name: str):
        ok, msg = set_display_name(name.strip())
        self._show_info(msg) if ok else self._show_error(msg)

    # ===== 工具方法 =====
    def _get_contact(self, uuid_str: str):
        for c in self.contacts:
            if c["uuid"] == uuid_str:
                return c
        return None

    def _load_contacts_list(self) -> list:
        from client.storage.identity import load_contacts
        return load_contacts()

    def _save_contacts_list(self):
        from client.storage.identity import save_contacts
        save_contacts(self.contacts)

    def _show_error(self, msg: str):
        print(f"[ERROR] {msg}")
        try:
            messagebox.showerror("错误", msg, parent=self.root)
        except Exception:
            messagebox.showerror("错误", msg)

    def _show_info(self, msg: str):
        print(f"[INFO] {msg}")
        try:
            messagebox.showinfo("提示", msg, parent=self.root)
        except Exception:
            messagebox.showinfo("提示", msg)

    # ===== 启动 / 关闭 =====
    def _connect_and_login(self):
        try:
            self.tcp.connect()
            e_priv = load_ed25519_private(self.identity["ed25519_private"])
            login_data = json.dumps({
                "type": LOGIN, "uuid": self.uuid, "ed25519_public": self.identity["ed25519_public"]
            }, sort_keys=True).encode()
            signature = sign_data(e_priv, login_data)
            self.tcp.login(self.uuid, self.identity["ed25519_public"], signature)
        except Exception as e:
            self._show_error(f"连接服务器失败: {e}")
            self._on_close()

    def _on_close(self):
        try:
            self.tcp.disconnect()
        except Exception:
            pass
        clear_all_sessions()
        self.root.quit()
        sys.exit(0)

    def run(self):
        self.root.mainloop()
