"""
API 管理对话框。
- API 服务器端口设置 + 启动/停止
- API Key 管理（创建/列表/删除）
- 细粒度权限选择
- 有效期设置
- 攻击面过宽警告
"""

import time
import customtkinter as ctk
import tkinter as tk

from client.storage.api_keys import (
    create_api_key, list_api_keys, delete_api_key,
    ALL_PERMISSIONS, is_attack_surface_warning, get_total_permission_count,
)
from client.api.server import api_server


PERMISSION_LABELS = {
    "messages:send": "发送消息",
    "messages:read": "读取消息",
    "messages:delete": "删除消息",
    "contacts:read": "读取联系人",
    "contacts:add": "添加联系人",
    "contacts:delete": "删除联系人",
    "profile:read": "读取资料",
    "profile:write": "修改资料",
    "settings:read": "读取设置",
    "settings:write": "修改设置",
    "deadman:read": "读取死人开关",
    "deadman:write": "修改死人开关",
    "groups:read": "读取群聊",
    "groups:write": "管理群聊",
    "files:send": "发送文件",
    "files:download": "下载文件",
}


class APIManagerDialog:
    def __init__(self, parent, config):
        self.parent = parent
        self.config = config
        self.win = ctk.CTkToplevel(parent)
        self.win.title("API 管理")
        self.win.geometry("640x720")
        self.win.transient(parent)
        self.win.grab_set()
        self._key_vars = {}
        self._build()

    def _build(self):
        # ===== API 服务器 =====
        ctk.CTkLabel(self.win, text="── HTTP API 服务器 ──", font=("Arial", 12, "bold")).pack(pady=(10, 5))

        server_frame = ctk.CTkFrame(self.win)
        server_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(server_frame, text="端口:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.port_entry = ctk.CTkEntry(server_frame, width=100)
        self.port_entry.insert(0, str(self.config.get("api_port", 8765)))
        self.port_entry.grid(row=0, column=1, padx=5, pady=5)

        self.server_status_label = ctk.CTkLabel(server_frame, text="", font=("Arial", 10))
        self.server_status_label.grid(row=0, column=2, padx=10, pady=5)

        self.server_btn = ctk.CTkButton(server_frame, text="启动服务器", width=100, command=self._toggle_server)
        self.server_btn.grid(row=0, column=3, padx=5, pady=5)

        self._update_server_status()

        # ===== 攻击面警告 =====
        self.warning_label = ctk.CTkLabel(self.win, text="", text_color="red", font=("Arial", 10, "bold"))
        self.warning_label.pack(pady=2)
        self._update_warning()

        # ===== API Key 列表 =====
        ctk.CTkLabel(self.win, text="── API Keys ──", font=("Arial", 12, "bold")).pack(pady=(10, 5))

        list_frame = ctk.CTkFrame(self.win)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.key_listbox = tk.Listbox(list_frame, font=("Consolas", 9), bg="#1a1a2e", fg="white",
                                        selectbackground="#3a3a5e", activestyle="none")
        self.key_listbox.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        scrollbar = ctk.CTkScrollbar(list_frame, command=self.key_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.key_listbox.config(yscrollcommand=scrollbar.set)

        self._refresh_key_list()

        # ===== 按钮 =====
        btn_frame = ctk.CTkFrame(self.win)
        btn_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkButton(btn_frame, text="➕ 创建新 Key", width=120, command=self._open_create_dialog).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="🗑 删除选中", width=120, command=self._delete_selected).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="关闭", width=80, command=self.win.destroy).pack(side="right", padx=5)

    def _update_server_status(self):
        if api_server.is_running:
            self.server_status_label.configure(text=f"运行中 (端口 {api_server.port})", text_color="green")
            self.server_btn.configure(text="停止服务器")
        else:
            self.server_status_label.configure(text="未运行", text_color="gray")
            self.server_btn.configure(text="启动服务器")

    def _toggle_server(self):
        if api_server.is_running:
            api_server.stop()
            self._update_server_status()
        else:
            try:
                port = int(self.port_entry.get())
            except ValueError:
                self._show_error("端口必须是数字")
                return
            ok, msg = api_server.start(port)
            if ok:
                self.config["api_port"] = port
                self._update_server_status()
            else:
                self._show_error(msg)

    def _update_warning(self):
        if is_attack_surface_warning():
            total = get_total_permission_count()
            self.warning_label.configure(text=f"⚠ 攻击面过宽警告：全部 API 共 {total} 项权限（>15），建议精简")
        else:
            self.warning_label.configure(text="")

    def _refresh_key_list(self):
        self.key_listbox.delete(0, tk.END)
        keys = list_api_keys()
        if not keys:
            self.key_listbox.insert(tk.END, "  (暂无 API Key)")
            return
        for k in keys:
            expiry_str = "永久"
            if k.get("expiry"):
                remaining = k["expiry"] - time.time()
                if remaining > 0:
                    expiry_str = f"{remaining/3600:.1f}小时后过期"
                else:
                    expiry_str = "已过期"
            perms = ",".join(PERMISSION_LABELS.get(p, p) for p in k["permissions"])
            line = f"  {k['mask']}  |  {k['name']}  |  {perms}  |  {expiry_str}"
            self.key_listbox.insert(tk.END, line)
            self._key_vars[line] = k["key_hash"]

    def _open_create_dialog(self):
        CreateKeyDialog(self.win, self._on_key_created)

    def _on_key_created(self):
        self._refresh_key_list()
        self._update_warning()

    def _delete_selected(self):
        sel = self.key_listbox.curselection()
        if not sel:
            self._show_error("请先选择一个 Key")
            return
        line = self.key_listbox.get(sel[0])
        key_hash = self._key_vars.get(line)
        if not key_hash:
            return
        if delete_api_key(key_hash):
            self._refresh_key_list()
            self._update_warning()
        else:
            self._show_error("删除失败")

    def _show_error(self, msg):
        ctk.CTkLabel(self.win, text=msg, text_color="red").pack(pady=2)
        self.win.after(3000, lambda: self.win.winfo_children()[-1].destroy())


class CreateKeyDialog:
    def __init__(self, parent, on_created):
        self.on_created = on_created
        self.win = ctk.CTkToplevel(parent)
        self.win.title("创建 API Key")
        self.win.geometry("480x620")
        self.win.transient(parent)
        self.win.grab_set()
        self._perm_vars = {}
        self._build()

    def _build(self):
        ctk.CTkLabel(self.win, text="Key 名称:").pack(anchor="w", padx=10, pady=(10, 0))
        self.name_entry = ctk.CTkEntry(self.win, placeholder_text="例如：自动化脚本")
        self.name_entry.pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(self.win, text="有效期（小时，负数=永久）:").pack(anchor="w", padx=10, pady=(10, 0))
        self.expiry_entry = ctk.CTkEntry(self.win, width=100)
        self.expiry_entry.insert(0, "-1")
        self.expiry_entry.pack(anchor="w", padx=10, pady=2)

        ctk.CTkLabel(self.win, text="权限（每项0.1，总>15警告）:", font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 5))

        perm_frame = ctk.CTkScrollableFrame(self.win, height=300)
        perm_frame.pack(fill="both", expand=True, padx=10, pady=2)

        for i, perm in enumerate(ALL_PERMISSIONS):
            var = ctk.BooleanVar(value=False)
            label = PERMISSION_LABELS.get(perm, perm)
            cb = ctk.CTkCheckBox(perm_frame, text=f"{label} ({perm})", variable=var)
            cb.grid(row=i // 2, column=i % 2, sticky="w", padx=5, pady=2)
            self._perm_vars[perm] = var

        btn_frame = ctk.CTkFrame(self.win)
        btn_frame.pack(fill="x", padx=10, pady=10)

        ctk.CTkButton(btn_frame, text="全选", width=60, command=self._select_all).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="全不选", width=60, command=self._select_none).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="创建", width=80, command=self._create).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="取消", width=80, command=self.win.destroy).pack(side="right", padx=5)

    def _select_all(self):
        for v in self._perm_vars.values():
            v.set(True)

    def _select_none(self):
        for v in self._perm_vars.values():
            v.set(False)

    def _create(self):
        name = self.name_entry.get().strip()
        if not name:
            self._show_error("请输入 Key 名称")
            return
        try:
            expiry = float(self.expiry_entry.get())
        except ValueError:
            self._show_error("有效期必须是数字")
            return
        perms = [p for p, v in self._perm_vars.items() if v.get()]
        if not perms:
            self._show_error("至少选择一项权限")
            return

        result = create_api_key(name, perms, expiry)

        # 显示完整 key（只此一次）
        self.win.geometry("520x300")
        for w in self.win.winfo_children():
            w.destroy()

        ctk.CTkLabel(self.win, text="API Key 已创建！", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(self.win, text="请立即复制，之后只显示前8后4位：", text_color="red").pack(pady=2)

        key_text = ctk.CTkTextbox(self.win, height=80, font=("Consolas", 9))
        key_text.pack(fill="x", padx=10, pady=5)
        key_text.insert("1.0", result["key"])
        key_text.configure(state="disabled")

        ctk.CTkButton(self.win, text="复制并关闭", width=120,
                       command=lambda: [self.win.clipboard_clear(), self.win.clipboard_append(result["key"]),
                                         self.on_created(), self.win.destroy()]).pack(pady=10)

    def _show_error(self, msg):
        ctk.CTkLabel(self.win, text=msg, text_color="red").pack(pady=2)
