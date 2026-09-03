"""
实验性功能解锁对话框。

启用流程：
1. 验证解锁密码（PIN）
2. 键入"打开实验性功能"
3. 滑块冷却期 5 秒
4. 滑块滑到最右边才能启用
关闭直接关闭即可。
"""

import time
import customtkinter as ctk
import tkinter as tk

from client.experimental.manager import (
    is_experimental_enabled, enable_experimental, disable_experimental,
    get_all_features, enable_feature, disable_feature, is_feature_enabled,
)
from client.storage.identity import check_unlock_pin_hash

CONFIRM_TEXT = "打开实验性功能"


class ExperimentalDialog:
    def __init__(self, parent, on_features_changed=None):
        self.parent = parent
        self.on_features_changed = on_features_changed
        self.win = ctk.CTkToplevel(parent)
        self.win.title("实验性功能")
        self.win.geometry("520x600")
        self.win.transient(parent)
        self.win.grab_set()
        self._slider_cooldown_end = 0
        self._build()

    def _build(self):
        if is_experimental_enabled():
            self._build_enabled_view()
        else:
            self._build_locked_view()

    def _clear(self):
        for w in self.win.winfo_children():
            w.destroy()

    # ===== 锁定视图 =====
    def _build_locked_view(self):
        self._clear()
        ctk.CTkLabel(self.win, text="实验性功能", font=("Arial", 16, "bold")).pack(pady=(20, 5))
        ctk.CTkLabel(self.win, text="实验性功能可能包含不稳定的高级功能，启用前请确认。",
                     text_color="gray", wraplength=400).pack(pady=5)

        # 步骤 1: PIN 验证
        ctk.CTkLabel(self.win, text="第 1 步：验证解锁密码", font=("Arial", 11, "bold")).pack(anchor="w", padx=20, pady=(15, 2))
        self.pin_entry = ctk.CTkEntry(self.win, show="*", placeholder_text="输入解锁 PIN")
        self.pin_entry.pack(fill="x", padx=20, pady=2)
        self.pin_status = ctk.CTkLabel(self.win, text="", text_color="red", font=("Arial", 9))
        self.pin_status.pack(anchor="w", padx=20)

        # 步骤 2: 键入确认
        ctk.CTkLabel(self.win, text=f'第 2 步：键入"{CONFIRM_TEXT}"', font=("Arial", 11, "bold")).pack(anchor="w", padx=20, pady=(10, 2))
        self.confirm_entry = ctk.CTkEntry(self.win, placeholder_text=f"请输入: {CONFIRM_TEXT}")
        self.confirm_entry.pack(fill="x", padx=20, pady=2)
        self.confirm_status = ctk.CTkLabel(self.win, text="", text_color="red", font=("Arial", 9))
        self.confirm_status.pack(anchor="w", padx=20)

        # 步骤 3: 滑块
        ctk.CTkLabel(self.win, text="第 3 步：等待冷却后滑到最右", font=("Arial", 11, "bold")).pack(anchor="w", padx=20, pady=(10, 2))

        slider_frame = ctk.CTkFrame(self.win)
        slider_frame.pack(fill="x", padx=20, pady=5)

        self.slider = ctk.CTkSlider(slider_frame, from_=0, to=100, number_of_steps=100,
                                      command=self._on_slider_change)
        self.slider.set(0)
        self.slider.pack(side="left", fill="x", expand=True, padx=5)
        self.slider.configure(state="disabled")

        self.slider_label = ctk.CTkLabel(slider_frame, text="5s", width=40, font=("Consolas", 11))
        self.slider_label.pack(side="right", padx=5)

        self.enable_btn = ctk.CTkButton(self.win, text="开始验证", width=150, command=self._start_verification)
        self.enable_btn.pack(pady=15)

        ctk.CTkButton(self.win, text="关闭", width=80, command=self.win.destroy).pack(pady=5)

    def _start_verification(self):
        # 验证 PIN
        pin = self.pin_entry.get()
        if not check_unlock_pin_hash(pin):
            self.pin_status.configure(text="PIN 错误")
            return
        self.pin_status.configure(text="PIN 正确", text_color="green")

        # 验证确认文本
        confirm = self.confirm_entry.get().strip()
        if confirm != CONFIRM_TEXT:
            self.confirm_status.configure(text=f'请准确输入: "{CONFIRM_TEXT}"')
            return
        self.confirm_status.configure(text="确认正确", text_color="green")

        # 开始冷却
        self.enable_btn.configure(state="disabled", text="验证中...")
        self._slider_cooldown_end = time.time() + 5
        self._tick_cooldown()

    def _tick_cooldown(self):
        remaining = self._slider_cooldown_end - time.time()
        if remaining > 0:
            self.slider_label.configure(text=f"{remaining:.1f}s")
            self.win.after(100, self._tick_cooldown)
        else:
            self.slider_label.configure(text="滑动→")
            self.slider.configure(state="normal")
            self.enable_btn.configure(text="滑到最右启用", state="normal")

    def _on_slider_change(self, value):
        if value >= 99:
            # 启用实验性功能
            enable_experimental()
            self._build_enabled_view()
            if self.on_features_changed:
                self.on_features_changed()

    # ===== 已启用视图 =====
    def _build_enabled_view(self):
        self._clear()
        ctk.CTkLabel(self.win, text="实验性功能", font=("Arial", 16, "bold")).pack(pady=(15, 5))
        ctk.CTkLabel(self.win, text="状态：已启用", text_color="green", font=("Arial", 11, "bold")).pack(pady=2)

        ctk.CTkLabel(self.win, text="── 功能列表 ──", font=("Arial", 11, "bold")).pack(anchor="w", padx=15, pady=(15, 5))

        features_frame = ctk.CTkScrollableFrame(self.win, height=250)
        features_frame.pack(fill="both", expand=True, padx=15, pady=5)

        self._feature_vars = {}
        features = get_all_features()
        for i, f in enumerate(features):
            row = ctk.CTkFrame(features_frame)
            row.pack(fill="x", pady=3)

            var = ctk.BooleanVar(value=f["enabled"])
            cb = ctk.CTkCheckBox(row, text=f["name"], variable=var,
                                  command=lambda fid=f["id"], v=var: self._toggle_feature(fid, v))
            cb.pack(side="left", padx=5, pady=5)

            desc = ctk.CTkLabel(row, text=f["description"], text_color="gray",
                                 font=("Arial", 9), wraplength=350, justify="left")
            desc.pack(side="left", padx=5, pady=5)

            if f.get("requires"):
                req_label = ctk.CTkLabel(row, text=f"需要: {','.join(f['requires'])}",
                                          text_color="orange", font=("Arial", 8))
                req_label.pack(side="right", padx=5)

            self._feature_vars[f["id"]] = var

        # 关闭总开关
        ctk.CTkLabel(self.win, text="关闭实验性功能将同时关闭所有子功能",
                     text_color="gray", font=("Arial", 9)).pack(pady=(10, 2))
        ctk.CTkButton(self.win, text="关闭实验性功能", width=150, fg_color="red",
                       command=self._disable_all).pack(pady=5)
        ctk.CTkButton(self.win, text="关闭", width=80, command=self.win.destroy).pack(pady=5)

    def _toggle_feature(self, feature_id, var):
        if var.get():
            ok, msg = enable_feature(feature_id)
            if not ok:
                var.set(False)
                self._show_toast(msg)
            elif self.on_features_changed:
                self.on_features_changed()
        else:
            disable_feature(feature_id)
            if self.on_features_changed:
                self.on_features_changed()

    def _disable_all(self):
        disable_experimental()
        self._build_locked_view()
        if self.on_features_changed:
            self.on_features_changed()

    def _show_toast(self, msg):
        toast = ctk.CTkLabel(self.win, text=msg, text_color="red", fg_color="#2a2a2a", corner_radius=5)
        toast.place(relx=0.5, rely=0.9, anchor="center")
        self.win.after(2500, toast.destroy)
