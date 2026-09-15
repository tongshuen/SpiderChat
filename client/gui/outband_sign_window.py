"""
带外签名工具窗口（GUI）。

功能：
    - 模式选择：账号所有权证明（输入外部挑战 nonce）/ 自定义文本签名
    - 生成签名：调用 sign_outband 输出可复制的签名串
    - 校验签名：粘贴签名串 + 原文，显示有效/无效、签名账号 UUID、签名时间、模式

安全：
    - 私钥仅从已解锁身份中读取，全程在本地内存使用，不上传任何服务器。
"""

import tkinter as tk
from tkinter import messagebox

try:
    import customtkinter as ctk
except Exception:  # 无 GUI 环境容错
    ctk = None

from client.crypto.outband_sign import sign_outband, verify_outband
from shared.protocol import OUTBAND_MODE_OWNERSHIP, OUTBAND_MODE_CONTENT


if ctk is not None:
    _Base = ctk.CTkToplevel
else:
    _Base = object


class OutbandSignWindow(_Base):
    """带外签名工具窗口。"""

    def __init__(self, parent, identity: dict):
        """
        Args:
            parent: 父窗口
            identity: 已解锁身份字典，需含 ed25519_private / ed25519_public / uuid
        """
        if ctk is None:
            raise RuntimeError("当前环境不支持图形界面（缺少 customtkinter）")

        self.identity = identity or {}
        self._priv_b64 = self.identity.get("ed25519_private", "")
        self._pub_b64 = self.identity.get("ed25519_public", "")
        self._uuid = self.identity.get("uuid", "")

        super().__init__(parent)
        self.title("带外签名工具")
        self.geometry("640x720")
        self.transient(parent)
        self._build()

    # ===== 界面 =====
    def _build(self):
        ctk.CTkLabel(self, text="带外签名（Out-of-Band Signature）",
                     font=("Arial", 16, "bold")).pack(pady=(15, 2))
        ctk.CTkLabel(self, text=f"签名账号 UUID：{self._uuid or '（未解锁）'}",
                     text_color="gray", font=("Consolas", 9),
                     wraplength=600).pack(pady=2)

        # ---- 模式选择 ----
        mode_frame = ctk.CTkFrame(self)
        mode_frame.pack(fill="x", padx=15, pady=(12, 5))
        ctk.CTkLabel(mode_frame, text="签名模式：", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
        self._mode_var = tk.StringVar(value=OUTBAND_MODE_CONTENT)
        ctk.CTkRadioButton(mode_frame, text="账号所有权证明（输入外部挑战 nonce）",
                           variable=self._mode_var, value=OUTBAND_MODE_OWNERSHIP,
                           command=self._on_mode_change).pack(anchor="w", padx=15, pady=2)
        ctk.CTkRadioButton(mode_frame, text="自定义文本签名（输入任意原文）",
                           variable=self._mode_var, value=OUTBAND_MODE_CONTENT,
                           command=self._on_mode_change).pack(anchor="w", padx=15, pady=(2, 8))

        # ---- 待签名输入 ----
        input_frame = ctk.CTkFrame(self)
        input_frame.pack(fill="x", padx=15, pady=5)
        self._input_label = ctk.CTkLabel(input_frame, text="待签名文本：",
                                         font=("Arial", 11, "bold"))
        self._input_label.pack(anchor="w", padx=10, pady=(8, 2))
        self._text_entry = ctk.CTkTextbox(input_frame, height=70)
        self._text_entry.pack(fill="x", padx=10, pady=(0, 10))

        ctk.CTkButton(input_frame, text="生成签名", width=140,
                      command=self._on_sign).pack(pady=(0, 10))

        # ---- 签名输出 ----
        out_frame = ctk.CTkFrame(self)
        out_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(out_frame, text="签名串：", font=("Arial", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
        self._sig_output = ctk.CTkTextbox(out_frame, height=80)
        self._sig_output.pack(fill="x", padx=10, pady=2)
        ctk.CTkButton(out_frame, text="复制签名串", width=140,
                      command=self._copy_signature).pack(pady=(2, 10))

        # ---- 校验区域 ----
        verify_frame = ctk.CTkFrame(self)
        verify_frame.pack(fill="both", expand=True, padx=15, pady=(10, 15))
        ctk.CTkLabel(verify_frame, text="── 校验签名 ──",
                     font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(8, 2))

        ctk.CTkLabel(verify_frame, text="粘贴签名串：",
                     font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(4, 2))
        self._verify_sig_entry = ctk.CTkTextbox(verify_frame, height=60)
        self._verify_sig_entry.pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(verify_frame, text="原始文本：",
                     font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(4, 2))
        self._verify_text_entry = ctk.CTkTextbox(verify_frame, height=50)
        self._verify_text_entry.pack(fill="x", padx=10, pady=2)

        ctk.CTkLabel(verify_frame, text="签名者公钥（base64，留空则用本账号公钥）：",
                     font=("Arial", 10, "bold")).pack(anchor="w", padx=10, pady=(4, 2))
        self._verify_pub_entry = ctk.CTkEntry(verify_frame, placeholder_text="留空使用本账号公钥")
        self._verify_pub_entry.pack(fill="x", padx=10, pady=2)

        ctk.CTkButton(verify_frame, text="核验", width=140,
                      command=self._on_verify).pack(pady=8)

        self._verify_result = ctk.CTkLabel(verify_frame, text="", justify="left",
                                            wraplength=580, font=("Consolas", 10))
        self._verify_result.pack(anchor="w", padx=10, pady=(0, 10))

    def _on_mode_change(self):
        mode = self._mode_var.get()
        if mode == OUTBAND_MODE_OWNERSHIP:
            self._input_label.configure(text="挑战 nonce（外部随机挑战）：")
        else:
            self._input_label.configure(text="待签名文本：")

    # ===== 生成签名 =====
    def _on_sign(self):
        if not self._priv_b64:
            messagebox.showerror("错误", "身份未解锁或缺少 Ed25519 私钥，无法签名")
            return
        text = self._text_entry.get("1.0", "end").rstrip("\n")
        mode = self._mode_var.get()
        try:
            sig = sign_outband(text=text, mode=mode,
                               ed25519_priv_b64=self._priv_b64, uuid=self._uuid)
        except Exception as e:
            messagebox.showerror("签名失败", str(e))
            return
        self._sig_output.delete("1.0", "end")
        self._sig_output.insert("1.0", sig)

    def _copy_signature(self):
        sig = self._sig_output.get("1.0", "end").strip()
        if not sig:
            return
        self.clipboard_clear()
        self.clipboard_append(sig)
        messagebox.showinfo("已复制", "签名串已复制到剪贴板")

    # ===== 校验 =====
    def _on_verify(self):
        sig = self._verify_sig_entry.get("1.0", "end").strip()
        original = self._verify_text_entry.get("1.0", "end").rstrip("\n")
        pub = self._verify_pub_entry.get().strip() or self._pub_b64
        if not sig:
            self._verify_result.configure(text="请先粘贴待校验的签名串", text_color="red")
            return
        if not pub:
            self._verify_result.configure(text="缺少公钥，无法校验", text_color="red")
            return

        result = verify_outband(sig, original, pub)
        if result["valid"]:
            from datetime import datetime
            ts = result["timestamp"]
            try:
                time_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                time_str = str(ts)
            text = (f"✔ 校验通过\n"
                    f"  模式：{result['mode']}\n"
                    f"  签名账号 UUID：{result['uuid']}\n"
                    f"  签名时间：{time_str}（{ts}）")
            self._verify_result.configure(text=text, text_color="green")
        else:
            text = f"✘ 校验失败\n  原因：{result['error']}"
            self._verify_result.configure(text=text, text_color="red")
