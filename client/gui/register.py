"""
注册 / 解锁窗口。(v2 — 安全加固版)

- 首次运行：生成 UUIDv1（强制真实 MAC）、创建密钥对、向服务器注册。
- 后续运行：PIN 解锁（解锁 PIN 或胁迫 PIN）。
- 胁迫 PIN 正确存储、验证，并触发清除 + 通知。
"""

import sys
import json
import traceback
import base64
import os
import time
import hashlib

try:
    import customtkinter as ctk
    USE_CTK = True
except ImportError:
    import tkinter as tk
    from tkinter import messagebox, simpledialog
    USE_CTK = False

from client.utils.uuidgen import generate_uuid_v1
from client.crypto.keys import (
    generate_keypairs, save_identity, load_identity, delete_identity,
    set_duress_pin, verify_duress_pin, remove_duress_pin,
)
from client.storage.identity import (
    save_identity_file, load_identity_file,
    check_duress_pin, wipe_all_data,
    set_duress_pin as identity_set_duress, clear_duress_pin as identity_clear_duress,
)
from client.utils.config import load_config, save_config, get_data_dir, identity_path, get_icon_path
from client.network.tcp_client import TCPClient
from client.network.discovery import UDPDiscovery
from shared.crypto_utils import (
    sign_data, load_ed25519_private, secure_token,
    PBKDF2_ITERATIONS,
)
from shared.protocol import *
from shared.crypto_utils import random_token as secure_token


class RegisterWindow:
    """首次运行注册或返回用户 PIN 解锁。"""

    def __init__(self):
        self.config = load_config()
        self.identity = None
        self.tcp = None
        self.server_host = None
        self.server_port = None
        self.discovered_servers = []
        self._fail_count = 0
        self._duress_verified = False
        if USE_CTK:
            self.root = ctk.CTk()
            self.root.title("Spider - 注册/解锁")
            self.root.geometry("540x580")
            ctk.set_appearance_mode("dark")
        else:
            self.root = tk.Tk()
            self.root.title("Spider - 注册/解锁")
            self.root.geometry("540x580")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._set_window_icon()

        if os.path.exists(identity_path()):
            self._build_unlock_ui()
        else:
            self._build_register_ui()


    def _set_window_icon(self):
        """设置窗口图标。"""
        try:
            import tkinter as _tk
            icon_path = get_icon_path()
            if os.path.exists(icon_path):
                self.root.iconphoto(False, _tk.PhotoImage(file=icon_path))
        except Exception:
            pass

    def _build_register_ui(self):
        if USE_CTK:
            ctk.CTkLabel(self.root, text="📝 首次注册", font=("Arial", 18, "bold")).pack(pady=15)

            srv_frame = ctk.CTkFrame(self.root)
            srv_frame.pack(fill="x", padx=20, pady=5)

            ctk.CTkLabel(srv_frame, text="服务器地址:").pack(anchor="w", padx=5)
            self.host_var = ctk.StringVar(value=self.config.get("server_host", ""))
            ctk.CTkEntry(srv_frame, textvariable=self.host_var, placeholder_text="域名或IP").pack(fill="x", padx=5, pady=2)

            port_frame = ctk.CTkFrame(srv_frame)
            port_frame.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(port_frame, text="端口:").pack(side="left")
            self.port_var = ctk.StringVar(value=str(self.config.get("server_port", DEFAULT_TCP_PORT)))
            ctk.CTkEntry(port_frame, textvariable=self.port_var, width=80).pack(side="left", padx=5)

            ctk.CTkButton(srv_frame, text="🔍 搜索局域网服务器", command=self._search_lan).pack(pady=5)

            self.server_list_frame = ctk.CTkScrollableFrame(self.root, height=80)
            self.server_list_frame.pack(fill="x", padx=20, pady=5)

            pin_frame = ctk.CTkFrame(self.root)
            pin_frame.pack(fill="x", padx=20, pady=10)

            ctk.CTkLabel(pin_frame, text="设置解锁PIN (6位数字):").pack(anchor="w")
            self.pin1_var = ctk.StringVar()
            ctk.CTkEntry(pin_frame, textvariable=self.pin1_var, show="*", width=100).pack(fill="x", pady=2)

            ctk.CTkLabel(pin_frame, text="确认解锁PIN:").pack(anchor="w", pady=(5, 0))
            self.pin1c_var = ctk.StringVar()
            ctk.CTkEntry(pin_frame, textvariable=self.pin1c_var, show="*", width=100).pack(fill="x", pady=2)

            ctk.CTkLabel(pin_frame, text="设置胁迫PIN (6位数字，被胁迫时使用):").pack(anchor="w", pady=(5, 0))
            self.pin2_var = ctk.StringVar()
            ctk.CTkEntry(pin_frame, textvariable=self.pin2_var, show="*", width=100).pack(fill="x", pady=2)

            ctk.CTkLabel(pin_frame, text="确认胁迫PIN:").pack(anchor="w", pady=(5, 0))
            self.pin2c_var = ctk.StringVar()
            ctk.CTkEntry(pin_frame, textvariable=self.pin2c_var, show="*", width=100).pack(fill="x", pady=2)

            ctk.CTkButton(self.root, text="🚀 注册并连接", command=self._do_register).pack(pady=10)

            name_frame = ctk.CTkFrame(self.root)
            name_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(name_frame, text="显示名称 (4-32 字节):", font=("Arial", 10)).pack(anchor="w", padx=5)
            self.display_name_var = ctk.StringVar()
            ctk.CTkEntry(name_frame, textvariable=self.display_name_var, placeholder_text="SpiderUser").pack(fill="x", padx=5, pady=2)

            dc_frame = ctk.CTkFrame(self.root)
            dc_frame.pack(fill="x", padx=20, pady=5)
            ctk.CTkLabel(dc_frame, text="🔗 直连设置 (可选)", font=("Arial", 12, "bold")).pack(anchor="w", padx=5)
            self.dc_enabled_var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(dc_frame, text="启用直连 (P2P)", variable=self.dc_enabled_var).pack(anchor="w", padx=5)
            self.dc_port_var = ctk.StringVar(value=str(self.config.get("direct_connect_port", DEFAULT_DIRECT_CONNECT_PORT)))
            port_row = ctk.CTkFrame(dc_frame)
            port_row.pack(fill="x", padx=5, pady=2)
            ctk.CTkLabel(port_row, text="直连端口:").pack(side="left")
            ctk.CTkEntry(port_row, textvariable=self.dc_port_var, width=80).pack(side="left", padx=5)
            ctk.CTkLabel(dc_frame, text="支持: 局域网 / WiFi直连 / 蓝牙 / 公网IP", text_color="gray", font=("Arial", 9)).pack(anchor="w", padx=5)
        else:
            tk.Label(self.root, text="📝 Spider 首次注册", font=("Arial", 18, "bold"), bg="#2b2b2b", fg="white").pack(pady=15)
            srv_frame = tk.LabelFrame(self.root, text="Spider 服务器", bg="#2b2b2b", fg="white")
            srv_frame.pack(fill="x", padx=20, pady=5)
            tk.Label(srv_frame, text="服务器地址:", bg="#2b2b2b", fg="white").pack(anchor="w", padx=5)
            self.host_var = tk.StringVar(value=self.config.get("server_host", ""))
            tk.Entry(srv_frame, textvariable=self.host_var).pack(fill="x", padx=5, pady=2)
            tk.Label(srv_frame, text="端口:", bg="#2b2b2b", fg="white").pack(anchor="w", padx=5)
            self.port_var = tk.StringVar(value=str(self.config.get("server_port", DEFAULT_TCP_PORT)))
            tk.Entry(srv_frame, textvariable=self.port_var).pack(fill="x", padx=5, pady=2)
            tk.Button(srv_frame, text="🔍 搜索局域网服务器", command=self._search_lan).pack(pady=5)

            self.server_list_frame = tk.Frame(self.root, bg="#2b2b2b")
            self.server_list_frame.pack(fill="x", padx=20, pady=5)

            pin_frame = tk.LabelFrame(self.root, text="Spider PIN设置", bg="#2b2b2b", fg="white")
            pin_frame.pack(fill="x", padx=20, pady=10)
            tk.Label(pin_frame, text="解锁PIN (6位数字):", bg="#2b2b2b", fg="white").pack(anchor="w")
            self.pin1_var = tk.StringVar()
            tk.Entry(pin_frame, textvariable=self.pin1_var, show="*").pack(fill="x", pady=2)
            tk.Label(pin_frame, text="确认解锁PIN:", bg="#2b2b2b", fg="white").pack(anchor="w", pady=(5, 0))
            self.pin1c_var = tk.StringVar()
            tk.Entry(pin_frame, textvariable=self.pin1c_var, show="*").pack(fill="x", pady=2)
            tk.Label(pin_frame, text="胁迫PIN (6位数字):", bg="#2b2b2b", fg="white").pack(anchor="w", pady=(5, 0))
            self.pin2_var = tk.StringVar()
            tk.Entry(pin_frame, textvariable=self.pin2_var, show="*").pack(fill="x", pady=2)
            tk.Label(pin_frame, text="确认胁迫PIN:", bg="#2b2b2b", fg="white").pack(anchor="w", pady=(5, 0))
            self.pin2c_var = tk.StringVar()
            tk.Entry(pin_frame, textvariable=self.pin2c_var, show="*").pack(fill="x", pady=2)

            tk.Button(self.root, text="🚀 注册并连接", command=self._do_register).pack(pady=10)

            name_frame = tk.LabelFrame(self.root, text="显示名称", bg="#2b2b2b", fg="white")
            name_frame.pack(fill="x", padx=20, pady=5)
            tk.Label(name_frame, text="(4-32字节 UTF-8):", bg="#2b2b2b", fg="white").pack(anchor="w")
            self.display_name_var = tk.StringVar()
            tk.Entry(name_frame, textvariable=self.display_name_var).pack(fill="x", padx=5, pady=2)

    def _search_lan(self):
        try:
            disc = UDPDiscovery(self.config.get("udp_port", DEFAULT_UDP_PORT))
            servers = disc.discover(timeout=3.0)
            disc.stop()
            for w in self.server_list_frame.winfo_children():
                w.destroy()
            if not servers:
                if USE_CTK:
                    ctk.CTkLabel(self.server_list_frame, text="未发现服务器", text_color="gray").pack()
                return
            self.discovered_servers = servers
            for srv in servers:
                name = srv.get("name", "Unknown")
                host = srv.get("host", "")
                port = srv.get("tcp_port", DEFAULT_TCP_PORT)
                if USE_CTK:
                    ctk.CTkButton(self.server_list_frame, text=f"{name} ({host}:{port})",
                                   command=lambda h=host, p=port: self._select_server(h, p)).pack(fill="x", pady=1)
        except Exception as e:
            self._show_error(f"搜索失败: {e}")

    def _select_server(self, host: str, port: int):
        self.host_var.set(host)
        self.port_var.set(str(port))


    def _build_unlock_ui(self):
        if USE_CTK:
            ctk.CTkLabel(self.root, text="🔐 输入PIN解锁", font=("Arial", 18, "bold")).pack(pady=30)
            self.unlock_pin = ctk.StringVar()
            pin_entry = ctk.CTkEntry(self.root, textvariable=self.unlock_pin, show="*", width=150, placeholder_text="6位PIN")
            pin_entry.pack(pady=10)
            pin_entry.focus_set()
            ctk.CTkButton(self.root, text="解锁", command=self._do_unlock).pack(pady=10)
            ctk.CTkLabel(self.root, text="提示: 输入胁迫PIN将清除所有数据并通知服务器", text_color="orange", font=("Arial", 10)).pack(pady=20)
            self.root.bind("<Return>", lambda e: self._do_unlock())
        else:
            tk.Label(self.root, text="🔐 输入PIN解锁", font=("Arial", 18, "bold"), bg="#2b2b2b", fg="white").pack(pady=30)
            self.unlock_pin = tk.StringVar()
            pin_entry = tk.Entry(self.root, textvariable=self.unlock_pin, show="*", width=15, font=("Arial", 14))
            pin_entry.pack(pady=10)
            pin_entry.focus_set()
            tk.Button(self.root, text="解锁", command=self._do_unlock).pack(pady=10)
            tk.Label(self.root, text="提示: 输入胁迫PIN将清除所有数据", bg="#2b2b2b", fg="orange", font=("Arial", 10)).pack(pady=20)
            self.root.bind("<Return>", lambda e: self._do_unlock())


    def _do_register(self):

        pin1 = self.pin1_var.get().strip()
        pin1c = self.pin1c_var.get().strip()
        pin2 = self.pin2_var.get().strip()
        pin2c = self.pin2c_var.get().strip()

        if not (pin1.isdigit() and len(pin1) == 6):
            self._show_error("解锁PIN必须是6位数字")
            return
        if pin1 != pin1c:
            self._show_error("解锁PIN两次输入不一致")
            return
        if not (pin2.isdigit() and len(pin2) == 6):
            self._show_error("胁迫PIN必须是6位数字")
            return
        if pin2 != pin2c:
            self._show_error("胁迫PIN两次输入不一致")
            return
        if pin1 == pin2:
            self._show_error("解锁PIN和胁迫PIN不能相同")
            return


        display_name = self.display_name_var.get().strip()
        if display_name:
            from client.crypto.keys import validate_display_name
            ok, err = validate_display_name(display_name)
            if not ok:
                self._show_error(f"显示名称无效: {err}")
                return

        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except:
            self._show_error("端口必须是数字")
            return
        if not host:
            self._show_error("请输入服务器地址")
            return

        try:

            uuid_obj = generate_uuid_v1()
            uuid_str = str(uuid_obj)
            mac_int = uuid_obj.node
            mac_str = ":".join(f"{(mac_int >> (i*8)) & 0xff:02x}" for i in range(5, -1, -1))


            keys = generate_keypairs()

            identity = {
                "uuid": uuid_str,
                "mac_address": mac_str,
                "server_host": host,
                "server_port": port,
                "x25519_public": keys["x25519_public"],
                "x25519_private": keys["x25519_private"],
                "ed25519_public": keys["ed25519_public"],
                "ed25519_private": keys["ed25519_private"],
            }


            save_identity_file(identity, pin1, duress_pin=pin2)


            if display_name:
                from client.storage.identity import save_user_profile
                save_user_profile({"display_name": display_name})


            self.config["server_host"] = host
            self.config["server_port"] = port
            save_config(self.config)


            self.tcp = TCPClient(host, port)
            self.tcp.connect()

            e_priv = load_ed25519_private(keys["ed25519_private"])
            reg_data = json.dumps({
                "type": REGISTER,
                "uuid": uuid_str,
                "x25519_public": keys["x25519_public"],
                "ed25519_public": keys["ed25519_public"],
                "display_name": display_name,
            }, sort_keys=True).encode()
            signature = sign_data(e_priv, reg_data)

            self.tcp.register(uuid_str, keys["x25519_public"], keys["ed25519_public"], signature, display_name)

            self.identity = identity
            self.server_host = host
            self.server_port = port

            self._show_info("注册成功！正在进入主界面...")
            self.root.after(1000, self._enter_main)

        except RuntimeError as e:
            self._show_error(f"无法生成UUID(需要真实MAC): {e}")
        except Exception as e:
            self._show_error(f"注册失败: {e}")
            traceback.print_exc()

    def _do_unlock(self):
        pin = self.unlock_pin.get().strip()
        if not pin:
            self._show_error("请输入PIN")
            return

        try:
            identity = load_identity_file(pin)
            self.identity = identity
            self.server_host = identity.get("server_host", "")
            self.server_port = identity.get("server_port", DEFAULT_TCP_PORT)
            self._fail_count = 0
            self._enter_main()
            return
        except ValueError:
            pass
        except FileNotFoundError:
            self._show_error("身份文件不存在，请重新注册")
            return
        except Exception as e:
            self._show_error(f"解锁失败: {e}")
            return


        if check_duress_pin(pin):
            self._trigger_duress(pin)
            return

        self._fail_count += 1
        remaining = 3 - self._fail_count
        if self._fail_count >= 3:
            if self._confirm_duress_wipe():
                self._trigger_duress_no_notify()
            else:
                self._fail_count = 0
                self._show_error("PIN错误，请重试")
        else:
            self._show_error(f"PIN错误，还剩 {remaining} 次尝试机会")

    def _trigger_duress(self, pin: str):
        """
        胁迫 PIN 验证成功 — 清除所有本地数据并通知服务器。
        服务器将标记此身份为已泄露并断开会话。
        """
        try:

            identity_path_tmp = identity_path()
            if os.path.exists(identity_path_tmp):
                with open(identity_path_tmp) as f:
                    data = json.load(f)
                uuid_str = data.get("uuid", "")


                host = data.get("server_host", "")
                port = data.get("server_port", DEFAULT_TCP_PORT)
                try:
                    tcp = TCPClient(host, port)
                    tcp.connect()
                    # 构造并签署 COMPROMISED 通知（使用身份 Ed25519 私钥）
                    from shared.crypto_utils import sign_data, load_ed25519_private
                    e_priv_b64 = data.get("ed25519_private", "")
                    comp_data = json.dumps(
                        {"type": COMPROMISED, "uuid": uuid_str},
                        sort_keys=True
                    ).encode()
                    comp_sig = ""
                    if e_priv_b64:
                        try:
                            comp_sig = sign_data(load_ed25519_private(e_priv_b64), comp_data)
                        except Exception:
                            comp_sig = ""
                    tcp.send_compromised(uuid_str, comp_sig)
                    tcp.disconnect()
                except Exception as e:
                    print(f"[DURESS] Server notification failed: {e}")

            wipe_all_data()
            self._show_info("⚠️ 数据已清除。正在退出...")
            self.root.after(2000, self._on_close)

        except Exception as e:
            self._show_error(f"清除过程出错: {e}")
            self._on_close()

    def _trigger_duress_no_notify(self):
        """不通知服务器直接清除（离线 / 三次失败回退）。"""
        try:
            wipe_all_data()
            self._show_info("⚠️ 数据已清除。正在退出...")
            self.root.after(2000, self._on_close)
        except Exception as e:
            self._show_error(f"清除过程出错: {e}")
            self._on_close()

    def _confirm_duress_wipe(self) -> bool:
        """显示数据清除确认对话框。"""
        if USE_CTK:
            return True
        else:
            from tkinter import messagebox
            return messagebox.askyesno(
                "确认清除",
                "连续3次PIN错误。\n是否清除所有本地数据？\n\n"
                "选择'是'将删除所有身份、聊天记录和设置。",
                icon="warning"
            )

    def _enter_main(self):
        self.root.destroy()
        from client.gui.main_window import MainWindow
        app = MainWindow(self.identity, self.server_host, self.server_port)
        app.run()


    def _show_error(self, msg: str):
        print(f"[ERROR] {msg}")
        if USE_CTK:
            try:
                ctk.CTkMessageBox(title="错误", message=msg, parent=self.root) if hasattr(ctk, 'CTkMessageBox') else None
            except:
                pass
            if not hasattr(ctk, 'CTkMessageBox'):
                from tkinter import messagebox
                messagebox.showerror("错误", msg)
        else:
            from tkinter import messagebox
            messagebox.showerror("错误", msg)

    def _show_info(self, msg: str):
        print(f"[INFO] {msg}")
        if USE_CTK:
            try:
                ctk.CTkMessageBox(title="提示", message=msg, parent=self.root, icon="info") if hasattr(ctk, 'CTkMessageBox') else None
            except:
                pass
            if not hasattr(ctk, 'CTkMessageBox'):
                from tkinter import messagebox
                messagebox.showinfo("提示", msg)
        else:
            from tkinter import messagebox
            messagebox.showinfo("提示", msg)

    def _on_close(self):
        try:
            if self.tcp:
                self.tcp.disconnect()
        except:
            pass
        self.root.quit()
        sys.exit(0)

    def run(self):
        self.root.mainloop()
