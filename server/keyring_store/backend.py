"""
Keyring 后端检测与弹窗提示。
支持有显示器（tkinter）和无显示器（环境变量/CLI）两种模式。
"""

import sys
import os
import traceback


def detect_headless():
    """
    检测当前是否为无显示器环境。
    检查 DISPLAY / WAYLAND_DISPLAY 环境变量。
    """
    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return not has_display


def check_keyring():
    """
    检查 keyring 是否可用，按优先级尝试后端：
    1. 系统钥匙链（Windows Credential Locker / macOS Keychain / Linux SecretService）
    2. 无显示器后备：keyrings.cryptfile（AES-256 加密文件）
    返回 (ok: bool, error_message: str, backend_type: str)
    """
    try:
        import keyring
    except ImportError:
        return False, (
            "缺少必要依赖库 'keyring'，请先安装：\n"
            "  pip install keyring\n"
            "  pip install keyrings.cryptfile  # 无显示器服务器需要\n\n"
            "该库用于将密钥安全存储在系统凭据管理器中。"
        ), ""

    headless = detect_headless()

    # 尝试系统钥匙链
    try:
        backend = keyring.get_keyring()
        if backend is not None and backend.priority >= 0:
            # 测试可用性
            try:
                keyring.get_password("spider-test", "test")
                return True, "", "system"
            except Exception:
                pass  # 系统钥匙链不可用，继续尝试后备
    except Exception:
        pass

    # 后备：cryptfile（无显示器友好）
    try:
        from keyrings.cryptfile.cryptfile import CryptFileKeyring
        cf = CryptFileKeyring()
        keyring_dir = os.path.expanduser("~/.spider/keyring")
        os.makedirs(keyring_dir, exist_ok=True)
        cf.keyring_dir = keyring_dir

        # 从环境变量获取主密码
        master_pass = os.environ.get("SPIDER_KEYRING_PASSPHRASE")
        if not master_pass:
            if headless:
                return False, (
                    "无显示器模式下必须使用 cryptfile 后备，\n"
                    "请设置环境变量 SPIDER_KEYRING_PASSPHRASE。\n\n"
                    "示例：\n"
                    "  export SPIDER_KEYRING_PASSPHRASE='你的强密码'\n"
                    "  python3 -m server.main"
                ), ""
            # 有显示器时尝试交互输入
            master_pass = _prompt_master_passphrase()
            if not master_pass:
                return False, "未提供 keyring 主密码，无法继续。", ""

        cf.set_password("spider", "_master_", master_pass)
        # 测试写入读取
        cf.set_password("spider-test", "test", "ok")
        cf.get_password("spider-test", "test")
        cf.delete_password("spider-test", "test")

        # 设置为默认后端
        keyring.set_keyring(cf)
        return True, "", "cryptfile"
    except ImportError:
        return False, (
            "未检测到系统凭据管理器，且未安装 cryptfile 后备。\n\n"
            "安装命令：\n"
            "  pip install keyrings.cryptfile\n\n"
            "Linux 也可安装系统级钥匙链：\n"
            "  sudo apt install gnome-keyring"
        ), ""
    except Exception as e:
        return False, f"cryptfile 后备初始化失败: {e}", ""


def _prompt_master_passphrase():
    """有显示器时弹出密码输入对话框"""
    try:
        import tkinter as tk
        from tkinter import simpledialog
        root = tk.Tk()
        root.withdraw()
        pwd = simpledialog.askstring(
            "设置 Keyring 主密码",
            "请输入用于加密密钥文件的主密码\n（请使用强密码，丢失无法恢复）：",
            show="*",
            parent=root
        )
        root.destroy()
        return pwd
    except Exception:
        return None


def show_error_popup(title: str, message: str):
    """
    显示错误弹窗（有显示器用 tkinter，无显示器输出到 stderr）。
    然后退出程序。
    """
    headless = detect_headless()
    if headless:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"  [ERROR] {title}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(message, file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        sys.exit(1)
    
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"  [ERROR] {title}", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(message, file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
    sys.exit(1)


def show_setup_popup(title: str, message: str):
    """显示信息弹窗（自动适配有无显示器）"""
    headless = detect_headless()
    if headless:
        print(f"\n[INFO] {title}: {message}", file=sys.stderr)
        return
    
    try:
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(title, message)
        root.destroy()
    except Exception:
        print(f"\n[INFO] {title}: {message}", file=sys.stderr)


def prompt_initial_pin() -> str:
    """
    提示管理员设置初始 6 位 PIN。
    有显示器用 tkinter 弹窗，无显示器从环境变量读取。
    """
    headless = detect_headless()
    
    if headless:
        # 无显示器：从环境变量读取
        pin = os.environ.get("SPIDER_ADMIN_PIN")
        if pin and pin.isdigit() and len(pin) == 6:
            print(f"[INFO] 从环境变量 SPIDER_ADMIN_PIN 读取管理员 PIN", file=sys.stderr)
            return pin
        # 尝试从 stdin 读取（支持 docker run -it 等交互场景）
        try:
            pin = input("请输入管理员 PIN (6位数字): ").strip()
            if pin.isdigit() and len(pin) == 6:
                confirm = input("请再次输入以确认: ").strip()
                if confirm == pin:
                    return pin
                else:
                    print("[ERROR] 两次输入的 PIN 不一致", file=sys.stderr)
                    sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            print("[ERROR] 无法读取管理员 PIN（非交互环境）", file=sys.stderr)
            sys.exit(1)

        print(
            "\n[ERROR] 无显示器模式下必须设置 SPIDER_ADMIN_PIN 环境变量。\n"
            "示例：export SPIDER_ADMIN_PIN=123456\n",
            file=sys.stderr
        )
        sys.exit(1)
    
    # 有显示器：使用 tkinter
    import tkinter as tk
    from tkinter import simpledialog, messagebox

    root = tk.Tk()
    root.withdraw()

    while True:
        pin = simpledialog.askstring(
            "初始化 — 设置管理员PIN",
            "请输入管理员PIN (6位数字):",
            show="*",
            parent=root
        )
        if pin is None:
            show_error_popup("错误", "必须设置管理员PIN才能继续。\n程序将退出。")
            sys.exit(1)
        if pin.isdigit() and len(pin) == 6:
            confirm = simpledialog.askstring(
                "确认PIN",
                "请再次输入管理员PIN以确认:",
                show="*",
                parent=root
            )
            if confirm == pin:
                root.destroy()
                return pin
            else:
                messagebox.showerror("错误", "两次输入的PIN不一致，请重试")
        else:
            messagebox.showerror("错误", "PIN必须是6位数字")


def check_keyring_or_exit():
    """
    检查 keyring 可用性，不可用时弹出错误并退出。
    自动适配有显示器/无显示器两种模式。
    """
    ok, msg, backend_type = check_keyring()
    if not ok:
        show_error_popup("Spider 服务端 — 启动失败", msg)
        sys.exit(1)

    headless = detect_headless()
    if headless:
        print(f"[INFO] Keyring 后端: {backend_type}（无显示器模式）", file=sys.stderr)
    else:
        print(f"[INFO] Keyring 后端: {backend_type}")

    return backend_type
