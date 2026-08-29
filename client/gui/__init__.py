"""客户端图形界面模块。

注意：GUI 组件依赖 customtkinter / tkinter，在无显示器的服务器/CI 环境下
可能不可用。为便于「逻辑层测试 + 打包」在无 GUI 依赖时也能正常导入本包，
这里做惰性/容错导入：缺依赖时对应名字置为 None，由上层在真正打开窗口前检查。
"""
import importlib


def _safe(name):
    try:
        return importlib.import_module("." + name, __package__)
    except Exception:
        return None


mw = _safe("main_window")
rg = _safe("register")
cp = _safe("chat_panel")
cl = _safe("contact_list")
st = _safe("settings")
ap = _safe("admin_panel")

MainWindow = getattr(mw, "MainWindow", None) if mw else None
RegisterWindow = getattr(rg, "RegisterWindow", None) if rg else None
ChatPanel = getattr(cp, "ChatPanel", None) if cp else None
ContactList = getattr(cl, "ContactList", None) if cl else None
SettingsWindow = getattr(st, "SettingsWindow", None) if st else None
AdminPanel = getattr(ap, "AdminPanel", None) if ap else None


def available() -> bool:
    """当前环境是否能真正打开 GUI 窗口。"""
    return MainWindow is not None


__all__ = ["MainWindow", "RegisterWindow", "ChatPanel", "ContactList",
           "SettingsWindow", "AdminPanel", "available"]
