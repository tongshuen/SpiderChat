"""
联系人列表 — 左侧面板。
核心功能在 MainWindow 中；本模块提供独立辅助函数。
"""

import json
import os
from client.utils.config import contacts_path


def load_contacts() -> list:
    """从磁盘加载联系人。"""
    path = contacts_path()
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def save_contacts(contacts: list):
    """保存联系人到磁盘。"""
    path = contacts_path()
    with open(path, "w") as f:
        json.dump(contacts, f, indent=2)


def add_contact(contacts: list, uuid_str: str, name: str = "", x25519_pub: str = "", ed25519_pub: str = "") -> list:
    """添加或更新联系人。"""
    for c in contacts:
        if c["uuid"] == uuid_str:
            c["name"] = name or c.get("name", "")
            c["x25519_public"] = x25519_pub or c.get("x25519_public", "")
            c["ed25519_public"] = ed25519_pub or c.get("ed25519_public", "")
            return contacts
    contacts.append({
        "uuid": uuid_str,
        "name": name,
        "x25519_public": x25519_pub,
        "ed25519_public": ed25519_pub,
        "blocked": False,
    })
    return contacts


def remove_contact(contacts: list, uuid_str: str) -> list:
    return [c for c in contacts if c["uuid"] != uuid_str]


def search_local(contacts: list, query: str) -> list:
    """按名称搜索联系人（仅本地）。"""
    q = query.lower()
    return [c for c in contacts if q in c.get("name", "").lower() or q in c["uuid"].lower()]
