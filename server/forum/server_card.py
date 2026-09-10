"""
服务器卡片管理 — SERVER_INFO_REQUEST/RESPONSE。

卡片 JSON 含：node_id, name, avatar_b64, tags, host, tcp_port, dht_port,
online_count, max_online, heat_level, heat_reference, protocol_version,
software_version, public_key, signature, updated_at, hidden, status。

签名覆盖除 signature 外所有字段。
首次连接记 known_hosts，后续公钥变更拒绝并报警。
"""

import json
import time
from server.forum.database import get_forum_db, now_ts
from shared.protocol import (
    FORUM_HEAT_LEVEL_GREEN, FORUM_HEAT_LEVEL_YELLOW,
    FORUM_HEAT_LEVEL_ORANGE, FORUM_HEAT_LEVEL_RED,
    FORUM_ARCHIVE_OFFLINE_DAYS,
)


def build_server_card(node_id: str, name: str, avatar_b64: str, tags: list,
                      host: str, tcp_port: int, dht_port: int,
                      online_count: int, max_online: int,
                      heat_reference: float, public_key: str,
                      protocol_version: int, software_version: str,
                      server_priv_key_b64: str) -> dict:
    """构建服务器卡片并签名。"""
    from shared.crypto_utils import sign_data, load_ed25519_private

    card = {
        "node_id": node_id,
        "name": name[:32],
        "avatar_b64": avatar_b64,
        "tags": tags[:5],
        "host": host,
        "tcp_port": tcp_port,
        "dht_port": dht_port,
        "online_count": online_count,
        "max_online": max_online,
        "heat_level": calculate_heat_level(online_count, heat_reference),
        "heat_reference": heat_reference,
        "protocol_version": protocol_version,
        "software_version": software_version,
        "public_key": public_key,
        "updated_at": now_ts(),
        "hidden": False,
        "status": "online",
    }

    # 签名覆盖除 signature 外所有字段
    sign_content = json.dumps({k: v for k, v in card.items() if k != "signature"},
                               sort_keys=True)
    priv = load_ed25519_private(server_priv_key_b64)
    card["signature"] = sign_data(priv, sign_content.encode())
    return card


def verify_server_card(card: dict) -> bool:
    """验证服务器卡片签名。"""
    from shared.crypto_utils import verify_signature, load_ed25519_public
    try:
        pub = load_ed25519_public(card["public_key"])
        sign_content = json.dumps({k: v for k, v in card.items() if k != "signature"},
                                   sort_keys=True)
        return verify_signature(pub, sign_content.encode(), card["signature"])
    except Exception:
        return False


def calculate_heat_level(online_count: int, heat_reference: float) -> str:
    """
    热度四级：
    绿 [0,0.25]、黄 (0.25,0.5]、橙 (0.5,0.75]、红 (0.75,1.0]
    heat = online / heat_reference
    """
    if heat_reference <= 0:
        return FORUM_HEAT_LEVEL_GREEN
    ratio = online_count / heat_reference
    if ratio <= 0.25:
        return FORUM_HEAT_LEVEL_GREEN
    elif ratio <= 0.5:
        return FORUM_HEAT_LEVEL_YELLOW
    elif ratio <= 0.75:
        return FORUM_HEAT_LEVEL_ORANGE
    else:
        return FORUM_HEAT_LEVEL_RED


def heat_level_text(level: str) -> str:
    """热度等级文字（UI 显示）。"""
    return {
        FORUM_HEAT_LEVEL_GREEN: "活跃",
        FORUM_HEAT_LEVEL_YELLOW: "中等",
        FORUM_HEAT_LEVEL_ORANGE: "繁忙",
        FORUM_HEAT_LEVEL_RED: "拥挤",
    }.get(level, "活跃")


def save_known_server(card: dict) -> bool:
    """保存已知服务器（验签后缓存）。"""
    if not verify_server_card(card):
        return False

    db = get_forum_db()
    ts = now_ts()
    existing = db.execute("SELECT public_key FROM known_servers WHERE node_id=?",
                          (card["node_id"],)).fetchone()

    if existing and existing["public_key"] != card["public_key"]:
        # 公钥变更，拒绝并报警
        print(f"[FORUM] 安全警告：服务器 {card['node_id']} 公钥变更！拒绝更新。")
        return False

    db.execute("""
        INSERT OR REPLACE INTO known_servers
        (node_id, name, avatar_b64, tags, host, tcp_port, dht_port,
         public_key, signature, online_count, max_online, heat_level,
         heat_reference, protocol_version, software_version, updated_at,
         first_seen_at, last_connected_at, status, cached_until)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        card["node_id"], card.get("name", "Spider"), card.get("avatar_b64", ""),
        ",".join(card.get("tags", [])), card["host"], card["tcp_port"],
        card.get("dht_port", 0), card["public_key"], card["signature"],
        card.get("online_count", 0), card.get("max_online", 100),
        card.get("heat_level", "green"), card.get("heat_reference", 50),
        card.get("protocol_version", 3), card.get("software_version", "1.0.0"),
        ts, existing and ts or ts, ts, "online", ts + 300
    ))
    db.commit()
    return True


def list_known_servers(include_offline: bool = True) -> list:
    """列出已知服务器。超 30 天离线归档。"""
    db = get_forum_db()
    ts = now_ts()
    # 归档超 30 天离线的
    db.execute("""
        UPDATE known_servers SET status='archived'
        WHERE status='offline' AND ? - updated_at > ?
    """, (ts, FORUM_ARCHIVE_OFFLINE_DAYS * 86400))
    db.commit()

    if include_offline:
        rows = db.execute("SELECT * FROM known_servers ORDER BY status, updated_at DESC").fetchall()
    else:
        rows = db.execute("SELECT * FROM known_servers WHERE status='online' ORDER BY updated_at DESC").fetchall()
    return [dict(r) for r in rows]


def get_known_server(node_id: str) -> dict | None:
    db = get_forum_db()
    row = db.execute("SELECT * FROM known_servers WHERE node_id=?", (node_id,)).fetchone()
    return dict(row) if row else None


def record_connection(node_id: str):
    """记录一次成功连接。"""
    db = get_forum_db()
    ts = now_ts()
    db.execute("UPDATE known_servers SET last_connected_at=?, status='online' WHERE node_id=?",
              (ts, node_id))
    db.commit()
