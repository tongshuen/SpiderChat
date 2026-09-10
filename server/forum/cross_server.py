"""
跨服寻址与目录联邦。

帖子 ID 格式：{node_id}:{64hex}
寻址顺序：解析前缀 → 本服前缀本地查 → 本地 known_servers 查 → DHT 查 server: 键 → 失败返回明确错误。
禁止广播整个联邦作为回退。

帖子不联邦，只联邦服务器目录。
每服为本服帖子唯一权威，跨服按 ID 直达。
目录条目带签名，接收方验证后缓存。
联邦关系显式声明 federated_with。
跨服超时 5 秒。
"""

import json
import time
import threading
from server.forum.database import get_forum_db, now_ts
from server.forum.server_card import verify_server_card, save_known_server, get_known_server
from server.forum.posts import get_post
from shared.protocol import FORUM_CROSS_SERVER_TIMEOUT_SEC, FORUM_DIRECTORY_CACHE_TTL_SEC


def parse_post_id(post_id: str) -> tuple:
    """解析帖子 ID，返回 (node_id, hex_part)。"""
    if ":" not in post_id:
        return None, None
    parts = post_id.split(":", 1)
    return parts[0], parts[1]


def resolve_post(post_id: str, local_node_id: str, dht_store=None,
                  cross_server_conn=None) -> tuple:
    """
    按 ID 寻址帖子。
    返回 (post_dict, source, error)
    source: 'local' / 'remote' / None
    """
    node_id, hex_part = parse_post_id(post_id)
    if not node_id or not hex_part:
        return None, None, "无效的帖子 ID 格式"

    # 1. 本服前缀本地查
    if node_id == local_node_id:
        post = get_post(post_id)
        if post:
            return post, "local", None
        return None, None, "帖子不存在"

    # 2. 本地 known_servers 查
    server = get_known_server(node_id)
    if server and server.get("cached_until", 0) > now_ts():
        # 缓存有效，尝试跨服获取
        post = _fetch_remote_post(post_id, server, cross_server_conn)
        if post:
            return post, "remote", None

    # 3. DHT 查 server: 键
    if dht_store:
        server_info = _lookup_dht(dht_store, node_id)
        if server_info:
            # 验签后缓存
            if verify_server_card(server_info):
                save_known_server(server_info)
                post = _fetch_remote_post(post_id, server_info, cross_server_conn)
                if post:
                    return post, "remote", None

    return None, None, f"无法寻址服务器 {node_id[:16]}...，帖子可能不存在或服务器离线"


def _lookup_dht(dht_store, node_id: str) -> dict | None:
    """通过 DHT 查找服务器信息。"""
    try:
        value = dht_store.get(f"server:{node_id}")
        if value:
            return json.loads(value)
    except Exception:
        pass
    return None


def _fetch_remote_post(post_id: str, server_info: dict, cross_server_conn=None) -> dict | None:
    """从远程服务器获取帖子（5秒超时）。"""
    if not cross_server_conn:
        return None
    try:
        result = cross_server_conn.fetch_post(
            server_info["host"], server_info["tcp_port"], post_id,
            timeout=FORUM_CROSS_SERVER_TIMEOUT_SEC
        )
        if result and result.get("post"):
            # 验证跨服帖子签名
            post = result["post"]
            if _verify_remote_post(post, server_info):
                return post
    except Exception:
        pass
    return None


def _verify_remote_post(post: dict, server_info: dict) -> bool:
    """验证跨服帖子的服务器签名。"""
    from shared.crypto_utils import verify_signature, load_ed25519_public
    try:
        pub = load_ed25519_public(server_info["public_key"])
        sign_content = json.dumps(
            {k: v for k, v in post.items() if k != "server_signature"},
            sort_keys=True
        )
        return verify_signature(pub, sign_content.encode(), post.get("server_signature", ""))
    except Exception:
        return False


def announce_directory(server_card: dict, federated_peers: list, cross_server_conn=None):
    """向联邦节点广播目录条目（带签名）。"""
    if not cross_server_conn or not federated_peers:
        return
    for peer in federated_peers:
        try:
            cross_server_conn.send_directory_announce(peer, server_card)
        except Exception:
            pass


def receive_directory_announce(server_card: dict) -> bool:
    """接收目录条目，验签后缓存。"""
    return save_known_server(server_card)


def get_federated_servers(local_node_id: str) -> list:
    """获取联邦服务器列表（从 known_servers 中 federated_with 包含本服的）。"""
    db = get_forum_db()
    rows = db.execute("SELECT * FROM known_servers WHERE status='online'").fetchall()
    federated = []
    for row in rows:
        fw = row.get("federated_with", "")
        if local_node_id in fw.split(","):
            federated.append(dict(row))
    return federated
