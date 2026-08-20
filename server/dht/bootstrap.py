"""
引导加载器 — 读取 guide.txt 并连接到引导节点。
"""

import os
import socket
import json
import time
from server.dht.node import DHTNode


def load_guide(guide_path: str = None) -> list:
    """
    解析 guide.txt。格式：每行 host:port。
    返回 {host, port} 字典列表。
    """
    if guide_path is None:
        guide_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "server", "guide.txt")

    nodes = []
    if not os.path.exists(guide_path):
        print(f"[BOOTSTRAP] Warning: {guide_path} not found")
        return nodes

    with open(guide_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                host, port_str = line.rsplit(":", 1)
                try:
                    port = int(port_str)
                    nodes.append({"host": host.strip(), "port": port})
                except ValueError:
                    print(f"[BOOTSTRAP] Skipping invalid line: {line}")
    return nodes


def bootstrap_from_guide(dht_node: DHTNode, guide_path: str = None) -> int:
    """
    连接到 guide.txt 中的节点，ping 它们并构建路由表。
    返回成功连接的数量。
    """
    nodes = load_guide(guide_path)
    if not nodes:
        print("[BOOTSTRAP] No bootstrap nodes configured")
        return 0

    print(f"[BOOTSTRAP] Connecting to {len(nodes)} bootstrap node(s)...")

    found = 0
    for n in nodes:
        host = n["host"]
        port = n.get("port", dht_node.dht_port)
        print(f"  → Pinging {host}:{port} ...")
        if dht_node.ping(host, port):
            found += 1
            print(f"    ✓ Alive")
            dht_node.routing_table.add_node({
                "node_id": "",
                "host": host,
                "port": port,
                "last_seen": time.time(),
            })

            dht_node.find_node(dht_node.node_id, via_host=host, via_port=port)
        else:
            print(f"    ✗ Unreachable")

    for round_num in range(3):
        closest = dht_node.routing_table.get_closest(dht_node.node_id)
        for n in closest[:dht_node.config.get("alpha", 3)]:
            h = n.get("host", "")
            p = n.get("port", dht_node.dht_port)
            if h:
                dht_node.find_node(dht_node.node_id, via_host=h, via_port=p)

    print(f"[BOOTSTRAP] Complete. Found {dht_node.routing_table.total_nodes()} nodes in routing table.")
    return found
