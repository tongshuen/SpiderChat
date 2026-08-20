"""
Kademlia 路由表 — K-桶实现。
"""

import time
import random
import hashlib
import struct


class KBucket:
    """单个 K-桶，最多容纳 k 个节点。"""

    def __init__(self, k: int = 20):
        self.k = k
        self.nodes = []
    def add_or_update(self, node: dict) -> bool:
        """
        添加或更新节点。添加/替换成功返回 True。
        桶满时 ping 最旧的节点；仅当最旧节点失败时才替换。
        """
        nid = node["node_id"]
        for i, n in enumerate(self.nodes):
            if n["node_id"] == nid:
                self.nodes.pop(i)
                self.nodes.append(node)
                return True
        if len(self.nodes) < self.k:
            self.nodes.append(node)
            return True
        oldest = self.nodes[0]
        return False

    def force_replace_oldest(self, node: dict) -> bool:
        """替换最旧的条目（ping 失败后使用）。"""
        if len(self.nodes) >= self.k:
            self.nodes.pop(0)
        self.nodes.append(node)
        return True

    def remove(self, node_id: str):
        self.nodes = [n for n in self.nodes if n["node_id"] != node_id]

    def get_all(self) -> list:
        return list(self.nodes)

    def get_closest(self, target_id: str, count: int = 20) -> list:
        """按 XOR 距离获取距目标最近的 k 个节点。"""
        def xor_dist(a: str, b: str) -> int:

            ai = int(a, 16) if isinstance(a, str) else a
            bi = int(b, 16) if isinstance(b, str) else b
            return ai ^ bi

        t = int(target_id, 16) if isinstance(target_id, str) else target_id
        sorted_nodes = sorted(self.nodes, key=lambda n: xor_dist(n["node_id"], t))
        return sorted_nodes[:count]

    def __len__(self):
        return len(self.nodes)


class RoutingTable:
    """Kademlia 路由表，160 个桶（每个比特前缀一个）。"""

    def __init__(self, self_node_id: str, k: int = 20, alpha: int = 3):
        self.self_node_id = self_node_id
        self.k = k
        self.alpha = alpha
        self.buckets = [KBucket(k) for _ in range(160)]

    def _bucket_index(self, node_id: str) -> int:
        """查找给定节点 ID 对应的桶索引。"""
        a = int(self.self_node_id, 16)
        b = int(node_id, 16)
        xor = a ^ b
        if xor == 0:
            return 0
        return xor.bit_length() - 1

    def add_node(self, node: dict) -> bool:
        """将节点添加到适当的桶中。"""
        idx = self._bucket_index(node["node_id"])
        if idx >= 160:
            idx = 159
        return self.buckets[idx].add_or_update(node)

    def remove_node(self, node_id: str):
        idx = self._bucket_index(node_id)
        if idx < 160:
            self.buckets[idx].remove(node_id)

    def get_closest(self, target_id: str, count: int = 20) -> list:
        """跨所有桶获取距目标 ID 最近的 k 个节点。"""
        all_nodes = []
        for bucket in self.buckets:
            all_nodes.extend(bucket.get_all())

        def xor_dist_str(a: str, b: str) -> int:
            return int(a, 16) ^ int(b, 16)

        t = int(target_id, 16)
        sorted_nodes = sorted(all_nodes, key=lambda n: xor_dist_str(n["node_id"], t))
        return sorted_nodes[:count]

    def all_nodes(self) -> list:
        result = []
        for b in self.buckets:
            result.extend(b.get_all())
        return result

    def total_nodes(self) -> int:
        return sum(len(b) for b in self.buckets)

    def remove_all(self):
        for b in self.buckets:
            b.nodes.clear()
