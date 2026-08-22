"""
令牌桶限速器。
每个用户拥有独立桶。全局默认值 + 每用户覆盖。
"""

import time
import threading
from collections import defaultdict


import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from shared.protocol import DEFAULT_RATE_LIMIT, DEFAULT_BURST_CAPACITY as DEFAULT_BURST


class TokenBucket:
    """单个令牌桶。"""

    def __init__(self, capacity: int, refill_rate: float):
        """
        capacity: 最大令牌数（突发容量）
        refill_rate: 每秒令牌数
        """
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, n: int = 1) -> bool:
        """尝试消费 n 个令牌。允许返回 True。"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now

            if self.tokens >= n:
                self.tokens -= n
                return True
            return False

    def refill(self):
        """补充令牌桶。"""
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now


class RateLimiter:
    """每用户令牌桶限速器。"""

    def __init__(self, config: dict):
        rl_cfg = config.get("rate_limit", {})
        self.global_seconds_per_msg = rl_cfg.get("global_seconds_per_msg", DEFAULT_RATE_LIMIT)
        self.burst_capacity = rl_cfg.get("burst_capacity", DEFAULT_BURST)
        self._buckets: dict[str, TokenBucket] = {}
        self._overrides: dict[str, float] = {}
        self.lock = threading.Lock()

    def _get_bucket(self, uuid_str: str) -> TokenBucket:
        with self.lock:
            if uuid_str in self._buckets:
                return self._buckets[uuid_str]

            if uuid_str in self._overrides:
                seconds = self._overrides[uuid_str]
            else:
                seconds = self.global_seconds_per_msg

            rate = 1.0 / max(seconds, 0.001)  # 令牌/秒
            bucket = TokenBucket(self.burst_capacity, rate)
            self._buckets[uuid_str] = bucket
            return bucket

    def allow(self, uuid_str: str) -> bool:
        """检查该用户的消息是否应被允许（使用有效限速）。"""
        bucket = self._get_bucket(uuid_str)
        return bucket.consume(1)

    def allow_with_rate(self, uuid_str: str, seconds_per_msg: float) -> bool:
        """
        Check rate limit with an EXPLICITLY provided rate (for cross-server relay).
        This bypasses the per-user override and uses the stricter negotiated rate.
        Returns True if allowed.
        """

        with self.lock:
            if uuid_str in self._buckets:
                bucket = self._buckets[uuid_str]
            else:
                rate = 1.0 / max(seconds_per_msg, 0.001)
                bucket = TokenBucket(self.burst_capacity, rate)
                self._buckets[uuid_str] = bucket
        return bucket.consume(1)

    def set_global_rate(self, seconds_per_msg: float):
        """更新全局限速。新桶将使用此速率。"""
        self.global_seconds_per_msg = seconds_per_msg

        rate = 1.0 / max(seconds_per_msg, 0.001)
        with self.lock:
            for uuid_str, bucket in self._buckets.items():
                if uuid_str not in self._overrides:
                    bucket.refill_rate = rate

    def set_user_rate(self, uuid_str: str, seconds_per_msg: float):
        """设置每用户限速覆盖。"""
        self._overrides[uuid_str] = seconds_per_msg
        rate = 1.0 / max(seconds_per_msg, 0.001)
        with self.lock:
            if uuid_str in self._buckets:
                self._buckets[uuid_str].refill_rate = rate
            else:
                self._buckets[uuid_str] = TokenBucket(self.burst_capacity, rate)

    def set_burst(self, capacity: int):
        self.burst_capacity = capacity
        with self.lock:
            for bucket in self._buckets.values():
                bucket.capacity = capacity
                bucket.tokens = min(bucket.tokens, capacity)

    def get_status(self) -> dict:
        with self.lock:
            return {
                "global_seconds_per_msg": self.global_seconds_per_msg,
                "burst_capacity": self.burst_capacity,
                "tracked_users": len(self._buckets),
                "overrides": dict(self._overrides),
                "bucket_states": {
                    uid: {"tokens": round(b.tokens, 2), "rate": round(b.refill_rate, 4)}
                    for uid, b in self._buckets.items()
                }
            }

    def remove_user(self, uuid_str: str):
        with self.lock:
            self._buckets.pop(uuid_str, None)
            self._overrides.pop(uuid_str, None)

    def get_effective_rate(self, uuid_str: str) -> float:
        """获取用户的有效秒/条限速值。"""
        if uuid_str in self._overrides:
            return self._overrides[uuid_str]
        return self.global_seconds_per_msg

    def get_all_rates(self) -> dict:
        """返回所有有效限速（全局 + 覆盖）。"""
        result = {"global": self.global_seconds_per_msg, "users": {}}
        for uid, rate in self._overrides.items():
            result["users"][uid] = rate
        return result
