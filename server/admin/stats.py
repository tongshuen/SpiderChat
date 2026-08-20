"""
管理员监控用的统计信息收集。
"""

import time
import threading


class StatsCollector:
    """收集并汇总服务器统计信息。"""

    def __init__(self, chat_server):
        self.server = chat_server
        self._start_time = time.time()
        self._lock = threading.Lock()

        self.messages_total = 0
        self.messages_failed = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.connections_peak = 0
        self.dht_queries = 0
        self.dht_stores = 0
        self.admin_cmds = 0

    def record_message(self, size: int = 0):
        with self._lock:
            self.messages_total += 1
            self.bytes_out += size

    def record_failure(self):
        with self._lock:
            self.messages_failed += 1

    def record_dht_query(self):
        with self._lock:
            self.dht_queries += 1

    def record_dht_store(self):
        with self._lock:
            self.dht_stores += 1

    def record_admin_cmd(self):
        with self._lock:
            self.admin_cmds += 1

    def update_peak(self, current: int):
        with self._lock:
            if current > self.connections_peak:
                self.connections_peak = current

    def get_report(self) -> dict:
        with self._lock:
            uptime = time.time() - self._start_time
            return {
                "uptime_seconds": int(uptime),
                "uptime_human": self._human_time(uptime),
                "messages_total": self.messages_total,
                "messages_failed": self.messages_failed,
                "bytes_in": self.bytes_in,
                "bytes_out": self.bytes_out,
                "connections_peak": self.connections_peak,
                "dht_queries": self.dht_queries,
                "dht_stores": self.dht_stores,
                "admin_commands": self.admin_cmds,
                "msg_rate_per_min": round(self.messages_total / max(uptime/60, 1), 2),
            }

    def _human_time(self, sec: float) -> str:
        h = int(sec // 3600)
        m = int((sec % 3600) // 60)
        s = int(sec % 60)
        return f"{h}h {m}m {s}s"
