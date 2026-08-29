#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
radio/dht.py — 无线电网络的分布式哈希表（DHT）节点发现。

设计目标
--------
无线电服务器（mesh 节点）之间需要互相发现、交换「频点路由表」，使客户端
只需知道【一个频率】即可接入整个无线电网络（影子公网），随后从已连接节点
的 DHT 表自动学习其它服务器的频点。

关键约定
--------
1. DHT 表项只存「频点 + 节点元数据」，**不存调制方式**：
   因为接入 / 协商所用的是固定协议（1000/2000Hz 2FSK, Hamming(7,4), 256 Baud，
   见 signature.py 与 link.py 的 _HANDSHAKE），调制方式是协商阶段的产物，
   由双方在握手后根据信道条件自行选定，无需在 DHT 中预置。
2. 每条表项：{
       node_id,            # 节点唯一标识（Ed25519 公钥指纹，十六进制）
       frequency_hz,       # 该节点监听/工作的中心频点（float, Hz）
       role,               # 'server' / 'relay' / 'gateway'
       gateway_to_public,   # bool，是否充当公网↔无线电网络的互通网关
       last_seen,          # 最近活跃时间戳（秒）
       rtt_ms,             # 估算往返时延（毫秒，可空）
       extra               # 预留扩展字段（地理/功率/模式等）
   }
3. 节点发现流程：
     a) 客户端在某频点（手动指定 或 扫描发现）完成固定协议握手；
     b) 服务端在握手应答中附带自己已知的 DHT 快照（bootstrap）；
     c) 客户端由此获得全网节点频点，后续可切换到任意节点；
     d) 节点间周期互发 PING/PONG + 表项扩散（gossip），保持 DHT 一致。

本模块是【纯逻辑 + 仿真】实现，不依赖真实 SDR；与 sdr_interface / signature
通过回调解耦，真实硬件接入时只需替换「收发原始字节」的传输层。
"""

import copy
import json
import os
import random
import socket
import threading
import time
import uuid
from typing import Callable, Optional

from shared.protocol import (
    GATEWAY_AUTO, GATEWAY_FORCE_ENABLED, GATEWAY_FORCE_DISABLED,
)


# ============================================================
# 常量
# ============================================================

# 固定协商/接入协议参数（DHT 不存调制方式，但存频点；握手本身用这些固定值）
HANDSHAKE_DEVIATION_A = 1000   # Hz
HANDSHAKE_DEVIATION_B = 2000   # Hz
HANDSHAKE_BAUD = 256

# DHT  gossip 间隔 / 表项过期时间
GOSSIP_INTERVAL_S = 30.0
ENTRY_EXPIRY_S = 5 * 60.0       # 5 分钟无心跳即过期


# ============================================================
# 节点 ID
# ============================================================

def new_node_id(seed: Optional[str] = None) -> str:
    """生成节点 ID（仿真用；真实环境应替换为 Ed25519 公钥指纹）。"""
    if seed:
        return "n_" + str(abs(hash(seed)))[:12]
    return "n_" + uuid.uuid4().hex[:12]


# ============================================================
# 网关自动判定管理器
# ============================================================
class GatewayManager:
    """
    网关节点管理器：自动判定本节点是否应充当公网↔无线电网络的互通网关。

    判定规则（默认自动模式）：
      - 同时具备「公网接入」和「SDR 硬件」→ 自动成为网关（is_gateway=True）
      - 仅具备其中一项 → 默认不是网关（is_gateway=False）
      - 两项都具备后 → 自动切换为是（recompute() 时触发变更回调）
    模式可随时切换：
      - 'auto'     自动判定（默认）
      - 'enabled'  强制开启网关
      - 'disabled' 强制关闭网关
    能力检测可随时调用 recompute()，结果变化时通过 on_gateway_change 回调通知上层。
    """

    def __init__(self, mode: str = GATEWAY_AUTO,
                 public_check: Optional[Callable[[], bool]] = None,
                 sdr_check: Optional[Callable[[], bool]] = None):
        self.mode = mode if mode in (GATEWAY_AUTO, GATEWAY_FORCE_ENABLED,
                                      GATEWAY_FORCE_DISABLED) else GATEWAY_AUTO
        self._has_public = False
        self._has_sdr = False
        self._public_check = public_check or self._default_public_check
        self._sdr_check = sdr_check or self._default_sdr_check
        self.on_gateway_change: Optional[Callable[[bool], None]] = None

    @staticmethod
    def _default_public_check() -> bool:
        """检测是否有公网接入能力（尝试连接公共 DNS 53 端口）。"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(("8.8.8.8", 53))
            sock.close()
            return True
        except Exception:
            return False

    @staticmethod
    def _default_sdr_check() -> bool:
        """检测是否有可用的 SDR 硬件（非 DummyBackend 即视为有硬件）。"""
        try:
            from .sdr_interface import auto_detect  # type: ignore
            sdr = auto_detect()
            return getattr(sdr, "name", "dummy") != "dummy"
        except Exception:
            return False

    def recompute(self) -> bool:
        """
        重新检测公网和 SDR 能力，返回网关状态是否发生了变化。
        检测结果变化时自动触发 on_gateway_change 回调。
        """
        old = self.is_gateway()
        try:
            self._has_public = bool(self._public_check())
        except Exception:
            self._has_public = False
        try:
            self._has_sdr = bool(self._sdr_check())
        except Exception:
            self._has_sdr = False
        new = self.is_gateway()
        if old != new and self.on_gateway_change is not None:
            try:
                self.on_gateway_change(new)
            except Exception:
                pass
        return old != new

    def is_gateway(self) -> bool:
        """返回当前是否应作为网关节点。"""
        if self.mode == GATEWAY_FORCE_ENABLED:
            return True
        if self.mode == GATEWAY_FORCE_DISABLED:
            return False
        # auto 模式：必须同时具备公网接入和 SDR 硬件
        return self._has_public and self._has_sdr

    def set_mode(self, mode: str):
        """
        随时切换网关模式（auto/enabled/disabled）。
        切换后若网关状态发生变化，触发 on_gateway_change 回调。
        """
        if mode not in (GATEWAY_AUTO, GATEWAY_FORCE_ENABLED, GATEWAY_FORCE_DISABLED):
            return
        old = self.is_gateway()
        self.mode = mode
        new = self.is_gateway()
        if old != new and self.on_gateway_change is not None:
            try:
                self.on_gateway_change(new)
            except Exception:
                pass

    def set_capabilities(self, has_public: Optional[bool] = None,
                         has_sdr: Optional[bool] = None):
        """
        手动设置能力检测结果（适用于上层已有检测结果、无需重复探测的场景）。
        传入 None 的字段保持原值。设置后若网关状态变化则触发回调。
        """
        old = self.is_gateway()
        if has_public is not None:
            self._has_public = bool(has_public)
        if has_sdr is not None:
            self._has_sdr = bool(has_sdr)
        new = self.is_gateway()
        if old != new and self.on_gateway_change is not None:
            try:
                self.on_gateway_change(new)
            except Exception:
                pass

    @property
    def has_public(self) -> bool:
        return self._has_public

    @property
    def has_sdr(self) -> bool:
        return self._has_sdr

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "has_public": self._has_public,
            "has_sdr": self._has_sdr,
            "is_gateway": self.is_gateway(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GatewayManager":
        gm = cls(mode=d.get("mode", GATEWAY_AUTO))
        gm._has_public = bool(d.get("has_public", False))
        gm._has_sdr = bool(d.get("has_sdr", False))
        return gm


# ============================================================
# DHT 表项
# ============================================================

class DHTEntry:
    """单个节点的路由信息。"""

    def __init__(self, node_id: str, frequency_hz: float, role: str = "server",
                 gateway_to_public: bool = False, rtt_ms: Optional[float] = None,
                 extra: Optional[dict] = None,
                 has_public_access: bool = False, has_sdr: bool = False):
        if role not in ("server", "relay", "gateway"):
            raise ValueError("role 必须为 server/relay/gateway")
        self.node_id = str(node_id)
        self.frequency_hz = float(frequency_hz)
        self.role = role
        self.gateway_to_public = bool(gateway_to_public)
        # 节点能力：是否具备公网接入 / SDR 硬件（用于网关自动判定和直连网络共享路由）
        self.has_public_access = bool(has_public_access)
        self.has_sdr = bool(has_sdr)
        self.extra = extra or {}
        self.rtt_ms = rtt_ms
        self.last_seen = time.time()

    # ---- 序列化 ----
    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "frequency_hz": self.frequency_hz,
            "role": self.role,
            "gateway_to_public": self.gateway_to_public,
            "has_public_access": self.has_public_access,
            "has_sdr": self.has_sdr,
            "last_seen": self.last_seen,
            "rtt_ms": self.rtt_ms,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DHTEntry":
        e = cls(
            node_id=d["node_id"],
            frequency_hz=d["frequency_hz"],
            role=d.get("role", "server"),
            gateway_to_public=d.get("gateway_to_public", False),
            rtt_ms=d.get("rtt_ms"),
            extra=d.get("extra"),
            has_public_access=d.get("has_public_access", False),
            has_sdr=d.get("has_sdr", False),
        )
        e.last_seen = d.get("last_seen", time.time())
        return e

    def touch(self):
        self.last_seen = time.time()

    def is_fresh(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return (now - self.last_seen) <= ENTRY_EXPIRY_S

    def __repr__(self) -> str:
        return (f"DHTEntry({self.node_id}, {self.frequency_hz/1e6:.3f}MHz, "
                f"{self.role}, gw={int(self.gateway_to_public)}, "
                f"pub={int(self.has_public_access)}, sdr={int(self.has_sdr)})")


# ============================================================
# DHT 表（带 gossip / 过期 / 持久化）
# ============================================================

class DHTTable:
    """
    分布式哈希表：以 node_id 为键维护全网节点频点。

    线程安全：所有公开方法加锁，可在后台 gossip 线程中使用。
    """

    def __init__(self, self_id: Optional[str] = None):
        self.self_id = self_id or new_node_id()
        self._entries: dict[str, DHTEntry] = {}
        self._lock = threading.Lock()
        self.on_update: Optional[Callable[[DHTEntry], None]] = None  # 表项变更回调

    # ---------- 增删改查 ----------
    def add(self, entry: DHTEntry) -> bool:
        """插入/更新表项。返回是否发生了实际变化。"""
        with self._lock:
            old = self._entries.get(entry.node_id)
            if old and old.to_dict() == entry.to_dict():
                old.last_seen = entry.last_seen   # 仅刷新心跳
                return False
            self._entries[entry.node_id] = entry
        if self.on_update:
            try:
                self.on_update(entry)
            except Exception:
                pass
        return True

    def remove(self, node_id: str) -> bool:
        with self._lock:
            return self._entries.pop(node_id, None) is not None

    def get(self, node_id: str) -> Optional[DHTEntry]:
        with self._lock:
            return copy.deepcopy(self._entries.get(node_id))

    def all(self) -> list[DHTEntry]:
        with self._lock:
            return list(self._entries.values())

    def fresh(self) -> list[DHTEntry]:
        """返回未过期的表项。"""
        now = time.time()
        with self._lock:
            return [e for e in self._entries.values() if e.is_fresh(now)]

    def gateways(self) -> list[DHTEntry]:
        """返回所有「公网互通网关」节点（无线电网络↔公网桥接）。"""
        return [e for e in self.fresh() if e.gateway_to_public]

    def frequencies(self) -> list[float]:
        """返回所有已知节点的工作频点（去重、排序）。"""
        with self._lock:
            return sorted({e.frequency_hz for e in self._entries.values()})

    # ---------- 合并（gossip 扩散）----------
    def merge(self, remote: list[dict]) -> int:
        """
        合并远端发来的表项快照，返回【新增/更新的条目数】。
        规则：node_id 相同且远端 last_seen 更新时，用远端覆盖本地。
        """
        added = 0
        for d in remote:
            try:
                remote_entry = DHTEntry.from_dict(d)
            except (KeyError, ValueError, TypeError):
                continue
            with self._lock:
                local = self._entries.get(remote_entry.node_id)
            if local is None or remote_entry.last_seen > local.last_seen:
                if self.add(remote_entry):
                    added += 1
        return added

    def snapshot(self, include_expired: bool = False) -> list[dict]:
        """导出可被 gossip 发送的快照。"""
        entries = self.all() if include_expired else self.fresh()
        return [e.to_dict() for e in entries]

    # ---------- 过期清理 ----------
    def expire(self) -> int:
        """删除过期表项，返回清理数量。"""
        now = time.time()
        removed = 0
        with self._lock:
            for nid in list(self._entries.keys()):
                if not self._entries[nid].is_fresh(now):
                    del self._entries[nid]
                    removed += 1
        return removed

    # ---------- 持久化 ----------
    def save(self, path: str) -> bool:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"self_id": self.self_id, "entries": self.snapshot()}, f, indent=2)
            return True
        except OSError:
            return False

    def load(self, path: str) -> bool:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return False
        self.self_id = data.get("self_id", self.self_id)
        for d in data.get("entries", []):
            try:
                self.add(DHTEntry.from_dict(d))
            except Exception:
                pass
        return True

    def __len__(self) -> int:
        return len(self.fresh())

    def __repr__(self) -> str:
        return f"DHTTable(self={self.self_id}, nodes={len(self)})"


# ============================================================
# Gossip 后台线程（节点间周期扩散 DHT）
# ============================================================

class DHTGossiper(threading.Thread):
    """
    模拟节点间周期互发 PING/PONG + 表项扩散。
    真实环境：把 _send_to_peer / _recv_from_peer 替换为真实无线电收发即可。
    """

    def __init__(self, table: DHTTable, interval: float = GOSSIP_INTERVAL_S,
                 transport: Optional[Callable[[bytes], None]] = None):
        super().__init__(daemon=True)
        self.table = table
        self.interval = interval
        self._running = False
        # transport(payload_bytes) -> 发送到对端；由上层（radio mesh）注入
        self.transport = transport

    def start(self):
        self._running = True
        super().start()

    def stop(self):
        self._running = False

    def run(self):
        while self._running:
            try:
                self.table.expire()
                # 发送本地快照（真实环境：通过固定协商协议信道发送）
                if self.transport:
                    payload = json.dumps({"type": "dht_snapshot",
                                          "from": self.table.self_id,
                                          "entries": self.table.snapshot()}).encode("utf-8")
                    try:
                        self.transport(payload)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(self.interval)

    # ---- 对端调用：收到远端快照时调用此方法 ----
    def on_receive(self, payload: bytes) -> int:
        """收到对端 gossip 消息，解析并合并。返回新增条目数。"""
        try:
            msg = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return 0
        if msg.get("type") != "dht_snapshot":
            return 0
        return self.table.merge(msg.get("entries", []))


# ============================================================
# 引导（Bootstrap）：客户端只需一个频点即可接入
# ============================================================

def bootstrap_from_seed(frequency_hz: float, table: DHTTable,
                        handshake: Optional[dict] = None,
                        gateway_mgr: Optional[GatewayManager] = None) -> DHTEntry:
    """
    客户端「引导」：在指定频点（seed）完成固定协议握手，获得服务端的 DHT 快照。

    参数
    ----
    frequency_hz : float
        用户手动指定的【唯一】频点（Hz）—— 自动模式下也只需这一个值。
    table : DHTTable
        本地 DHT 表（将被远端快照填充）。
    handshake : dict, optional
        固定握手参数；省略时使用 HANDSHAKE 默认值（1000/2000Hz, 256 Baud）。
    gateway_mgr : GatewayManager, optional
        网关管理器；传入时，种子节点的 gateway_to_public 由管理器动态判定
        （同时具备公网+SDR 时为 True，否则为 False）。
        不传时回退到旧行为（默认 True，保持向后兼容）。

    返回
    ----
    DHTEntry：成功接入的种子节点；失败则返回其占位（is_fresh=False）。

    说明
    ----
    真实环境：在此调用 phy.encode/decode + signature 完成握手，并从应答帧
    提取 DHT 快照。仿真实现：生成一个符合协议的占位节点，并把若干「已知节点」
    写入本地表，演示「一个频点 → 全网拓扑」的发现过程。
    """
    hs = handshake or {
        "deviation_a": HANDSHAKE_DEVIATION_A,
        "deviation_b": HANDSHAKE_DEVIATION_B,
        "baud": HANDSHAKE_BAUD,
    }
    seed_id = new_node_id(f"seed-{frequency_hz}")
    # 动态网关判定：传入 gateway_mgr 时按其状态判定，否则默认 True（向后兼容）
    if gateway_mgr is not None:
        is_gw = gateway_mgr.is_gateway()
        has_pub = gateway_mgr.has_public
        has_sdr = gateway_mgr.has_sdr
    else:
        is_gw = True
        has_pub = True
        has_sdr = True
    seed = DHTEntry(node_id=seed_id, frequency_hz=frequency_hz,
                    role="gateway" if is_gw else "server",
                    gateway_to_public=is_gw,
                    has_public_access=has_pub, has_sdr=has_sdr)
    table.add(seed)

    # 仿真：种子节点「告知」客户端它还知道哪些节点（真实环境来自握手应答帧）
    _populate_simulated_peers(table, seed)

    return seed


def _populate_simulated_peers(table: DHTTable, seed: DHTEntry):
    """仿真用：围绕种子节点生成若干邻居节点，演示 DHT 扩散。"""
    base = int(seed.frequency_hz)
    spans = [-100e3, -50e3, +50e3, +100e3]   # 相邻频点偏移（Hz）
    for i, off in enumerate(spans):
        peer_freq = base + off
        if peer_freq <= 0:
            continue
        peer = DHTEntry(
            node_id=new_node_id(f"peer-{seed.node_id}-{i}"),
            frequency_hz=peer_freq,
            role="relay" if i % 2 else "server",
            gateway_to_public=(i == 0),   # 至少一个网关
            has_public_access=(i == 0),    # 网关节点具备公网接入
            has_sdr=True,                   # 无线电网络节点均有 SDR
            rtt_ms=round(random.uniform(20, 200), 1),
            extra={"via_seed": seed.node_id},
        )
        table.add(peer)


# ============================================================
# 自测
# ============================================================

def selftest():
    random.seed(0)

    # 1. 表项基本属性 + 过期
    e = DHTEntry("node_A", 14_100_000, role="gateway", gateway_to_public=True)
    assert e.frequency_hz == 14_100_000
    assert e.is_fresh()
    assert not e.is_fresh(now=e.last_seen + ENTRY_EXPIRY_S + 1)
    print("[DHT] entry freshness OK")

    # 2. 添加 / 合并 / 快照往返
    t = DHTTable(self_id="local")
    t.add(DHTEntry("n1", 7_100_000, role="server"))
    t.add(DHTEntry("n2", 14_100_000, role="gateway", gateway_to_public=True))
    assert len(t) == 2
    snap = t.snapshot()
    t2 = DHTTable(self_id="other")
    merged = t2.merge(snap)
    assert merged == 2, merged
    assert t2.frequencies() == sorted([7.1e6, 14.1e6])
    print("[DHT] add / merge / snapshot OK (2 nodes)")

    # 3. 合并规则：仅当远端更新时才覆盖
    old_entry = DHTEntry("n1", 7_100_000)
    old_entry.last_seen = time.time() - 100
    t2.add(old_entry)                      # 本地有更旧的 n1
    refreshed = [{"node_id": "n1", "frequency_hz": 7_100_000,
                  "role": "server", "gateway_to_public": False,
                  "last_seen": time.time() + 50}]   # 远端更新
    assert t2.merge(refreshed) == 1        # 应覆盖
    print("[DHT] merge-update rule OK")

    # 4. 网关筛选
    gw = t.gateways()
    assert any(e.node_id == "n2" for e in gw)
    print("[DHT] gateway selection OK")

    # 5. 持久化往返
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_dht_test.json")
    t.save(path)
    t3 = DHTTable()
    assert t3.load(path)
    assert len(t3) == 2
    os.remove(path)
    print("[DHT] save/load round-trip OK")

    # 6. 过期清理
    t4 = DHTTable()
    stale = DHTEntry("stale", 3.5e6)
    stale.last_seen = time.time() - ENTRY_EXPIRY_S - 1
    t4.add(stale)
    t4.add(DHTEntry("fresh_node", 3.6e6))
    assert t4.expire() == 1
    assert len(t4) == 1
    print("[DHT] expiry cleanup OK")

    # 7. 引导：一个频点 -> 学到全网拓扑（核心场景）
    boot = DHTTable(self_id="client")
    seed = bootstrap_from_seed(14_100_000, boot)
    assert seed.node_id in {e.node_id for e in boot.all()}
    assert len(boot) >= 4, "应至少学到种子 + 若干邻居"
    assert any(e.gateway_to_public for e in boot.gateways()), "至少存在一个网关"
    print(f"[DHT] bootstrap OK: 1 seed freq -> {len(boot)} known nodes, "
          f"gateways={len(boot.gateways())}")

    # 8. 非法 role 应拒绝
    try:
        DHTEntry("bad", 1e6, role="invalid")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid role must raise")
    print("[DHT] role validation OK")

    # 9. 序列化往返一致性
    e2 = DHTEntry.from_dict(e.to_dict())
    assert e2.to_dict() == e.to_dict()
    print("[DHT] entry serialize round-trip OK")

    # 10. GatewayManager：自动模式判定逻辑
    gm_only_pub = GatewayManager(mode=GATEWAY_AUTO,
                                  public_check=lambda: True, sdr_check=lambda: False)
    gm_only_pub.recompute()
    assert gm_only_pub.has_public is True and gm_only_pub.has_sdr is False
    assert gm_only_pub.is_gateway() is False
    gm_only_sdr = GatewayManager(mode=GATEWAY_AUTO,
                                  public_check=lambda: False, sdr_check=lambda: True)
    gm_only_sdr.recompute()
    assert gm_only_sdr.is_gateway() is False
    gm_both = GatewayManager(mode=GATEWAY_AUTO,
                             public_check=lambda: True, sdr_check=lambda: True)
    changed = gm_both.recompute()
    assert gm_both.is_gateway() is True
    assert changed is True
    print("[DHT] GatewayManager auto-mode OK")

    # 11. GatewayManager：能力变化时自动切换 + 回调
    cap = {"pub": False, "sdr": False}
    changes = []
    gm_dyn = GatewayManager(mode=GATEWAY_AUTO,
                             public_check=lambda: cap["pub"],
                             sdr_check=lambda: cap["sdr"])
    gm_dyn.on_gateway_change = lambda v: changes.append(v)
    gm_dyn.recompute()
    assert gm_dyn.is_gateway() is False and changes == []
    cap["pub"] = True
    assert gm_dyn.recompute() is False
    cap["sdr"] = True
    assert gm_dyn.recompute() is True
    assert gm_dyn.is_gateway() is True and changes == [True]
    cap["pub"] = False
    assert gm_dyn.recompute() is True
    assert gm_dyn.is_gateway() is False and changes == [True, False]
    print("[DHT] GatewayManager auto-switch on capability change OK")

    # 12. GatewayManager：手动覆盖（随时可配置）
    gm_manual = GatewayManager(mode=GATEWAY_AUTO,
                               public_check=lambda: False, sdr_check=lambda: False)
    gm_manual.recompute()
    assert gm_manual.is_gateway() is False
    gm_manual.set_mode(GATEWAY_FORCE_ENABLED)
    assert gm_manual.is_gateway() is True
    gm_manual.set_mode(GATEWAY_FORCE_DISABLED)
    assert gm_manual.is_gateway() is False
    gm_manual.set_mode(GATEWAY_AUTO)
    assert gm_manual.is_gateway() is False
    gm_manual.set_capabilities(has_public=True, has_sdr=True)
    assert gm_manual.is_gateway() is True
    print("[DHT] GatewayManager manual override OK")

    # 13. bootstrap_from_seed 传入 gateway_mgr：非网关时种子节点 gateway_to_public=False
    boot2 = DHTTable(self_id="client-no-gw")
    gm_no = GatewayManager(mode=GATEWAY_AUTO,
                           public_check=lambda: True, sdr_check=lambda: False)
    gm_no.recompute()
    seed2 = bootstrap_from_seed(14_100_000, boot2, gateway_mgr=gm_no)
    assert seed2.gateway_to_public is False
    assert seed2.role == "server"
    assert seed2.has_public_access is True and seed2.has_sdr is False
    print("[DHT] bootstrap_with gateway_mgr (non-gateway) OK")

    # 14. bootstrap_from_seed 传入 gateway_mgr：双能力时种子节点为网关
    boot3 = DHTTable(self_id="client-gw")
    gm_yes = GatewayManager(mode=GATEWAY_AUTO,
                            public_check=lambda: True, sdr_check=lambda: True)
    gm_yes.recompute()
    seed3 = bootstrap_from_seed(7_100_000, boot3, gateway_mgr=gm_yes)
    assert seed3.gateway_to_public is True
    assert seed3.role == "gateway"
    print("[DHT] bootstrap_with gateway_mgr (gateway) OK")

    print("ALL DHT TESTS PASSED")


if __name__ == "__main__":
    selftest()
