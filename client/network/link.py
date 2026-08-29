#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
link.py — Spider 统一链路层（公网 / 直连 / 无线电网络）

本模块是整个「多链路整合」的中枢，对外只暴露两个接口：
    Link.send(payload: bytes) -> None
    Link.recv() -> bytes | None
上层（IM / 会话层）无需关心当前走的是公网 WebSocket、局域网/蓝牙直连，还是无线电。

三种链路模式
------------
1. PUBLIC     公网：现有 Spider 服务器/中继网络（Internet）。
2. DIRECT     直连：蓝牙 / WiFi / 局域网 / 无线电 的直接点对点（无基础设施）。
3. RADIO_MESH 无线电网络：「影子公网」——把公网那套逻辑原样移植到无线电上，
               在无线电上自组织成类公网的结构（发现/中继/路由），
               公网与无线电网络上的用户【可互通】（网关桥接）。

频率策略
--------
无论手动还是自动模式，频率【始终由用户手动指定】；自动模式只负责协商
调制参数（波特率/FEC/重复码），不协商频率。
内置频段搜索：扫描 HAMbandlist.json 中的业余频段，用本协议独特的导频/签名
（见 signature.py）识别「疑似本协议」的信号，避免误连其它协议。

自动模式的「未命中降级」（本文件核心逻辑，见 ScanScope / auto_bootstrap）
----------------------------------------------------------------
自动模式在【用户指定的频点】完成固定协议握手前，可先调用 scan_bands()
做一次预扫描来「自动锁定一个确实在发本协议信号的频点」。扫描范围由
RadioConfig.search_policy 控制：

  'ham_only'  —— 仅扫描 HAMbandlist.json 中的业余频段（默认，合规优先）；
  'full'      —— 若业余段未搜到，扩大到全频段（0 ~ hardware上限）；
  'custom'    —— 若业余段未搜到，改扫用户指定的 custom_bands 列表。

降级触发条件：scan_bands(scope='ham') 返回空（业余段内无任何疑似本协议信号）。
降级时的「选择方式」由 RadioConfig.fallback_action 控制：

  'ask'   —— 暂停扫描，通过 on_fallback 回调把决定权交给上层（GUI/用户）；
  'auto'  —— 自动按 search_policy 执行（full 或 custom），无需用户确认；
  'stop'  —— 不降级，直接放弃自动锁定，退回到用户手填的 frequency_hz。

完整流程见 Link._auto_lock_frequency() 与 Link._send_radio_mesh()。
"""

import enum
import json
import os
import threading
import time
from typing import Optional, Callable, List, Dict, Any

from shared.protocol import (
    GATEWAY_AUTO, GATEWAY_FORCE_ENABLED, GATEWAY_FORCE_DISABLED,
)


# 扫描范围：业余段 / 全频段 / 用户指定频段
class ScanScope(enum.Enum):
    HAM_ONLY = "ham_only"   # 仅 HAMbandlist.json 中的业余频段（默认，合规优先）
    FULL = "full"           # 全频段（0 ~ hardware 上限）
    CUSTOM = "custom"       # 用户在 custom_bands 中指定的频段列表


# 业余段未命中时的降级选择方式
class FallbackAction(enum.Enum):
    STOP = "stop"   # 不降级，直接用用户手填频点
    AUTO = "auto"   # 自动按 search_policy 扩大扫描（无需用户确认）
    ASK = "ask"     # 暂停，通过 on_fallback 回调把决定权交给上层/GUI


# 全频段扫描的默认软上限（Hz）：真实 SDR 上限由 sdr_interface 覆盖
DEFAULT_FULL_SCAN_LOW_HZ = 0.0
DEFAULT_FULL_SCAN_HIGH_HZ = 3_000_000_000.0  # 3 GHz


# ============================================================
# 链路模式枚举
# ============================================================

class LinkMode(enum.Enum):
    PUBLIC = "public"          # 公网（Internet / 现有 Spider 网络）
    DIRECT = "direct"          # 直连（蓝牙 / WiFi / 局域网 / 无线电）
    RADIO_MESH = "radio_mesh"  # 无线电网络（影子公网）


# 模式可读名（设置界面下拉框用）
MODE_LABELS = {
    LinkMode.PUBLIC:    "公网",
    LinkMode.DIRECT:    "直连（蓝牙 / WiFi / 局域网 / 无线电）",
    LinkMode.RADIO_MESH: "无线电网络（影子公网）",
}


# ============================================================
# 配置：统一存放频率、复用方式、调制、参数
# ============================================================

class RadioConfig:
    """
    无线电配置（手动/自动共用）。
    字段在「手动模式」下由用户输入；「自动模式」下仅频率由用户输入，
    其余由协商自动选定。

    参数说明
    --------
    frequency_hz : float       频率（Hz），≥0，不强制检查是否在业余段（仅警告）
    duplex       : int         复用方式：0b1 = 12.5kHz 时分(TDD) / 0b0 = 25kHz 频分(FDD)
    modulation   : int         调制方式 0=FSK 1=ASK 2=PSK 3=QAM 4=GMSK
    mode         : str         'auto' 自动协商 / 'manual' 手动
    mod_params   : dict        调制参数（取决于调制方式）
    bandwidth_hz : float       占用带宽，必须 ≤ 12500（12.5kHz）
    search_policy: str        自动模式扫描范围：'ham_only' / 'full' / 'custom'
    custom_bands : list        search_policy='custom' 时生效，[(low_hz, high_hz), ...]
    fallback_action: str      业余段未命中时的行为：'stop' / 'auto' / 'ask'
    on_fallback : callable    降级回调（ask 模式下使用），签名见 _auto_lock_frequency
    """

    # 默认调制参数模板（每种调制方式的参数 schema）
    PARAM_SCHEMA = {
        0: {  # FSK：logic_x/y/z 频偏 + baud + fec
            "logic_0_deviation": 400,   # Hz，相对中心频点
            "logic_1_deviation": 800,
            "baud": 300,
            "fec": "hamming74+repeat2",
        },
        1: {  # ASK：幅度电平 + baud
            "levels": 2, "amplitude_high": 1.0, "amplitude_low": 0.0, "baud": 300,
        },
        2: {  # PSK：相位差 + baud
            "logic_0_phase": 0, "logic_1_phase": 180, "baud": 300,
        },
        3: {  # QAM：星座阶数 + 波特 + 滚降
            "order": 16, "baud": 2400, "rolloff": 0.35,
        },
        4: {  # GMSK（默认退化到 FSK 参数）
            "bt": 0.5, "baud": 1200,
        },
    }

    # 搜索范围/降级策略的合法取值
    SEARCH_POLICIES = tuple(e.value for e in ScanScope)
    FALLBACK_ACTIONS = tuple(e.value for e in FallbackAction)

    def __init__(self, frequency_hz: float = 14_100_000, duplex: int = 1,
                 modulation: int = 0, mode: str = "auto",
                 mod_params: Optional[dict] = None, bandwidth_hz: float = 12500,
                 search_policy: str = "ham_only", custom_bands: Optional[list] = None,
                 fallback_action: str = "ask", on_fallback: Optional[Callable] = None):
        self.frequency_hz = float(frequency_hz)
        self.duplex = int(duplex)                # 0 或 1（校验后再掩码，见 validate）
        self.modulation = int(modulation)        # 0..4
        self.mode = mode if mode in ("auto", "manual") else "auto"
        self.mod_params = mod_params if mod_params is not None else dict(self.PARAM_SCHEMA.get(self.modulation, {}))
        self.bandwidth_hz = float(bandwidth_hz)
        self.search_policy = search_policy if search_policy in self.SEARCH_POLICIES else "ham_only"
        self.custom_bands = self._normalize_custom_bands(custom_bands)
        self.fallback_action = fallback_action if fallback_action in self.FALLBACK_ACTIONS else "ask"
        self.on_fallback = on_fallback  # 降级回调（ask 模式）

    @staticmethod
    def _normalize_custom_bands(value) -> list:
        """规整 custom_bands 为 [(low, high), ...]，保证 low <= high 且均为 float。"""
        out = []
        if not isinstance(value, (list, tuple)):
            return out
        for item in value:
            try:
                if isinstance(item, (list, tuple)) and len(item) >= 2:
                    lo, hi = float(item[0]), float(item[1])
                elif isinstance(item, dict):
                    lo = float(item.get("low_hz", item.get("low")))
                    hi = float(item.get("high_hz", item.get("high")))
                else:
                    continue
            except (TypeError, ValueError):
                continue
            if lo > hi:
                lo, hi = hi, lo
            out.append((lo, hi))
        return out

    # ---------- 输入校验（手动模式用）----------
    def validate(self) -> list:
        """返回错误列表；空列表表示校验通过。"""
        errs = []
        if self.frequency_hz < 0:
            errs.append("频率必须为 ≥ 0 的浮点数（Hz）")
        if self.duplex not in (0, 1):
            errs.append("复用方式必须为 0b0(25kHz FDD) 或 0b1(12.5kHz TDD)")
        if self.modulation not in self.PARAM_SCHEMA:
            errs.append("调制方式必须为 0..4（FSK/ASK/PSK/QAM/GMSK）")
        if self.bandwidth_hz > 12500 + 1e-6:
            errs.append("占用带宽必须 ≤ 12.5 kHz（当前 %.1f Hz）" % self.bandwidth_hz)
        if self.search_policy not in self.SEARCH_POLICIES:
            errs.append("search_policy 必须为 ham_only / full / custom")
        if self.search_policy == "custom" and not self.custom_bands:
            errs.append("search_policy=custom 时必须至少指定一个 custom_bands 频段")
        if self.fallback_action not in self.FALLBACK_ACTIONS:
            errs.append("fallback_action 必须为 ask / auto / stop")
        return errs

    def warn_out_of_band(self, bandlist_path: Optional[str] = None) -> Optional[str]:
        """若频率不在业余段内，返回警告字符串（不强制拦截）。"""
        bands = _load_ham_bands(bandlist_path)
        if not bands:
            return None
        for lo, hi in bands:
            if lo <= self.frequency_hz <= hi:
                return None
        return "警告：%.3f MHz 不在已知业余频段内（仅警告，不拦截）" % (self.frequency_hz / 1e6)

    def to_dict(self) -> dict:
        return {
            "frequency_hz": self.frequency_hz,
            "duplex": self.duplex,
            "modulation": self.modulation,
            "mode": self.mode,
            "mod_params": self.mod_params,
            "bandwidth_hz": self.bandwidth_hz,
            "search_policy": self.search_policy,
            "custom_bands": [list(b) for b in self.custom_bands],
            "fallback_action": self.fallback_action,
            # on_fallback 为运行时回调，不可序列化，此处仅记录是否设置
            "has_on_fallback": self.on_fallback is not None,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RadioConfig":
        return cls(
            frequency_hz=d.get("frequency_hz", 14_100_000),
            duplex=d.get("duplex", 1),
            modulation=d.get("modulation", 0),
            mode=d.get("mode", "auto"),
            mod_params=d.get("mod_params"),
            bandwidth_hz=d.get("bandwidth_hz", 12500),
            search_policy=d.get("search_policy", "ham_only"),
            custom_bands=d.get("custom_bands"),
            fallback_action=d.get("fallback_action", "ask"),
        )


# ============================================================
# HAM 频段列表加载（用于搜索 + 越界警告）
# ============================================================

def _load_ham_bands(path: Optional[str] = None) -> list:
    """返回 [(low_Hz, high_Hz), ...] 列表。找不到文件时返回 []。"""
    if path is None:
        # 默认与 link.py 同目录的 HAMbandlist.json
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "HAMbandlist.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    bands = []
    for entry in data if isinstance(data, list) else data.get("bands", []):
        lo = entry.get("low_hz", entry.get("low"))
        hi = entry.get("high_hz", entry.get("high"))
        if lo is None or hi is None:
            continue
        bands.append((float(lo), float(hi)))
    return bands


# ============================================================
# 频段搜索：用独特导频/签名识别疑似本协议的信号
# 签名见 signature.py；这里只做「能量探测 + 签名匹配」的骨架。
# ============================================================

def _iter_bands(scope: str, config: Optional[RadioConfig] = None,
                bandlist_path: Optional[str] = None) -> List[tuple]:
    """
    按扫描范围枚举「(low_hz, high_hz)」频段列表。
      'ham_only' -> HAMbandlist.json 中的业余频段
      'full'     -> 单个全频段区间 [0, 硬件上限]
      'custom'   -> config.custom_bands
    """
    if scope == ScanScope.FULL.value:
        low = DEFAULT_FULL_SCAN_LOW_HZ
        high = DEFAULT_FULL_SCAN_HIGH_HZ
        # 若有 SDR 硬件，用其实际频率上限收缩范围
        try:
            from .radio.sdr_interface import auto_detect  # type: ignore
        except ImportError:
            auto_detect = None  # type: ignore
        if auto_detect is not None:
            try:
                sdr = auto_detect()
                high = getattr(sdr, "max_frequency_hz", DEFAULT_FULL_SCAN_HIGH_HZ) or DEFAULT_FULL_SCAN_HIGH_HZ
            except Exception:
                pass
        return [(float(low), float(high))]
    if scope == ScanScope.CUSTOM.value:
        if config is not None and config.custom_bands:
            return list(config.custom_bands)
        return []  # custom 但未配置 -> 空集（由调用方决定是否回退到 ham_only）
    # 默认：ham_only
    return _load_ham_bands(bandlist_path)


def scan_bands(config: RadioConfig, bandlist_path: Optional[str] = None,
               callback: Optional[Callable] = None, scope: str = "ham_only") -> list:
    """
    在指定范围内扫描，寻找「疑似本协议」的信号。
    返回 [{'frequency_hz': ..., 'signature_match': bool, 'scope': str}, ...]。

    参数
    ----
    config : RadioConfig       无线电配置（custom 模式下读 custom_bands）
    bandlist_path : str        业余频段文件路径（缺省自动定位 HAMbandlist.json）
    callback : callable        每扫描一个频点回调(center_hz)，用于进度反馈
    scope : str                'ham_only' / 'full' / 'custom'

    真实 SDR 采样由 sdr_interface 提供；无硬件时退化为仿真（返回空列表，不伪造）。
    """
    bands = _iter_bands(scope, config, bandlist_path)
    if not bands:
        return []
    found = []
    for lo, hi in bands:
        center = (lo + hi) / 2.0
        # —— 接入点：在此调用 SDR 采集 + signature.detect() ——
        # 仿真实现：默认无任何发现（无硬件时不伪造结果）
        if callback:
            try:
                callback(center)
            except Exception:
                pass
    return found


def scan_with_fallback(config: RadioConfig, bandlist_path: Optional[str] = None,
                       callback: Optional[Callable] = None) -> dict:
    """
    分级扫描（自动模式的核心入口）：

      第一步：在业余段（ham_only）扫描；
      第二步：若业余段无命中，按 config.search_policy 降级：
                full   -> 扩大到全频段
                custom -> 改扫 config.custom_bands
                （两者皆空/未配置时等同 stop）
      第三步：若仍无命中，按 config.fallback_action 决定最终行为：
                stop -> 返回空列表（调用方退回到用户手填频点）
                auto -> 直接采用降级结果（可能为空）
                ask  -> 若配置了 on_fallback 回调，把选择交给上层/GUI

    返回
    ----
    {
      'results': [...],        # 最终命中列表（可能为空）
      'scope_used': str,       # 实际产出命中的范围；空时为 'none'
      'fallback_triggered': bool,  # 是否触发了「业余段未命中」的降级
      'decision': str,         # 'ham' / 'fallback_scope' / 'user_stop' / 'user_custom'
    }
    """
    # 第一步：业余段
    ham = scan_bands(config, bandlist_path, callback, scope=ScanScope.HAM_ONLY.value)
    if ham:
        return {"results": ham, "scope_used": ScanScope.HAM_ONLY.value,
                "fallback_triggered": False, "decision": "ham"}

    # 第二步：业余段无命中 -> 降级扫描
    fb_scope = config.search_policy  # 'full' / 'custom' / 'ham_only'(=stop)
    if fb_scope not in (ScanScope.FULL.value, ScanScope.CUSTOM.value):
        # search_policy 就是 ham_only -> 不降级，直接 stop
        return {"results": [], "scope_used": "none",
                "fallback_triggered": True, "decision": "user_stop"}

    fb_results = scan_bands(config, bandlist_path, callback, scope=fb_scope)
    if fb_results:
        return {"results": fb_results, "scope_used": fb_scope,
                "fallback_triggered": True, "decision": "fallback_scope"}

    # 第三步：降级后仍无命中 -> 按 fallback_action 定夺
    if config.fallback_action == FallbackAction.STOP.value:
        return {"results": [], "scope_used": "none",
                "fallback_triggered": True, "decision": "user_stop"}
    if config.fallback_action == FallbackAction.ASK.value and config.on_fallback is not None:
        try:
            # 上层返回：'stop' / 'full' / 'custom' / 或直接返回频点(float)
            choice = config.on_fallback({
                "ham_results": ham,
                "fallback_scope": fb_scope,
                "fallback_results": fb_results,
                "custom_bands": list(config.custom_bands),
            })
        except Exception:
            choice = "stop"
        if choice == "full":
            return {"results": scan_bands(config, bandlist_path, callback, scope=ScanScope.FULL.value),
                    "scope_used": ScanScope.FULL.value, "fallback_triggered": True,
                    "decision": "user_custom"}
        if choice == "custom":
            return {"results": scan_bands(config, bandlist_path, callback, scope=ScanScope.CUSTOM.value),
                    "scope_used": ScanScope.CUSTOM.value, "fallback_triggered": True,
                    "decision": "user_custom"}
        if isinstance(choice, (int, float)) and choice > 0:
            # 用户直接指定了一个频点
            return {"results": [{"frequency_hz": float(choice),
                                 "signature_match": False, "scope": "user_specified"}],
                    "scope_used": "user_specified", "fallback_triggered": True,
                    "decision": "user_custom"}
        # 'stop' 或其它 -> 放弃
        return {"results": [], "scope_used": "none",
                "fallback_triggered": True, "decision": "user_stop"}

    # auto 模式（或 ask 但未配回调）-> 返回降级扫描结果（可能为空）
    return {"results": fb_results, "scope_used": fb_scope if fb_results else "none",
            "fallback_triggered": True, "decision": "fallback_scope"}


# ============================================================
# 协商：自动模式下选定最快且当前信道可稳定通信的参数组合
# 固定握手参数：1000/2000Hz 2FSK, Hamming(7,4), 256 Baud
# ============================================================
# 自动协商已下沉到 C 库 libphy.so（phy_auto_negotiate）。
# Python 端不再维护候选集和协商逻辑；自动模式下 Link 仅将频率和比特流交给 C 库，
# 由 C 库完成信道探测、最优参数选择、调制/解调及 SDR 交互。
# ============================================================


# ============================================================
# 链路中枢
# ============================================================

class Link:
    """
    统一链路对象。由 settings / 注册界面创建并持有。
    上层只需：link.send(bytes) / link.recv()。
    """

    def __init__(self, mode: LinkMode, radio: Optional[RadioConfig] = None,
                 public_url: str = "wss://spider.example.com",
                 gateway_mode: str = GATEWAY_AUTO):
        self.mode = mode
        self.radio = radio or RadioConfig()
        self.public_url = public_url
        self._lock = threading.Lock()
        self._rx_queue = []
        self._running = False
        # 网关管理器：自动判定本节点是否为公网↔无线电网络的互通网关
        # 规则：同时具备公网接入 + SDR 硬件时自动成为网关；仅一项时默认不是；
        #       两项都具备后自动切换为是；可随时通过 set_gateway_mode 手动覆盖。
        try:
            from .radio.dht import GatewayManager as _GM
        except ImportError:
            from radio.dht import GatewayManager as _GM  # type: ignore
        self._gateway_mgr = _GM(mode=gateway_mode)
        self._gateway_mgr.on_gateway_change = self._on_gateway_status_change
        # DHT 表：无线电网络模式下维护已知节点频点（不含调制方式）。
        # 自动模式下，只需 radio.frequency_hz 这一个频点做 bootstrap。
        try:
            from .radio.dht import DHTTable as _DHT, bootstrap_from_seed as _bs
        except ImportError:
            from radio.dht import DHTTable as _DHT, bootstrap_from_seed as _bs  # type: ignore
        self._dht = _DHT()
        self._bootstrap = _bs
        self._dht_bootstrapped = False
        self._locked_frequency_hz: Optional[float] = None  # 自动锁定的频点（None=尚未锁定）
        # 网关状态变更回调（供上层 GUI / 网络层订阅）
        self.on_gateway_change: Optional[Callable[[bool], None]] = None

    # ---------- 自动模式：频点自动锁定 ----------
    def _auto_lock_frequency(self, bandlist_path: Optional[str] = None,
                             progress: Optional[Callable[[float], None]] = None) -> float:
        """
        自动模式「频点锁定」逻辑（本文件核心）。

        流程：
          1) 先在业余段扫描（合规优先）；
          2) 业余段无命中 -> 按 radio.search_policy 降级：
               'full'   扩大到全频段
               'custom' 改扫 radio.custom_bands
               'ham_only'(=stop) 不降级
          3) 降级后仍无命中 -> 按 radio.fallback_action 定夺：
               'stop'  直接用用户手填频点（退化为"手动指定"语义）
               'auto'  无需用户确认，采用降级结果（为空则退回手填频点）
               'ask'   通过 radio.on_fallback(...) 把决定权交给上层/GUI，
                        上层可返回 'full'/'custom'/具体频点(float)/'stop'

        返回最终用于 bootstrap 的频点（Hz）。任何时候都不会返回 <=0 的值：
        若所有扫描均无命中且未锁定，则退回 radio.frequency_hz（用户手填值）。
        """
        cfg = self.radio
        if cfg.mode != "auto":
            # 手动模式：始终直接使用用户指定的频点
            self._locked_frequency_hz = cfg.frequency_hz
            return cfg.frequency_hz

        outcome = scan_with_fallback(cfg, bandlist_path, callback=progress)

        if outcome["results"]:
            # 取首个命中（按信号质量排序可在此扩展；当前仿真无 SNR，取第一个）
            chosen = float(outcome["results"][0]["frequency_hz"])
            self._locked_frequency_hz = chosen
            return chosen

        # 未命中：退回用户手填频点（stop/ask-returned-stop 都会走到这里）
        self._locked_frequency_hz = cfg.frequency_hz
        return cfg.frequency_hz

    def auto_lock_frequency(self, **kw) -> float:
        """公开封装：供 GUI/注册界面显式触发频点扫描（如"重新扫描"按钮）。"""
        return self._auto_lock_frequency(**kw)

    # ---------- 网关管理（自动判定 + 随时可配置）----------
    def _on_gateway_status_change(self, is_gateway: bool):
        """网关状态变更时的内部回调：通知上层并更新 DHT 中自身条目的角色。"""
        if self.on_gateway_change is not None:
            try:
                self.on_gateway_change(is_gateway)
            except Exception:
                pass

    def recompute_gateway(self) -> bool:
        """
        重新检测公网和 SDR 能力，自动更新网关状态。
        返回网关状态是否发生了变化。
        当两项能力（公网+SDR）都具备时自动切换为网关；失去任一项时自动切回。
        """
        return self._gateway_mgr.recompute()

    def is_gateway(self) -> bool:
        """返回当前是否作为网关节点。"""
        return self._gateway_mgr.is_gateway()

    def set_gateway_mode(self, mode: str):
        """
        随时切换网关模式：
          'auto'     自动判定（同时具备公网+SDR 时为网关）
          'enabled'  强制开启网关
          'disabled' 强制关闭网关
        """
        self._gateway_mgr.set_mode(mode)

    def get_gateway_mode(self) -> str:
        """返回当前网关模式（auto/enabled/disabled）。"""
        return self._gateway_mgr.mode

    def get_gateway_status(self) -> dict:
        """返回网关状态详情（模式、能力、是否网关）。"""
        return self._gateway_mgr.to_dict()

    def set_gateway_capabilities(self, has_public: Optional[bool] = None,
                                  has_sdr: Optional[bool] = None):
        """
        手动设置能力检测结果（适用于上层已有检测结果的场景）。
        传入 None 的字段保持原值。设置后若网关状态变化则自动切换。
        """
        self._gateway_mgr.set_capabilities(has_public, has_sdr)

    # ---------- 上层接口 ----------
    def send(self, payload: bytes) -> bool:
        """发送二进制载荷。返回是否成功入队/发送。"""
        with self._lock:
            if self.mode == LinkMode.PUBLIC:
                return self._send_public(payload)
            elif self.mode == LinkMode.DIRECT:
                return self._send_direct(payload)
            else:  # RADIO_MESH
                return self._send_radio_mesh(payload)

    def recv(self, timeout: float = 0.0) -> Optional[bytes]:
        """非阻塞接收（timeout=0）；>0 时阻塞至多 timeout 秒。"""
        deadline = time.time() + timeout
        while True:
            with self._lock:
                if self._rx_queue:
                    return self._rx_queue.pop(0)
            if timeout <= 0 or time.time() >= deadline:
                return None
            time.sleep(0.01)

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    # ---------- 各模式实现（骨架 + 直通公网的桥接占位）----------
    def _send_public(self, payload: bytes) -> bool:
        # 真实实现：走现有 Spider client.network 的公网 WebSocket / 中继
        self._rx_queue.append(b"[public-echo]" + payload[:0])  # 占位
        return True

    def _send_direct(self, payload: bytes) -> bool:
        # 蓝牙 / WiFi / 局域网 / 无线电 直连
        return True

    def _send_radio_mesh(self, payload: bytes) -> bool:
        """
        无线电网络（影子公网）：把公网那套逻辑原样映射到无线电上。
        关键：通过网关桥接，使【公网 ↔ 无线电网络用户互通】。

        节点发现（DHT）：
        自动模式下只需用户填写【一个频率】—— 在该频点由 C 库 libphy.so 自动完成
        信道探测、协商和调制解调（自动协商已下沉到 C 库，Python 端不再做参数选择），
        后由 bootstrap 从服务端 DHT 快照自动学习全网其它节点的频点，
        无需在 DHT 中预置调制方式。
        """
        # 首次发送前自动 bootstrap：用一个频点发现整个 mesh
        if not self._dht_bootstrapped:
            try:
                # 自动模式：先扫描锁定频点（业余段未命中则按策略降级/询问）
                if self.radio.mode == "auto":
                    seed_freq = self._auto_lock_frequency()
                else:
                    seed_freq = self.radio.frequency_hz
                seed = self._bootstrap(seed_freq, self._dht, gateway_mgr=self._gateway_mgr)
                self._dht_bootstrapped = True
                # 若自身或 DHT 中存在网关节点，经网关桥接到公网，实现互通
                if self._gateway_mgr.is_gateway() or any(
                    e.gateway_to_public for e in self._dht.gateways()
                ):
                    return self._send_public(payload)
            except Exception:
                pass
        return self._send_public(payload)  # 桥接到公网，实现互通

    # ---------- 便捷构造 ----------
    @classmethod
    def public(cls, url: str = "wss://spider.example.com") -> "Link":
        return cls(LinkMode.PUBLIC, public_url=url)

    @classmethod
    def direct(cls, radio: Optional[RadioConfig] = None) -> "Link":
        return cls(LinkMode.DIRECT, radio=radio)

    @classmethod
    def radio_mesh(cls, radio: Optional[RadioConfig] = None) -> "Link":
        return cls(LinkMode.RADIO_MESH, radio=radio)


# ============================================================
# 自测
# ============================================================

def selftest():
    # 1. 配置校验：合法
    cfg = RadioConfig(frequency_hz=14_100_000, duplex=1, modulation=0, mode="manual",
                      bandwidth_hz=12500)
    assert cfg.validate() == [], cfg.validate()
    print("[LINK] valid config OK")

    # 2. 输入检查：非法值
    bad = RadioConfig(frequency_hz=-1, duplex=2, modulation=9, bandwidth_hz=999999)
    errs = bad.validate()
    assert len(errs) == 4, errs
    print("[LINK] input validation OK (4 errors detected)")

    # 3. 越界仅警告不拦截
    warn = RadioConfig(frequency_hz=88_000_000)  # FM 广播段，非业余
    w = warn.warn_out_of_band()
    assert w is not None, "should warn out-of-band"
    print("[LINK] out-of-band warning (non-blocking):", w)

    # 4. C 库物理层验证（自动协商已下沉到 libphy.so）
    from client.network.radio.phy_wrapper import PhyContext, PHY_SDR_VIRTUAL
    ctx = PhyContext(PHY_SDR_VIRTUAL, 14_100_000)
    result = ctx.auto_negotiate()
    assert result["candidate_index"] >= 0
    assert result["effective_bitrate"] > 0
    # 虚拟 SDR 环回验证
    ctx.virtual_reset()
    test_data = b"\xAA\x55\x00\xFF"
    sent = ctx.auto_send(test_data)
    assert sent > 0
    received = ctx.auto_recv(max_len=1024, timeout_ms=50)
    assert received is not None and len(received) > 0
    ctx.close()
    print(f"[LINK] C 库物理层 OK: auto-negotiate={result['name']}, "
          f"loopback recv={len(received)}B")

    # 5. 链路收发
    link = Link.public()
    link.start()
    assert link.send(b"hello") is True
    link.stop()
    print("[LINK] Link.send/recv skeleton OK")

    # 6. JSON 往返
    cfg2 = RadioConfig.from_dict(cfg.to_dict())
    assert cfg2.to_dict() == cfg.to_dict()
    print("[LINK] config JSON round-trip OK")

    # 7. DHT bootstrap：无线电网络自动模式只需一个频点
    if link._dht is not None:
        mesh = Link(LinkMode.RADIO_MESH, radio=RadioConfig(frequency_hz=14_100_000))
        mesh.start()
        assert mesh.send(b"register-me") is True
        assert mesh._dht_bootstrapped is True
        assert len(mesh._dht) >= 4, "应学到种子 + 若干邻居节点"
        assert any(e.gateway_to_public for e in mesh._dht.gateways())
        print(f"[LINK] DHT bootstrap OK: 1 freq -> {len(mesh._dht)} nodes, "
              f"gateways={len(mesh._dht.gateways())}")
        mesh.stop()

    # ---------- 新增：自动模式分级扫描 + 降级 ----------
    HAM = ScanScope.HAM_ONLY.value
    FULL = ScanScope.FULL.value
    CUSTOM = ScanScope.CUSTOM.value

    # 8. scan_bands：三种 scope 均返回列表（无硬件时为空，不伪造）
    assert scan_bands(cfg, scope=HAM) == []
    assert scan_bands(cfg, scope=FULL) == []
    assert scan_bands(cfg, scope=CUSTOM) == []
    print("[LINK] scan_bands 三 scope 均返回 [] (无硬件，不伪造)")

    # 9. _iter_bands：ham_only 来自 HAMbandlist，full/custom 按策略
    ham_bands = _iter_bands(HAM)
    assert len(ham_bands) > 10, "业余段应从 HAMbandlist 加载"
    full_bands = _iter_bands(FULL)
    assert len(full_bands) == 1 and full_bands[0][0] == 0.0
    custom_cfg = RadioConfig(custom_bands=[(7.0e6, 7.3e6), (50e6, 54e6)])
    custom_bands = _iter_bands(CUSTOM, custom_cfg)
    assert custom_bands == [(7.0e6, 7.3e6), (50e6, 54e6)]
    print(f"[LINK] _iter_bands OK: ham={len(ham_bands)} full={full_bands} custom={custom_bands}")

    # 10. scan_with_fallback：ham_only 未命中 + stop -> 返回空 + user_stop
    stop_cfg = RadioConfig(frequency_hz=14_100_000, mode="auto",
                           search_policy="ham_only", fallback_action="stop")
    out = scan_with_fallback(stop_cfg)
    assert out["results"] == [] and out["decision"] == "user_stop"
    print("[LINK] fallback(stop) OK:", out["decision"])

    # 11. scan_with_fallback：fallback_action=auto, search_policy=full -> 仍空（无硬件）但流程走通
    auto_cfg = RadioConfig(frequency_hz=14_100_000, mode="auto",
                           search_policy="full", fallback_action="auto")
    out = scan_with_fallback(auto_cfg)
    assert out["decision"] in ("fallback_scope", "user_stop")
    assert out["fallback_triggered"] is True
    print(f"[LINK] fallback(auto/full) OK: decision={out['decision']} scope={out['scope_used']}")

    # 12. scan_with_fallback：ask + on_fallback 返回 'full'
    def ask_full(_info):
        return "full"
    ask_cfg = RadioConfig(frequency_hz=14_100_000, mode="auto",
                          search_policy="custom", fallback_action="ask",
                          custom_bands=[(88e6, 108e6)], on_fallback=ask_full)
    out = scan_with_fallback(ask_cfg)
    assert out["decision"] == "user_custom"
    print(f"[LINK] fallback(ask->full) OK: scope={out['scope_used']}")

    # 13. scan_with_fallback：ask + on_fallback 返回具体频点 -> 使用该频点
    def ask_freq(_info):
        return 145_600_000.0
    ask2 = RadioConfig(frequency_hz=14_100_000, mode="auto",
                       search_policy="custom", fallback_action="ask",
                       custom_bands=[(88e6, 108e6)], on_fallback=ask_freq)
    out = scan_with_fallback(ask2)
    assert out["results"] and out["results"][0]["frequency_hz"] == 145_600_000.0
    print(f"[LINK] fallback(ask->freq) OK: chosen={out['results'][0]['frequency_hz']/1e6} MHz")

    # 14. _auto_lock_frequency：手动模式始终返回用户频点
    manual = Link(LinkMode.RADIO_MESH,
                  radio=RadioConfig(frequency_hz=7_100_000, mode="manual"))
    assert manual._auto_lock_frequency() == 7_100_000
    print("[LINK] auto_lock(manual) -> user freq OK")

    # 15. _auto_lock_frequency：自动模式 + stop -> 业余段空则退回手填频点
    lock_link = Link(LinkMode.RADIO_MESH, radio=stop_cfg)
    assert lock_link._auto_lock_frequency() == 14_100_000
    assert lock_link._locked_frequency_hz == 14_100_000
    print("[LINK] auto_lock(stop) -> fallback to user freq OK")

    # 16. _send_radio_mesh 自动模式：bootstrap 使用锁定频点
    mesh2 = Link(LinkMode.RADIO_MESH, radio=stop_cfg)
    mesh2.start()
    assert mesh2.send(b"auto-bootstrap") is True
    assert mesh2._dht_bootstrapped is True
    assert mesh2._locked_frequency_hz == 14_100_000
    print(f"[LINK] radio_mesh auto bootstrap OK: locked={mesh2._locked_frequency_hz/1e6} MHz")
    mesh2.stop()

    # 17. Link 网关管理：默认 auto 模式 + 能力检测（双条件）
    gw_link = Link(LinkMode.RADIO_MESH, radio=RadioConfig(frequency_hz=14_100_000))
    assert gw_link.get_gateway_mode() == GATEWAY_AUTO
    gw_link.set_gateway_capabilities(has_public=False, has_sdr=False)
    assert gw_link.is_gateway() is False
    gw_link.set_gateway_capabilities(has_public=True, has_sdr=False)
    assert gw_link.is_gateway() is False  # 只有公网 -> 不是网关
    gw_link.set_gateway_capabilities(has_public=False, has_sdr=True)
    assert gw_link.is_gateway() is False  # 只有 SDR -> 不是网关
    gw_link.set_gateway_capabilities(has_public=True, has_sdr=True)
    assert gw_link.is_gateway() is True  # 两项都有 -> 自动成为网关
    status = gw_link.get_gateway_status()
    assert status["is_gateway"] is True and status["has_public"] and status["has_sdr"]
    print("[LINK] gateway auto-detection (both required) OK")

    # 18. Link 网关管理：手动覆盖（随时可配置）
    gw_link.set_gateway_mode(GATEWAY_FORCE_DISABLED)
    assert gw_link.is_gateway() is False  # 强制关闭
    gw_link.set_gateway_mode(GATEWAY_FORCE_ENABLED)
    assert gw_link.is_gateway() is True   # 强制开启
    gw_link.set_gateway_mode(GATEWAY_AUTO)
    assert gw_link.is_gateway() is True   # 恢复自动，双能力仍为网关
    gw_link.set_gateway_capabilities(has_public=False, has_sdr=True)
    assert gw_link.is_gateway() is False  # 失去一项 -> 自动切回
    print("[LINK] gateway manual override (auto/enabled/disabled) OK")

    # 19. Link 网关状态变更回调
    cb_events = []
    gw_link.on_gateway_change = lambda v: cb_events.append(v)
    gw_link.set_gateway_capabilities(has_public=True, has_sdr=True)
    assert gw_link.is_gateway() is True and cb_events == [True]
    gw_link.set_gateway_capabilities(has_public=False, has_sdr=False)
    assert gw_link.is_gateway() is False and cb_events == [True, False]
    print("[LINK] gateway status change callback OK")
    gw_link.stop()

    print("ALL LINK TESTS PASSED")


if __name__ == "__main__":
    selftest()
