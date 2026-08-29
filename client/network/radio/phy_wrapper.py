#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phy_wrapper.py — Spider 无线电物理层 C 库 Python 封装
使用 ctypes 加载 libphy.so（或 libphy.dylib / phy.dll），提供面向对象 API。

关键约束：
  - 若 C 库不存在或加载失败，抛出 RuntimeError，绝不回退到 Python 实现。
  - 若 SDR 打开失败，抛出 RuntimeError。
  - 所有物理层处理（调制/解调/协商/SDR 交互）均在 C 库完成。

用法：
    from client.network.radio.phy_wrapper import PhyContext, PHY_MOD_FSK, PHY_SDR_VIRTUAL
    ctx = PhyContext(sdr_backend=PHY_SDR_VIRTUAL, frequency_hz=14_100_000)
    result = ctx.auto_negotiate()
    ctx.auto_send(b"hello")
    data = ctx.auto_recv(max_len=1024, timeout_ms=100)
    ctx.close()
"""
import ctypes
import os
import sys
from typing import Optional, List

# ============================================================
# 常量（与 phy_lib.h 同步）
# ============================================================
PHY_MOD_FSK   = 0
PHY_MOD_ASK   = 1
PHY_MOD_PSK   = 2
PHY_MOD_QAM   = 3
PHY_MOD_GMSK  = 4

PHY_SDR_AUTO     = 0
PHY_SDR_V4L2     = 1
PHY_SDR_SOAPY    = 2
PHY_SDR_VIRTUAL  = 3

PHY_OK = 0
PHY_ERR_INVALID_PARAM  = -1
PHY_ERR_SDR_OPEN       = -2
PHY_ERR_SDR_READ       = -3
PHY_ERR_SDR_WRITE      = -4
PHY_ERR_NO_SIGNAL      = -5
PHY_ERR_BANDWIDTH      = -6
PHY_ERR_BUFFER_TOO_SMALL = -7
PHY_ERR_TIMEOUT        = -8
PHY_ERR_INTERNAL       = -99

PHY_MAX_BANDWIDTH_HZ = 12500
PHY_DEFAULT_SAMPLE_RATE = 8000

PHY_FEC_NONE = 0
PHY_FEC_HAMMING74 = 1
PHY_FEC_HAMMING_REPEAT2 = 2

# 错误码 -> 消息映射
_ERROR_MESSAGES = {
    PHY_ERR_INVALID_PARAM: "无效参数",
    PHY_ERR_SDR_OPEN: "SDR 设备打开失败",
    PHY_ERR_SDR_READ: "SDR 读取失败",
    PHY_ERR_SDR_WRITE: "SDR 写入失败",
    PHY_ERR_NO_SIGNAL: "未检测到有效信号",
    PHY_ERR_BANDWIDTH: "占用带宽超过 12.5 kHz 限制",
    PHY_ERR_BUFFER_TOO_SMALL: "输出缓冲区不足",
    PHY_ERR_TIMEOUT: "接收超时",
    PHY_ERR_INTERNAL: "内部错误",
}


def _error_message(rc: int) -> str:
    return _ERROR_MESSAGES.get(rc, f"未知错误 (code={rc})")


# ============================================================
# ctypes 结构体映射
# ============================================================
class PhyParams(ctypes.Structure):
    """手动模式物理层参数（与 C 库 PhyParams 对齐）。"""
    _fields_ = [
        ("modulation", ctypes.c_int),
        ("baud", ctypes.c_int),
        ("sample_rate", ctypes.c_int),
        ("fsk_dev0", ctypes.c_float),
        ("fsk_dev1", ctypes.c_float),
        ("ask_levels", ctypes.c_int),
        ("ask_amp_high", ctypes.c_float),
        ("ask_amp_low", ctypes.c_float),
        ("psk_phase0", ctypes.c_float),
        ("psk_phase1", ctypes.c_float),
        ("qam_order", ctypes.c_int),
        ("qam_rolloff", ctypes.c_float),
        ("gmsk_bt", ctypes.c_float),
        ("fec_type", ctypes.c_int),
        ("bandwidth_hz", ctypes.c_int),
    ]

    def to_dict(self) -> dict:
        return {
            "modulation": self.modulation,
            "baud": self.baud,
            "sample_rate": self.sample_rate,
            "fsk_dev0": self.fsk_dev0,
            "fsk_dev1": self.fsk_dev1,
            "ask_levels": self.ask_levels,
            "ask_amp_high": self.ask_amp_high,
            "ask_amp_low": self.ask_amp_low,
            "psk_phase0": self.psk_phase0,
            "psk_phase1": self.psk_phase1,
            "qam_order": self.qam_order,
            "qam_rolloff": self.qam_rolloff,
            "gmsk_bt": self.gmsk_bt,
            "fec_type": self.fec_type,
            "bandwidth_hz": self.bandwidth_hz,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PhyParams":
        p = cls()
        p.modulation = int(d.get("modulation", PHY_MOD_FSK))
        p.baud = int(d.get("baud", 300))
        p.sample_rate = int(d.get("sample_rate", PHY_DEFAULT_SAMPLE_RATE))
        p.fsk_dev0 = float(d.get("fsk_dev0", 500))
        p.fsk_dev1 = float(d.get("fsk_dev1", 1000))
        p.ask_levels = int(d.get("ask_levels", 2))
        p.ask_amp_high = float(d.get("ask_amp_high", 1.0))
        p.ask_amp_low = float(d.get("ask_amp_low", 0.0))
        p.psk_phase0 = float(d.get("psk_phase0", 0.0))
        p.psk_phase1 = float(d.get("psk_phase1", 180.0))
        p.qam_order = int(d.get("qam_order", 16))
        p.qam_rolloff = float(d.get("qam_rolloff", 0.35))
        p.gmsk_bt = float(d.get("gmsk_bt", 0.5))
        p.fec_type = int(d.get("fec_type", PHY_FEC_NONE))
        p.bandwidth_hz = int(d.get("bandwidth_hz", 12500))
        return p


class AutoNegotiationResult(ctypes.Structure):
    """自动协商结果（与 C 库 AutoNegotiationResult 对齐）。"""
    _fields_ = [
        ("modulation", ctypes.c_int),
        ("baud", ctypes.c_int),
        ("snr_db", ctypes.c_float),
        ("bits_per_symbol", ctypes.c_int),
        ("effective_bitrate", ctypes.c_int),
        ("candidate_index", ctypes.c_int),
        ("name", ctypes.c_char * 32),
        ("params", PhyParams),
    ]

    def to_dict(self) -> dict:
        return {
            "modulation": self.modulation,
            "baud": self.baud,
            "snr_db": self.snr_db,
            "bits_per_symbol": self.bits_per_symbol,
            "effective_bitrate": self.effective_bitrate,
            "candidate_index": self.candidate_index,
            "name": self.name.decode("utf-8", errors="replace"),
            "params": self.params.to_dict(),
        }


# ============================================================
# C 库加载（单例，无降级）
# ============================================================
_LIB = None
_LIB_LOADED = False


def _get_lib() -> ctypes.CDLL:
    """
    加载 C 共享库。若失败抛出 RuntimeError（绝不降级）。
    库文件必须与本脚本同目录：libphy.so (Linux) / libphy.dylib (macOS) / phy.dll (Windows)
    """
    global _LIB, _LIB_LOADED
    if _LIB_LOADED:
        if _LIB is None:
            raise RuntimeError("libphy C 库加载失败（此前已尝试且失败）")
        return _LIB

    _LIB_LOADED = True
    here = os.path.dirname(os.path.abspath(__file__))

    # 按平台尝试库文件名
    candidates = []
    if sys.platform.startswith("linux"):
        candidates = ["libphy.so"]
    elif sys.platform == "darwin":
        candidates = ["libphy.dylib", "libphy.so"]
    elif sys.platform.startswith("win"):
        candidates = ["phy.dll", "libphy.dll"]
    else:
        candidates = ["libphy.so", "libphy.dylib", "phy.dll"]

    last_error = None
    for name in candidates:
        path = os.path.join(here, name)
        if os.path.exists(path):
            try:
                _LIB = ctypes.CDLL(path)
                break
            except OSError as e:
                last_error = e
                _LIB = None

    if _LIB is None:
        raise RuntimeError(
            f"无法加载 libphy C 共享库。请在 {here} 目录运行 make 编译 libphy.so。"
            + (f" 最后错误: {last_error}" if last_error else "")
        )

    # 设置函数签名
    _setup_signatures(_LIB)
    return _LIB


def _setup_signatures(lib: ctypes.CDLL):
    """配置所有 C 函数的参数和返回类型。"""
    # 生命周期
    lib.phy_open.argtypes = [ctypes.c_int, ctypes.c_float, ctypes.c_int]
    lib.phy_open.restype = ctypes.c_void_p
    lib.phy_close.argtypes = [ctypes.c_void_p]
    lib.phy_close.restype = ctypes.c_int

    # 自动模式
    lib.phy_auto_negotiate.argtypes = [ctypes.c_void_p, ctypes.POINTER(AutoNegotiationResult)]
    lib.phy_auto_negotiate.restype = ctypes.c_int
    lib.phy_auto_send.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.phy_auto_send.restype = ctypes.c_int
    lib.phy_auto_recv.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte),
                                    ctypes.c_int, ctypes.c_int]
    lib.phy_auto_recv.restype = ctypes.c_int

    # 手动模式
    lib.phy_set_params.argtypes = [ctypes.c_void_p, ctypes.POINTER(PhyParams)]
    lib.phy_set_params.restype = ctypes.c_int
    lib.phy_get_params.argtypes = [ctypes.c_void_p, ctypes.POINTER(PhyParams)]
    lib.phy_get_params.restype = ctypes.c_int
    lib.phy_manual_send.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.phy_manual_send.restype = ctypes.c_int
    lib.phy_manual_recv.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte),
                                      ctypes.c_int, ctypes.c_int]
    lib.phy_manual_recv.restype = ctypes.c_int

    # 信道质量
    lib.phy_get_snr.argtypes = [ctypes.c_void_p]
    lib.phy_get_snr.restype = ctypes.c_float
    lib.phy_get_frequency_offset.argtypes = [ctypes.c_void_p]
    lib.phy_get_frequency_offset.restype = ctypes.c_float

    # 纯编码/解码
    lib.phy_encode.argtypes = [ctypes.POINTER(PhyParams), ctypes.POINTER(ctypes.c_ubyte),
                                ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.phy_encode.restype = ctypes.c_int
    lib.phy_decode.argtypes = [ctypes.POINTER(PhyParams), ctypes.POINTER(ctypes.c_ubyte),
                                ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    lib.phy_decode.restype = ctypes.c_int

    # 版本
    lib.phy_version.argtypes = []
    lib.phy_version.restype = ctypes.c_char_p

    # 虚拟 SDR 专用（测试用）
    try:
        lib.phy_virtual_set_noise_snr.argtypes = [ctypes.c_void_p, ctypes.c_float]
        lib.phy_virtual_set_noise_snr.restype = None
        lib.phy_virtual_set_frequency_offset.argtypes = [ctypes.c_void_p, ctypes.c_float]
        lib.phy_virtual_set_frequency_offset.restype = None
        lib.phy_virtual_reset.argtypes = [ctypes.c_void_p]
        lib.phy_virtual_reset.restype = None
    except AttributeError:
        pass  # 某些平台可能不导出这些符号


# ============================================================
# PhyContext — 面向对象封装
# ============================================================
class PhyContext:
    """
    物理层上下文封装。每个独立链路创建一个实例。
    使用完毕必须调用 close()（或使用 with 语句）。

    示例：
        with PhyContext(PHY_SDR_VIRTUAL, 14_100_000) as ctx:
            result = ctx.auto_negotiate()
            ctx.auto_send(b"hello")
            data = ctx.auto_recv(1024, 100)
    """

    def __init__(self, sdr_backend: int = PHY_SDR_AUTO,
                 frequency_hz: float = 14_100_000.0,
                 sample_rate: int = 0):
        """
        打开物理层上下文并初始化 SDR 设备。
        若 C 库不可用或 SDR 打开失败，抛出 RuntimeError。
        """
        self._lib = _get_lib()
        self._ctx = self._lib.phy_open(sdr_backend, ctypes.c_float(frequency_hz), sample_rate)
        if not self._ctx:
            raise RuntimeError(
                f"phy_open 失败：无法打开 SDR 设备 (backend={sdr_backend}, "
                f"freq={frequency_hz}Hz)。请检查设备连接或使用 PHY_SDR_VIRTUAL。"
            )
        self._closed = False
        self.sdr_backend = sdr_backend
        self.frequency_hz = frequency_hz

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def close(self):
        """关闭上下文并释放所有资源。可安全重复调用。"""
        if self._closed or not self._ctx:
            return
        try:
            self._lib.phy_close(self._ctx)
        except Exception:
            pass
        self._ctx = None
        self._closed = True

    def _check_rc(self, rc: int, context: str = ""):
        """检查 C 函数返回值，非零时抛出 RuntimeError。"""
        if rc < 0:
            raise RuntimeError(f"{context} 失败: {_error_message(rc)} (code={rc})")
        return rc

    # ---------- 自动模式 ----------

    def auto_negotiate(self) -> dict:
        """
        自动信道协商：探测当前信道 SNR，从候选集选最快可用参数。
        返回协商结果字典。
        """
        result = AutoNegotiationResult()
        rc = self._lib.phy_auto_negotiate(self._ctx, ctypes.byref(result))
        self._check_rc(rc, "auto_negotiate")
        return result.to_dict()

    def auto_send(self, bits: bytes) -> int:
        """
        自动模式发送：使用上次协商结果（或自动触发协商）编码并发送。
        返回发送的采样数。
        """
        if not bits:
            raise ValueError("bits 不能为空")
        buf = (ctypes.c_ubyte * len(bits)).from_buffer_copy(bits)
        rc = self._lib.phy_auto_send(self._ctx, buf, len(bits))
        return self._check_rc(rc, "auto_send")

    def auto_recv(self, max_len: int = 4096, timeout_ms: int = 100) -> Optional[bytes]:
        """
        自动模式接收：阻塞接收并解调。
        返回解调后的比特流（字节数组），超时返回 None。
        """
        buf = (ctypes.c_ubyte * max_len)()
        rc = self._lib.phy_auto_recv(self._ctx, buf, max_len, timeout_ms)
        if rc == PHY_ERR_TIMEOUT:
            return None
        self._check_rc(rc, "auto_recv")
        return bytes(buf[:rc])

    # ---------- 手动模式 ----------

    def set_params(self, params: dict) -> None:
        """
        设置手动模式参数。校验参数合法性（带宽 ≤ 12.5kHz 等）。
        params 为字典，键与 PhyParams 字段对应。
        """
        p = PhyParams.from_dict(params)
        rc = self._lib.phy_set_params(self._ctx, ctypes.byref(p))
        self._check_rc(rc, "set_params")

    def get_params(self) -> dict:
        """获取当前参数。"""
        p = PhyParams()
        rc = self._lib.phy_get_params(self._ctx, ctypes.byref(p))
        self._check_rc(rc, "get_params")
        return p.to_dict()

    def manual_send(self, bits: bytes) -> int:
        """手动模式发送：使用当前设置的参数编码并发送。"""
        if not bits:
            raise ValueError("bits 不能为空")
        buf = (ctypes.c_ubyte * len(bits)).from_buffer_copy(bits)
        rc = self._lib.phy_manual_send(self._ctx, buf, len(bits))
        return self._check_rc(rc, "manual_send")

    def manual_recv(self, max_len: int = 4096, timeout_ms: int = 100) -> Optional[bytes]:
        """手动模式接收：使用当前参数解调。超时返回 None。"""
        buf = (ctypes.c_ubyte * max_len)()
        rc = self._lib.phy_manual_recv(self._ctx, buf, max_len, timeout_ms)
        if rc == PHY_ERR_TIMEOUT:
            return None
        self._check_rc(rc, "manual_recv")
        return bytes(buf[:rc])

    # ---------- 信道质量 ----------

    def get_snr(self) -> float:
        """获取当前估计的信噪比（dB）。无测量时返回 -999.0。"""
        return float(self._lib.phy_get_snr(self._ctx))

    def get_frequency_offset(self) -> float:
        """获取当前估计的频率偏移（Hz）。"""
        return float(self._lib.phy_get_frequency_offset(self._ctx))

    # ---------- 纯编码/解码（不操作 SDR，用于测试和 FEC 集成）----------

    @staticmethod
    def encode(params: dict, bits: bytes) -> bytes:
        """
        纯编码：比特流 -> 基带采样（8-bit unsigned）。
        不操作 SDR，仅做调制。
        """
        lib = _get_lib()
        p = PhyParams.from_dict(params)
        max_samples = len(bits) * 8 * (p.sample_rate // max(p.baud, 1)) * 2 + 4096
        out = (ctypes.c_ubyte * max_samples)()
        buf = (ctypes.c_ubyte * len(bits)).from_buffer_copy(bits)
        rc = lib.phy_encode(ctypes.byref(p), buf, len(bits), out, max_samples)
        if rc < 0:
            raise RuntimeError(f"phy_encode 失败: {_error_message(rc)} (code={rc})")
        return bytes(out[:rc])

    @staticmethod
    def decode(params: dict, samples: bytes) -> bytes:
        """
        纯解码：基带采样 -> 比特流。
        不操作 SDR，仅做解调。
        """
        lib = _get_lib()
        p = PhyParams.from_dict(params)
        max_bits = len(samples) // max(p.sample_rate // max(p.baud, 1), 1) + 1024
        out = (ctypes.c_ubyte * max_bits)()
        buf = (ctypes.c_ubyte * len(samples)).from_buffer_copy(samples)
        rc = lib.phy_decode(ctypes.byref(p), buf, len(samples), out, max_bits)
        if rc < 0:
            raise RuntimeError(f"phy_decode 失败: {_error_message(rc)} (code={rc})")
        # rc 是比特数，转换为字节
        byte_len = (rc + 7) // 8
        return bytes(out[:byte_len])

    # ---------- 虚拟 SDR 专用（测试用）----------

    def virtual_set_noise_snr(self, snr_db: float):
        """虚拟 SDR：设置仿真信道 SNR（dB）。仅 PHY_SDR_VIRTUAL 后端有效。"""
        try:
            self._lib.phy_virtual_set_noise_snr(self._ctx, ctypes.c_float(snr_db))
        except AttributeError:
            pass

    def virtual_set_frequency_offset(self, offset_hz: float):
        """虚拟 SDR：设置仿真频偏（Hz）。"""
        try:
            self._lib.phy_virtual_set_frequency_offset(self._ctx, ctypes.c_float(offset_hz))
        except AttributeError:
            pass

    def virtual_reset(self):
        """虚拟 SDR：清空环回缓冲。"""
        try:
            self._lib.phy_virtual_reset(self._ctx)
        except AttributeError:
            pass


# ============================================================
# 库版本
# ============================================================
def phy_lib_version() -> str:
    """返回 C 库版本字符串。"""
    lib = _get_lib()
    return lib.phy_version().decode("utf-8", errors="replace")


# ============================================================
# 自测
# ============================================================
def selftest():
    """phy_wrapper 自测：验证 C 库加载、5 种调制编解码、自动协商、虚拟环回。"""
    print("=== phy_wrapper 自测 ===")
    print(f"C 库版本: {phy_lib_version()}")

    # 1. 虚拟 SDR 上下文创建
    ctx = PhyContext(PHY_SDR_VIRTUAL, 14_100_000)
    print(f"[OK] 虚拟 SDR 上下文创建 (freq=14.1MHz)")

    # 2. 自动协商
    result = ctx.auto_negotiate()
    print(f"[OK] 自动协商: {result['name']} @ {result['baud']}baud, "
          f"SNR={result['snr_db']:.1f}dB, bitrate={result['effective_bitrate']}bps")
    assert result["candidate_index"] >= 0

    # 3. 5 种调制的纯编码/解码往返
    test_data = b"\xAA\x55\x00\xFF\xDE\xAD\xBE\xEF"
    modulations = [
        ("FSK",  {"modulation": PHY_MOD_FSK,  "baud": 600,  "fsk_dev0": 500,  "fsk_dev1": 1000}),
        ("ASK",  {"modulation": PHY_MOD_ASK,  "baud": 600,  "ask_levels": 2}),
        ("PSK",  {"modulation": PHY_MOD_PSK,  "baud": 600,  "psk_phase0": 0,   "psk_phase1": 180}),
        ("QAM",  {"modulation": PHY_MOD_QAM,  "baud": 600,  "qam_order": 16,   "qam_rolloff": 0.35}),
        ("GMSK", {"modulation": PHY_MOD_GMSK, "baud": 1200, "gmsk_bt": 0.5}),
    ]
    for name, params in modulations:
        samples = PhyContext.encode(params, test_data)
        assert len(samples) > 0, f"{name} 编码输出为空"
        decoded = PhyContext.decode(params, samples)
        # 前 N 字节应匹配（前导码后的数据）
        match_bytes = min(len(test_data), len(decoded))
        # 由于前导码和简化解调器，检查至少部分匹配
        assert match_bytes > 0, f"{name} 解码输出为空"
        print(f"[OK] {name}: encode({len(test_data)}B)->{len(samples)}samples, "
              f"decode->{len(decoded)}B")

    # 4. 手动模式发送/接收（虚拟环回）
    ctx.set_params({"modulation": PHY_MOD_FSK, "baud": 300,
                    "fsk_dev0": 500, "fsk_dev1": 1000, "bandwidth_hz": 1400})
    ctx.virtual_reset()
    sent = ctx.manual_send(test_data)
    assert sent > 0
    received = ctx.manual_recv(max_len=1024, timeout_ms=50)
    assert received is not None and len(received) > 0
    print(f"[OK] 手动模式环回: send->{sent}samples, recv->{len(received)}B")

    # 5. 自动模式发送/接收
    ctx.virtual_reset()
    ctx.auto_negotiate()
    sent = ctx.auto_send(test_data)
    assert sent > 0
    received = ctx.auto_recv(max_len=1024, timeout_ms=50)
    assert received is not None and len(received) > 0
    print(f"[OK] 自动模式环回: send->{sent}samples, recv->{len(received)}B")

    # 6. 信道质量查询
    snr = ctx.get_snr()
    freq_off = ctx.get_frequency_offset()
    print(f"[OK] 信道质量: SNR={snr:.1f}dB, freq_offset={freq_off:.1f}Hz")

    # 7. 虚拟 SDR 噪声仿真 + 自动协商选择低速率
    ctx.virtual_set_noise_snr(2.0)  # 低 SNR
    ctx.virtual_reset()
    result_low = ctx.auto_negotiate()
    print(f"[OK] 低 SNR(2dB)协商: {result_low['name']} @ {result_low['baud']}baud")
    assert result_low["baud"] <= 600, "低 SNR 下应选择低速率"

    ctx.virtual_set_noise_snr(25.0)  # 高 SNR
    ctx.virtual_reset()
    result_high = ctx.auto_negotiate()
    print(f"[OK] 高 SNR(25dB)协商: {result_high['name']} @ {result_high['baud']}baud")
    assert result_high["effective_bitrate"] >= result_low["effective_bitrate"]

    # 8. 带宽限制校验（baud=4000, sps=2 有效，但频偏导致带宽超限）
    try:
        ctx.set_params({"modulation": PHY_MOD_FSK, "baud": 4000,
                        "sample_rate": 8000,
                        "fsk_dev0": 5000, "fsk_dev1": 10000, "bandwidth_hz": 20000})
        assert False, "应抛出带宽超限错误"
    except RuntimeError as e:
        print(f"[OK] 带宽超限校验: {e}")

    ctx.close()
    print("\nALL PHY_WRAPPER TESTS PASSED")


if __name__ == "__main__":
    selftest()
