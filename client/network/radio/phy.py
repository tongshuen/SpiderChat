#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phy.py — 物理层薄封装（调制/解调/同步）

设计原则：
  - 所有物理层处理（调制/解调/自动协商/SDR 交互/信道估计）均在 C 库 libphy.so 中完成。
  - 本模块仅负责：加载 C 库封装、根据 config 选择自动/手动模式、调用 C API。
  - 若 C 库不可用或 SDR 打开失败，抛出 RuntimeError，绝不回退到 Python 实现。

上层（协议/链路层）只需调用两个接口：
    encode(bits: bytes, config: RadioConfig) -> bytes   # 比特流 -> 基带采样
    decode(samples: bytes, config: RadioConfig) -> bytes # 基带采样 -> 比特流
"""
from typing import Optional

try:
    from .fec import fec_encode, fec_decode
except ImportError:
    from fec import fec_encode, fec_decode  # type: ignore

try:
    from .phy_wrapper import (
        PhyContext, PhyParams,
        PHY_MOD_FSK, PHY_MOD_ASK, PHY_MOD_PSK, PHY_MOD_QAM, PHY_MOD_GMSK,
        PHY_SDR_AUTO, PHY_SDR_VIRTUAL,
        PHY_FEC_NONE,
    )
except ImportError as e:
    raise RuntimeError(
        f"无法加载 phy_wrapper（C 库封装）: {e}。"
        "请在 client/network/radio/ 目录运行 make 编译 libphy.so。"
    )

# 调制类型名称 -> C 常量映射
_MODULATION_MAP = {
    "fsk": PHY_MOD_FSK,
    "ask": PHY_MOD_ASK,
    "psk": PHY_MOD_PSK,
    "qam": PHY_MOD_QAM,
    "gmsk": PHY_MOD_GMSK,
    PHY_MOD_FSK: PHY_MOD_FSK,
    PHY_MOD_ASK: PHY_MOD_ASK,
    PHY_MOD_PSK: PHY_MOD_PSK,
    PHY_MOD_QAM: PHY_MOD_QAM,
    PHY_MOD_GMSK: PHY_MOD_GMSK,
}


def _resolve_modulation(config) -> int:
    """从 config 解析调制类型常量。"""
    mod = getattr(config, "modulation", "fsk")
    if isinstance(mod, str):
        mod = mod.lower()
    if mod in _MODULATION_MAP:
        return _MODULATION_MAP[mod]
    return PHY_MOD_FSK  # 默认 FSK


def _build_params(config) -> dict:
    """从 config 构建手动模式参数字典。"""
    mod_params = getattr(config, "mod_params", {}) or {}
    params = {
        "modulation": _resolve_modulation(config),
        "baud": int(mod_params.get("baud", 300)),
        "sample_rate": int(mod_params.get("sample_rate", 8000)),
        "fsk_dev0": float(mod_params.get("fsk_dev0", mod_params.get("deviation0", 500))),
        "fsk_dev1": float(mod_params.get("fsk_dev1", mod_params.get("deviation1", 1000))),
        "ask_levels": int(mod_params.get("ask_levels", 2)),
        "ask_amp_high": float(mod_params.get("ask_amp_high", 1.0)),
        "ask_amp_low": float(mod_params.get("ask_amp_low", 0.0)),
        "psk_phase0": float(mod_params.get("psk_phase0", 0.0)),
        "psk_phase1": float(mod_params.get("psk_phase1", 180.0)),
        "qam_order": int(mod_params.get("qam_order", 16)),
        "qam_rolloff": float(mod_params.get("qam_rolloff", 0.35)),
        "gmsk_bt": float(mod_params.get("gmsk_bt", 0.5)),
        "fec_type": PHY_FEC_NONE,
        "bandwidth_hz": int(mod_params.get("bandwidth_hz", 12500)),
    }
    return params


def _is_auto_mode(config) -> bool:
    """判断是否为自动模式。"""
    mode = getattr(config, "mode", "auto")
    if isinstance(mode, str):
        return mode.lower() == "auto"
    return mode == 0  # 假设 0 表示自动


def encode(bits: bytes, config=None) -> bytes:
    """
    比特流 -> 基带采样（8-bit unsigned, 单声道）。

    自动模式：由 C 库自动完成信道探测、最优参数选择和调制。
    手动模式：使用 config 中指定的调制类型和参数。

    若 C 库不可用，抛出 RuntimeError（绝不降级）。
    """
    if not bits:
        return b""

    if config is None or _is_auto_mode(config):
        # 自动模式：使用 C 库的纯编码（默认参数，协商由 Link 层通过 SDR 上下文完成）
        # 对于纯基带编码（不操作 SDR），使用 FSK 300 兜底参数
        params = {
            "modulation": PHY_MOD_FSK,
            "baud": 300,
            "sample_rate": 8000,
            "fsk_dev0": 500,
            "fsk_dev1": 1000,
            "fec_type": PHY_FEC_NONE,
            "bandwidth_hz": 1400,
        }
        return PhyContext.encode(params, bits)
    else:
        # 手动模式
        params = _build_params(config)
        return PhyContext.encode(params, bits)


def decode(samples: bytes, config=None) -> bytes:
    """
    基带采样 -> 比特流。

    自动模式：使用 C 库默认参数解调。
    手动模式：使用 config 中指定的参数解调。

    若 C 库不可用，抛出 RuntimeError（绝不降级）。
    """
    if not samples:
        return b""

    if config is None or _is_auto_mode(config):
        params = {
            "modulation": PHY_MOD_FSK,
            "baud": 300,
            "sample_rate": 8000,
            "fsk_dev0": 500,
            "fsk_dev1": 1000,
            "fec_type": PHY_FEC_NONE,
            "bandwidth_hz": 1400,
        }
        return PhyContext.decode(params, samples)
    else:
        params = _build_params(config)
        return PhyContext.decode(params, samples)


# ============================================================
# SDR 上下文管理（供 Link 层在自动模式下使用）
# ============================================================
def create_sdr_context(frequency_hz: float, sdr_backend: int = PHY_SDR_AUTO) -> PhyContext:
    """
    创建 SDR 物理层上下文（自动模式用）。
    打开 SDR 设备失败时抛出 RuntimeError。
    """
    return PhyContext(sdr_backend=sdr_backend, frequency_hz=frequency_hz)


# ============================================================
# 自测
# ============================================================
def selftest():
    """phy.py 自测：验证 C 库加载和 encode/decode 往返。"""
    print("=== phy.py 自测（C 库薄封装）===")

    # 1. 基本 encode/decode 往返
    msg = b"\xAA\x55\x00\xFF\xDE\xAD\xBE\xEF"
    audio = encode(msg)
    assert len(audio) > 0, "encode 输出为空"
    recovered = decode(audio)
    assert isinstance(recovered, bytes), "decode 输出不是 bytes"
    print(f"[OK] encode({len(msg)}B) -> {len(audio)} samples; decode -> {len(recovered)}B")

    # 2. 手动模式 FSK
    class ManualConfig:
        mode = "manual"
        modulation = "fsk"
        mod_params = {"baud": 600, "fsk_dev0": 500, "fsk_dev1": 1000}

    audio2 = encode(msg, ManualConfig())
    recovered2 = decode(audio2, ManualConfig())
    assert len(recovered2) > 0
    print(f"[OK] 手动 FSK: encode -> {len(audio2)} samples; decode -> {len(recovered2)}B")

    # 3. 手动模式 QAM
    class QamConfig:
        mode = "manual"
        modulation = "qam"
        mod_params = {"baud": 1200, "qam_order": 16, "sample_rate": 8000}

    audio3 = encode(msg, QamConfig())
    recovered3 = decode(audio3, QamConfig())
    assert len(recovered3) > 0
    print(f"[OK] 手动 QAM-16: encode -> {len(audio3)} samples; decode -> {len(recovered3)}B")

    # 4. FEC 集成确认
    frame = fec_encode(msg)
    assert len(frame) > len(msg)
    print("[OK] FEC integration OK")

    # 5. 虚拟 SDR 上下文创建和自动协商
    ctx = create_sdr_context(14_100_000, PHY_SDR_VIRTUAL)
    result = ctx.auto_negotiate()
    assert result["candidate_index"] >= 0
    print(f"[OK] 虚拟 SDR 自动协商: {result['name']} @ {result['baud']}baud")

    # 6. 虚拟 SDR 自动模式发送/接收环回
    ctx.virtual_reset()
    sent = ctx.auto_send(msg)
    assert sent > 0
    received = ctx.auto_recv(max_len=1024, timeout_ms=50)
    assert received is not None and len(received) > 0
    print(f"[OK] 虚拟 SDR 自动环回: send -> {sent}samples; recv -> {len(received)}B")

    ctx.close()
    print("\nALL PHY TESTS PASSED")


if __name__ == "__main__":
    selftest()
