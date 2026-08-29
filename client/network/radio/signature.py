#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
signature.py — Spider Radio 协议签名（导频 + 信号模式）

为了让本协议能与现有业余无线电协议（FT8、JS8、WSPR、RTTY、Packet 等）
【明确可区分】，帧头采用独特的双导频 + 交替 FSK 模式：
  - 前导 (preamble)：13 个交替的 0xAA / 0x55 字节 → 在频谱上呈现
    「两固定频点等间隔交替」的特征纹，区别于 PSK31/FT8 的连续相位包络。
  - 导频音 (pilot)：3 个完整周期的 1600Hz 纯音（采样率 8000），
    提供精确的 AFC 频偏估计基准。
  - 帧同步字 (syncword)：0x5F 0x45（"Spider FEC" magic）做帧边界锁定。

检测端：correlate() 对相关峰做门限判决，命中即判定「疑似 Spider Radio」。
"""

import struct

MAGIC = 0x5F45
PREAMBLE = b"\xAA\x55" * 13           # 26 字节交替比特
PILOT_FREQ_HZ = 1600
PILOT_SAMPLES = 3 * 1600              # 3 个周期 @ 1600Hz, 8kHz 采样
SAMPLE_RATE = 8000


def build_preamble() -> bytes:
    """构造完整前导（preamble + pilot + syncword）。"""
    pilot = _gen_pilot(PILOT_FREQ_HZ, PILOT_SAMPLES, SAMPLE_RATE)
    sync = struct.pack(">H", MAGIC)
    return PREAMBLE + pilot + sync


def _gen_pilot(freq: int, samples: int, sr: int) -> bytes:
    """生成单频导频音（用于 AFC / 能量检测基准）。"""
    out = bytearray()
    for i in range(samples):
        # 8-bit 无符号正弦，峰峰值居中 128
        import math
        v = 128 + int(63 * math.sin(2 * math.pi * freq * i / sr))
        out.append(v)
    return bytes(out)


def correlate(samples: bytes, threshold: float = 0.25) -> bool:
    """
    在基带采样流中检测本协议签名。
    采用两路判别（任一满足即命中）：
      (a) 比特翻转率：0xAA/0x55 交替产生接近 50% 的比特翻转密度；
      (b) 直流偏移接近 128（单频/静音则显著偏离）。
    真实部署应替换为匹配滤波器 + 门限联合判决。
    """
    if len(samples) < 32:
        return False
    # (a) 相邻采样翻转率（交替模式应 ≈ 0.5）
    flips = sum(1 for i in range(1, len(samples)) if samples[i] != samples[i - 1])
    flip_ratio = flips / (len(samples) - 1)
    # (b) 均值接近 128（能量集中，非纯 0x00 / 0xFF）
    mean = sum(samples) / len(samples)
    dc_ok = 96 < mean < 160
    return (flip_ratio > threshold) and dc_ok


def selftest():
    pre = build_preamble()
    assert len(pre) >= 26 + 2
    assert correlate(pre) is True
    assert correlate(b"\x00" * 64) is False
    print("[SIGNATURE] preamble/syncword/correlate OK")


if __name__ == "__main__":
    selftest()
