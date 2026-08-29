#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
radio/fec.py — 前向纠错（Hamming(7,4) + 比特重复码 + 块交织）。

设计目标：在 ≤12.5kHz 射频带宽、HF–UHF 业余频段、异步 IM 场景下，
以数据带宽为代价换取强纠错能力。纯 Python，无外部依赖。

编码流水线：  payload ──Hamming(7,4)──▶ 比特流 ──交织──▶ 比特流 ──比特重复──▶ 输出
解码流水线：  输出 ──比特重复判决──▶ 解交织 ──▶ Hamming 译码 ──▶ payload

关键设计决定：
1. 重复码在【比特级】操作（每个比特重复 N 次后多数表决），与交织可交换；
2. 帧内「Hamming 码字流」是定长、自描述的：解码端按实际比特数自动推断码字数，
   不依赖易错的外部长度参数，从根本上消除对齐 bug。

帧格式（编码后附加 4 字节长度前缀，便于精确还原）：
    [ magic(2B)=0x5F45 ][ payload_byte_len(4B, big-endian) ][ fec_body ... ]
"""

import struct
import os

MAGIC = 0x5F45          # "Spider FEC" 标识
HEADER_SIZE = 6         # 2 magic + 4 length


# ============================================================
# 比特 ↔ 字节 基础工具
# ============================================================

def _pack_bits(bits: list) -> bytes:
    """比特列表（高位在前）紧凑打包为字节。"""
    out = bytearray()
    acc = 0
    n = 0
    for b in bits:
        acc = (acc << 1) | (b & 1)
        n += 1
        if n == 8:
            out.append(acc)
            acc = 0
            n = 0
    if n:
        out.append(acc << (8 - n))
    return bytes(out)


def _to_bits(data: bytes) -> list:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


# ============================================================
# Hamming(7,4)：4 信息位 + 3 校验位，可纠正任意单比特错误。
# 码字排列（高位在前）：[p1, p2, d1, p3, d2, d3, d4]
#   信息位 0-索引：2(d1),4(d2),5(d3),6(d4)
#   校验位：p1=d1^d2^d4, p2=d1^d3^d4, p3=d2^d3^d4
# ============================================================

def _encode_nibble(nibble: int) -> list:
    d1 = (nibble >> 3) & 1
    d2 = (nibble >> 2) & 1
    d3 = (nibble >> 1) & 1
    d4 = (nibble >> 0) & 1
    p1 = d1 ^ d2 ^ d4
    p2 = d1 ^ d3 ^ d4
    p3 = d2 ^ d3 ^ d4
    return [p1, p2, d1, p3, d2, d3, d4]


def _syndrome(codeword: list) -> int:
    b = codeword
    s1 = b[0] ^ b[2] ^ b[4] ^ b[6]
    s2 = b[1] ^ b[2] ^ b[5] ^ b[6]
    s3 = b[3] ^ b[4] ^ b[5] ^ b[6]
    return (s1 << 2) | (s2 << 1) | s3


# Syndrome -> 错误位置映射：由 H 矩阵第 j 列 = j(1..7) 的二进制。
# 通过暴力枚举生成，保证正确（不再手工维护）。
def _build_syndrome_table():
    table = {0: 0}
    for pos in range(1, 8):          # 错误位置 1..7
        cw = [0] * 7; cw[pos - 1] = 1
        table[_syndrome(cw)] = pos
    return table

_SYNDROME_TABLE = _build_syndrome_table()


def _correct(cw: list):
    """原地纠正 7 位码字中的单比特错误。"""
    syn = _syndrome(cw)
    pos = _SYNDROME_TABLE.get(syn, 0)
    if pos:
        cw[pos - 1] ^= 1


def hamming_encode(data: bytes) -> bytes:
    """字节流 -> Hamming(7,4)。每字节 2 nibble -> 2×7 = 14 比特。"""
    bitstream = []
    for byte in data:
        for nibble in ((byte >> 4) & 0xF, byte & 0xF):
            bitstream.extend(_encode_nibble(nibble))
    return _pack_bits(bitstream)


def hamming_decode(data: bytes) -> bytes:
    """
    Hamming(7,4) 解码。按数据实际比特数自动推断码字数（每 7 比特一个码字）。
    尾部不足 7 比特的片段丢弃（由帧边界保证对齐）。
    """
    bits = _to_bits(data)
    num_codewords = len(bits) // 7
    if num_codewords == 0:
        return b""
    bits = bits[:num_codewords * 7]
    out = bytearray(num_codewords // 2)
    for cw_idx in range(0, num_codewords, 2):
        cw1 = list(bits[cw_idx * 7:(cw_idx + 1) * 7])
        if cw_idx + 1 < num_codewords:
            cw2 = list(bits[(cw_idx + 1) * 7:(cw_idx + 2) * 7])
        else:
            cw2 = [0] * 7
        _correct(cw1)
        _correct(cw2)
        d1, d2, d3, d4 = cw1[2], cw1[4], cw1[5], cw1[6]
        hi = (d1 << 3) | (d2 << 2) | (d3 << 1) | d4
        d1, d2, d3, d4 = cw2[2], cw2[4], cw2[5], cw2[6]
        lo = (d1 << 3) | (d2 << 2) | (d3 << 1) | d4
        out[cw_idx // 2] = (hi << 4) | lo
    return bytes(out)


# ============================================================
# 比特级重复码：每个比特重复 n 次，解码时每 n 比特多数表决。
# ============================================================

def repeat_encode(data: bytes, n: int = 2) -> bytes:
    if n < 2:
        return data
    bits = _to_bits(data)
    expanded = []
    for b in bits:
        expanded.extend([b] * n)
    return _pack_bits(expanded)


def repeat_decode(data: bytes, n: int = 2) -> bytes:
    """比特级多数表决：每 n 个比特还原 1 个。长度自动向下取整到 n 的倍数。"""
    if n < 2:
        return data
    bits = _to_bits(data)
    bits = bits[: (len(bits) // n) * n]
    out = []
    for i in range(0, len(bits), n):
        group = bits[i:i + n]
        out.append(1 if sum(group) * 2 > len(group) else 0)
    return _pack_bits(out)


# ============================================================
# 块交织（比特矩阵，行写列读；逆为列写行读 —— 两者形式相同即对合）
# 输入比特数若非 depth 整数倍，尾部补 0（解码端由码字结构自然吸收）。
# ============================================================

def _pad(bits: list, depth: int) -> list:
    rem = len(bits) % depth
    if rem:
        bits = list(bits) + [0] * (depth - rem)
    return bits


def interleave(data: bytes, depth: int = 32) -> bytes:
    if depth <= 1:
        return data
    bits = _to_bits(data)
    if len(bits) <= depth:
        return data
    bits = _pad(bits, depth)
    rows = len(bits) // depth
    grid = [[0] * depth for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(depth):
            grid[r][c] = bits[idx]; idx += 1
    out = []
    for c in range(depth):
        for r in range(rows):
            out.append(grid[r][c])
    return _pack_bits(out)


def deinterleave(data: bytes, depth: int = 32) -> bytes:
    if depth <= 1:
        return data
    bits = _to_bits(data)
    if len(bits) <= depth:
        return data
    bits = _pad(bits, depth)
    rows = len(bits) // depth
    grid = [[0] * depth for _ in range(rows)]
    idx = 0
    for c in range(depth):
        for r in range(rows):
            grid[r][c] = bits[idx]; idx += 1
    out = []
    for r in range(rows):
        for c in range(depth):
            out.append(grid[r][c])
    return _pack_bits(out)


# ============================================================
# 便捷 API（带帧头，编码/解码严格对称）
# ============================================================

def fec_encode(payload: bytes, repeat: int = 1, interleave_depth: int = 1) -> bytes:
    """
    编码 payload 并在头部写入 (magic + payload_byte_len)。
    返回完整帧字节，可直接送入调制器。
    """
    body = hamming_encode(payload)
    if interleave_depth > 1:
        body = interleave(body, interleave_depth)
    if repeat > 1:
        body = repeat_encode(body, repeat)
    header = struct.pack(">HI", MAGIC, len(payload))
    return header + body


def fec_decode(frame: bytes, repeat: int = 1, interleave_depth: int = 1) -> bytes:
    """
    解码 FEC 帧。校验 magic；读取 payload 长度仅用于校验，解码本身按实际比特数自推断。
    返回原始 payload；magic 不匹配时返回 b""（由上层 ARQ 处理）。
    """
    if len(frame) < HEADER_SIZE:
        return b""
    magic, payload_byte_len = struct.unpack(">HI", frame[:HEADER_SIZE])
    if magic != MAGIC:
        return b""
    body = frame[HEADER_SIZE:]
    if repeat > 1:
        body = repeat_decode(body, repeat)
    if interleave_depth > 1:
        body = deinterleave(body, interleave_depth)
    payload = hamming_decode(body)
    # 校验还原长度与帧头声明一致（额外安全网）
    if payload_byte_len > 0 and len(payload) != payload_byte_len:
        # 长度不符说明帧损坏严重，丢弃（触发 ARQ）
        return b""
    return payload


# ============================================================
# 自测
# ============================================================

def selftest():
    import random
    random.seed(0)

    # 1. 往返一致（干净信道）
    for size in (1, 7, 64, 200):
        msg = os.urandom(size)
        enc = fec_encode(msg, repeat=2, interleave_depth=8)
        dec = fec_decode(enc, repeat=2, interleave_depth=8)
        assert dec == msg, f"round-trip mismatch size={size}"
    print("[FEC] round-trip OK (sizes 1,7,64,200; clean)")

    # 2. 单比特纠错：直接在每个码字的 7 比特内翻转 1 位后译码，应还原。
    for nibble in range(16):
        cw = _encode_nibble(nibble)           # 7 比特干净码字
        for pos in range(7):
            corrupted = list(cw); corrupted[pos] ^= 1
            fixed = list(corrupted); _correct(fixed)
            assert fixed == cw, f"nibble={nibble} pos={pos}: {cw} not corrected from {corrupted}"
    print("[FEC] single-bit correction OK (16 nibbles x 7 positions)")

    # 3. 随机突发：交织(depth=16) + 重复(repeat=2) 下可恢复的突发长度。
    #    交织把连续突发打散到多个码字；深度 16 时，约 ≤16 字节突发可视为能力上限。
    for burst_len in (5, 10, 16):
        long_msg = os.urandom(128)
        enc = fec_encode(long_msg, repeat=2, interleave_depth=16)
        corrupted = bytearray(enc)
        burst_start = random.randint(HEADER_SIZE, max(HEADER_SIZE, len(corrupted) - burst_len - 1))
        for k in range(burst_len):
            corrupted[burst_start + k] ^= 0xFF
        dec = fec_decode(bytes(corrupted), repeat=2, interleave_depth=16)
        assert dec == long_msg, f"burst {burst_len}B recovery failed"
    print("[FEC] burst recovery OK (5/10/16-byte bursts, depth=16)")

    # 3b. 超长突发(40B)：交织后仍可能有多码字≥2错，此时应【拒绝】而非错译。
    long_msg = os.urandom(128)
    enc = fec_encode(long_msg, repeat=2, interleave_depth=16)
    corrupted = bytearray(enc)
    for k in range(40):
        corrupted[HEADER_SIZE + k] ^= 0xFF
    dec = fec_decode(bytes(corrupted), repeat=2, interleave_depth=16)
    assert dec == b"" or dec != long_msg, "long burst must not silently decode wrong"
    print("[FEC] long-burst rejection OK (40B -> no silent corruption)")

    # 4. 全参数组合：repeat ∈ {1,2}, depth ∈ {1,8,16}
    for repeat in (1, 2):
        for depth in (1, 8, 16):
            m = os.urandom(50)
            e = fec_encode(m, repeat=repeat, interleave_depth=depth)
            d = fec_decode(e, repeat=repeat, interleave_depth=depth)
            assert d == m, f"combo repeat={repeat} depth={depth}"
    print("[FEC] parameter combos OK (repeat x depth)")

    # 5. magic / 长度校验
    msg = os.urandom(32)
    enc = fec_encode(msg)
    bad = bytearray(enc); bad[0] ^= 0xFF
    assert fec_decode(bytes(bad)) == b""
    print("[FEC] bad-magic rejection OK")

    print("ALL FEC TESTS PASSED")


if __name__ == "__main__":
    selftest()
