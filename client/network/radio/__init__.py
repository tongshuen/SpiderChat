#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
radio 包 —— Spider 无线电物理层与链路层。
对外 API（上层只需关心这些）：
    from client.network.radio import phy, fec, signature, sdr_interface, dht
    from client.network.link import Link, LinkMode, RadioConfig
设计要点：
- 物理层：全部下沉到 C 共享库 libphy.so（5 种调制/解调/自动协商/SDR 交互/信道估计），
  Python 端 phy.py 为薄封装，无降级（C 库不可用则抛 RuntimeError）；
- 自动模式：用户仅指定频率，由 C 库自动完成信道探测、最优参数选择和调制解调；
- 手动模式：用户指定调制类型和参数，Python 透传给 C 库；
- 独特协议签名，与 FT8/JS8/WSPR/RTTY 等明确区分；
- DHT：节点间交换「频点路由表」（不含调制方式），客户端只需【一个频点】
  即可通过 bootstrap 学到全网节点，实现无线电网络（影子公网）的自动发现；
- 带宽严格 ≤ 12.5 kHz。
"""
from . import fec
from . import phy
from . import signature
from . import sdr_interface
from . import dht
__all__ = ["fec", "phy", "signature", "sdr_interface", "dht"]
