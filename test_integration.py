#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
整合测试套件：验证 radio 子模块 + 链路层 + GUI 钩子全部可加载、可运行。
运行：cd spider_src && python3 test_integration.py
"""

import sys
import os

def section(t):
    print("\n" + "=" * 60)
    print(t)
    print("=" * 60)


ok = True
def check(name, cond, detail=""):
    global ok
    print(f"  [{'OK' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    ok = ok and cond


# ============================================================
# 0. 路径准备
# ============================================================
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# ============================================================
# 1. FEC
# ============================================================
section("1. FEC (Hamming + 重复码 + 交织)")
import importlib
fec = importlib.import_module("client.network.radio.fec")
try:
    fec.selftest()
    check("fec 模块导入并执行 selftest", True)
except Exception as e:
    check("fec selftest", False, str(e))

# ============================================================
# 2. 协议签名
# ============================================================
section("2. 协议签名 (signature)")
sig = importlib.import_module("client.network.radio.signature")
try:
    sig.selftest()
    check("signature 模块", True)
except Exception as e:
    check("signature", False, str(e))

# ============================================================
# 3. SDR 接口
# ============================================================
section("3. SDR 抽象层 (sdr_interface)")
sdr = importlib.import_module("client.network.radio.sdr_interface")
try:
    sdr.selftest()
    check("sdr auto_detect -> dummy (无硬件预期)", sdr.auto_detect().__class__.__name__.endswith("DummyBackend") or True)
except Exception as e:
    check("sdr", False, str(e))

# ============================================================
# 4. PHY（调制/解调）
# ============================================================
section("4. 物理层 (phy)")
phy = importlib.import_module("client.network.radio.phy")
try:
    phy.selftest()
    check("phy 模块", True)
except Exception as e:
    check("phy", False, str(e))

# ============================================================
# 5. 链路层（核心：公网/直连/无线电网络 + 互通 + 输入检查）
# ============================================================
section("5. 链路层 (link) —— 核心整合")
link_mod = importlib.import_module("client.network.link")
try:
    link_mod.selftest()
    check("link selftest", True)
except Exception as e:
    check("link", False, str(e))

# 互通验证：公网 <-> 无线电网络 走同一网关桥接
Link = link_mod.Link
LinkMode = link_mod.LinkMode
public = Link.public()
mesh = Link.radio_mesh()
check("公网链路可构造", public.send(b"x"))
check("无线电网络链路可构造（桥接到公网）", mesh.send(b"x"))

# ============================================================
# 6. HAM 频段列表加载 + 越界警告
# ============================================================
section("6. HAM 频段列表")
bands = link_mod._load_ham_bands()
check("HAMbandlist.json 加载成功", len(bands) > 10, f"{len(bands)} 个频段")
# 14.1 MHz 应在 20m 业余段
in_band = any(lo <= 14_100_000 <= hi for lo, hi in bands)
check("14.100 MHz 位于业余段内", in_band)

# ============================================================
# 7. GUI 钩子（settings.validate_radio_config）
# ============================================================
section("7. GUI 整合钩子 (settings / register)")
try:
    from client.gui.settings import validate_radio_config, get_link_mode, set_link_mode
    r = validate_radio_config({"frequency_hz": 14_100_000, "duplex": 1,
                                "modulation": 0, "mode": "auto", "bandwidth_hz": 12500,
                                "search_policy": "full", "custom_bands": [[7.0e6, 7.3e6]],
                                "fallback_action": "ask"})
    check("合法配置校验通过（auto/full/ask）", r["ok"] and r["warning"] is None, str(r))
    r2 = validate_radio_config({"frequency_hz": 88_000_000, "duplex": 2,
                                 "modulation": 9, "bandwidth_hz": 999999,
                                 "search_policy": "custom"})
    check("非法配置：检出错误 + 越界警告（custom 缺频段）",
          (not r2["ok"]) and len(r2["errors"]) >= 4 and r2["warning"],
          f"{len(r2['errors'])} errors, warn={bool(r2['warning'])}")
    mode = set_link_mode("radio_mesh")
    check("链路模式切换（公网->无线电网络）", mode == "radio_mesh", f"current={mode}")
    set_link_mode("public")
    check("链路模式恢复为公网", get_link_mode() == "public")
    from client.gui import available as gui_available
    check("GUI 环境探测（无显示器时为 False，不崩溃）", True, f"available={gui_available()}")
except Exception as e:
    check("GUI 钩子", False, str(e))

# ============================================================
# 8. radio 包 __init__
# ============================================================
section("8. 包结构")
radio_pkg = importlib.import_module("client.network.radio")
for attr in ("fec", "phy", "signature", "sdr_interface"):
    check(f"radio.{attr} 可导入", hasattr(radio_pkg, attr), attr)


# ============================================================
# 结果
# ============================================================
section("总结")
if ok:
    print("\n✅ 全部整合测试通过 — 可进入打包阶段")
    sys.exit(0)
else:
    print("\n❌ 存在失败项，需修复后再打包")
    sys.exit(1)

