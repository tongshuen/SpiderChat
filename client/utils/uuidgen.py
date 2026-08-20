"""
UUIDv1 generation with forced real MAC address binding.

SECURITY FIX (v2):
- Rejects virtual/VM/random MAC addresses
- Only accepts MACs from physical interfaces
- Raises RuntimeError if no suitable MAC found (NO fallback)
- Validates MAC is not in reserved/private ranges
"""

import uuid
import struct
import sys
import re
import os

REJECTED_OUI_PREFIXES = {
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",
    "08:00:27",
    "00:15:5d",
    "00:1c:42", "00:03:ff",
    "02:42", "02:43",
    "02",  # 设置了本地管理位
    "fe:ff:ff", "fe:ff:fe",
    "00:00:00", "ff:ff:ff",
}

LOCAL_ADMIN_BYTE_PREFIXES = {0x02, 0x06, 0x0a, 0x0e}


def _is_physical_mac(mac_str: str) -> bool:
    """
    检查 MAC 地址是否来自物理网卡。
    拒绝虚拟、随机、本地管理和零 MAC 地址。
    """
    if not mac_str:
        return False

    mac_clean = mac_str.lower().replace(":", "").replace("-", "").replace(".", "")
    if len(mac_clean) != 12:
        return False


    if mac_clean == "0" * 12 or mac_clean == "f" * 12:
        return False


    first_byte = int(mac_clean[:2], 16)
    if (first_byte & 0x02) != 0:
        return False


    formatted = ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])
    for prefix in REJECTED_OUI_PREFIXES:
        if prefix.endswith(":"):
            if formatted.startswith(prefix):
                return False
        elif formatted.startswith(prefix.lower()):
            return False

    return True


def _get_mac_linux() -> str | None:
    """从 Linux /sys/class/net 获取 MAC，优先选择物理网卡。"""
    net_dir = "/sys/class/net"
    if not os.path.isdir(net_dir):
        return None

    candidates = []
    for iface in os.listdir(net_dir):

        iface_path = os.path.join(net_dir, iface)

        device_path = os.path.join(iface_path, "device")
        if not os.path.exists(device_path):
            continue

        if iface == "lo":
            continue
        addr_path = os.path.join(iface_path, "address")
        if os.path.exists(addr_path):
            with open(addr_path) as f:
                mac = f.read().strip()
            if _is_physical_mac(mac):
                candidates.append(mac)

    return candidates[0] if candidates else None


def _get_mac_darwin() -> str | None:
    """使用 ifconfig 从 macOS 获取 MAC。"""
    import subprocess
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
    except:
        return None


    current_iface = None
    macs = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith(("	", " ")):
            current_iface = line.split(":")[0].split(" ")[0]
        elif "ether" in line and current_iface and current_iface != "lo0":
            parts = line.split()
            if len(parts) >= 2:
                mac = parts[1]
                if _is_physical_mac(mac):
                    if current_iface == "en0":
                        return mac
                    macs.append(mac)

    return macs[0] if macs else None


def _get_mac_windows() -> str | None:
    """使用 getmac 从 Windows 获取 MAC。"""
    import subprocess
    try:
        out = subprocess.run(
            ["getmac", "/FO", "CSV", "/NH", "/V"],
            capture_output=True, text=True, timeout=5
        )
    except:
        return None


    lines = [l for l in out.stdout.strip().splitlines() if l]
    macs = []
    for line in lines:
        parts = [p.strip().strip('"') for p in line.split(",")]
        if len(parts) >= 2:
            mac = parts[0]

            if re.match(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$", mac):
                if _is_physical_mac(mac):
                    conn_name = parts[1] if len(parts) > 1 else ""
                    if any(k in conn_name.lower() for k in ["ethernet", "wi-fi", "wifi", "local area"]):
                        return mac
                    macs.append(mac)

    return macs[0] if macs else None


def get_real_mac():
    """
    Get the real MAC address of a physical network interface.
    Returns int (last 48 bits suitable for uuid.uuid1 node param).

    SECURITY: Rejects virtual, VM, random, and locally-administered MACs.
    Raises RuntimeError if no valid physical MAC can be found.
    """
    system = sys.platform.lower()
    mac_str = None

    if system.startswith("linux"):
        mac_str = _get_mac_linux()
    elif system == "darwin":
        mac_str = _get_mac_darwin()
    elif system.startswith("win"):
        mac_str = _get_mac_windows()


    if not mac_str:
        node = uuid.getnode()
        if node and node != 0:

            mac_str = ":".join(f"{(node >> (i*8)) & 0xff:02x}" for i in range(5, -1, -1))
            if not _is_physical_mac(mac_str):
                mac_str = None

    if not mac_str:
        raise RuntimeError(
            "Cannot obtain a valid physical MAC address. "
            "Virtual interfaces, VM adapters, and random MACs are not accepted. "
            "Please ensure a physical network adapter is available and not in privacy mode."
        )


    mac_clean = mac_str.replace(":", "").replace("-", "")
    node_int = int(mac_clean, 16)

    if node_int == 0:
        raise RuntimeError("Obtained MAC is zero — invalid")

    return node_int


def generate_uuid_v1():
    """
    Generate a UUIDv1 with the real physical MAC address forced into the node field.
    Raises RuntimeError if no physical MAC can be obtained (NO fallback).
    """
    mac_int = get_real_mac()
    return uuid.uuid1(node=mac_int)
