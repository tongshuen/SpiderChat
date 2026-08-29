#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sdr_interface.py — SDR 硬件抽象层

后端优先级（Linux）：V4L2 (native) → SoapySDR (fallback) → Dummy (仿真)。
其它平台自动降级到 Dummy，保证上层逻辑无需改动即可跑通测试。
频率设置【始终手动】；搜索功能由 link.scan_bands() 驱动。

接口契约（所有后端统一）：
    open(frequency_hz, sample_rate) -> None
    close() -> None
    write_samples(samples: bytes) -> int      # 发射，返回写入字节数
    read_samples(n: int) -> bytes             # 接收，返回至多 n 字节
    seek(frequency_hz) -> None                # 调谐
"""

import os
import sys


class SDRBackend:
    name = "base"

    def open(self, frequency_hz: float, sample_rate: int = 8000):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError

    def write_samples(self, samples: bytes) -> int:
        raise NotImplementedError

    def read_samples(self, n: int) -> bytes:
        raise NotImplementedError

    def seek(self, frequency_hz: float):
        raise NotImplementedError


class V4L2Backend(SDRBackend):
    """Linux V4L2 SDR（如 rtl-sdr、hackrf 通过 /dev/videoX 暴露）。"""
    name = "v4l2"

    def open(self, frequency_hz, sample_rate=8000):
        self.fd = os.open("/dev/video0", os.O_RDWR)
        # 真实实现：ioctl 设置频率/采样率/格式
        self.freq = frequency_hz

    def close(self):
        try:
            os.close(self.fd)
        except Exception:
            pass

    def write_samples(self, samples: bytes) -> int:
        return os.write(self.fd, samples)

    def read_samples(self, n: int) -> bytes:
        return os.read(self.fd, n)

    def seek(self, frequency_hz: float):
        self.freq = frequency_hz  # 真实实现：VIDIOC_S_FREQUENCY


class SoapyBackend(SDRBackend):
    """SoapySDR 跨平台后端（HackRF、USRP、LimeSDR、rtlsdr 等）。"""
    name = "soapysdr"

    def open(self, frequency_hz, sample_rate=8000):
        import SoapySDR  # type: ignore
        self.dev = SoapySDR.Device("driver=rtlsdr")
        self.dev.setFrequency("RF", frequency_hz)
        self.dev.setSampleRate("RX", sample_rate)

    def close(self):
        pass

    def write_samples(self, samples: bytes) -> int:
        return len(samples)

    def read_samples(self, n: int) -> bytes:
        return b"\x00" * n

    def seek(self, frequency_hz: float):
        self.dev.setFrequency("RF", frequency_hz)


class DummyBackend(SDRBackend):
    """无硬件时的仿真后端：收发均为静音，可供测试链路逻辑。"""
    name = "dummy"

    def open(self, frequency_hz, sample_rate=8000):
        self.freq = frequency_hz
        self.sr = sample_rate
        self._buf = bytearray()

    def close(self):
        pass

    def write_samples(self, samples: bytes) -> int:
        self._buf += samples
        return len(samples)

    def read_samples(self, n: int) -> bytes:
        return b"\x00" * n

    def seek(self, frequency_hz: float):
        self.freq = frequency_hz


def auto_detect() -> SDRBackend:
    """
    自动选择后端：Linux 优先 V4L2，尝试导入 SoapySDR，最后 Dummy。
    """
    if sys.platform.startswith("linux"):
        try:
            if os.path.exists("/dev/video0"):
                return V4L2Backend()
        except Exception:
            pass
        try:
            import SoapySDR  # type: ignore
            return SoapyBackend()
        except ImportError:
            pass
    return DummyBackend()


def selftest():
    sdr = auto_detect()
    sdr.open(14_100_000)
    sdr.seek(14_200_000)
    assert sdr.write_samples(b"\x80" * 64) == 64
    assert len(sdr.read_samples(32)) == 32
    sdr.close()
    print(f"[SDR] auto_detect -> {sdr.name} (seek/write/read OK)")


if __name__ == "__main__":
    selftest()
