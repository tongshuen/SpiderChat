"""
日志工具 — 文件 + 控制台，带日志级别。
"""

import os
import time
import threading
from server.config.loader import get_data_dir

_lock = threading.Lock()
_log_file = None
_log_level = "INFO"
_log_path = ""

LEVELS = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3}

def init_logger(config: dict = None):
    """根据配置初始化日志器。"""
    global _log_file, _log_level, _log_path
    cfg = config or {}
    log_cfg = cfg.get("logging", {})
    _log_level = log_cfg.get("level", "INFO").upper()
    log_dir = log_cfg.get("directory", f"{get_data_dir()}/logs")
    os.makedirs(log_dir, exist_ok=True)
    _log_path = os.path.join(log_dir, "server.log")
    _log_file = open(_log_path, "a", buffering=1)  # 行缓冲
    info("Logger initialized", "LOG")


def get_logger(config: dict = None):
    """获取/初始化日志器。"""
    if not _log_file:
        init_logger(config)
    return _Logger()


class _Logger:
    """简单日志接口。"""

    def debug(self, msg: str, module: str = "APP"):
        _log("DEBUG", msg, module)

    def info(self, msg: str, module: str = "APP"):
        _log("INFO", msg, module)

    def warn(self, msg: str, module: str = "APP"):
        _log("WARN", msg, module)

    def error(self, msg: str, module: str = "APP"):
        _log("ERROR", msg, module)

    def get_recent(self, lines: int = 50) -> list:
        """从日志文件读取最后 N 行。"""
        if not _log_path or not os.path.exists(_log_path):
            return []
        with open(_log_path) as f:
            all_lines = f.readlines()
        return all_lines[-lines:]

    def set_level(self, level: str):
        global _log_level
        if level.upper() in LEVELS:
            _log_level = level.upper()
            info(f"Log level set to {_log_level}", "LOG")


def _log(level: str, msg: str, module: str):
    if LEVELS.get(level, 1) < LEVELS.get(_log_level, 1):
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level:5s}] [{module:8s}] {msg}\n"
    with _lock:
        if _log_file:
            _log_file.write(line)
        print(line.rstrip())


def debug(msg, module="APP"): _log("DEBUG", msg, module)
def info(msg, module="APP"): _log("INFO", msg, module)
def warn(msg, module="APP"): _log("WARN", msg, module)
def error(msg, module="APP"): _log("ERROR", msg, module)
