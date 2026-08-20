"""
Spider 客户端 — 入口点。
启动注册/解锁窗口。
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client.gui.register import RegisterWindow

def main():
    app = RegisterWindow()
    app.run()

if __name__ == "__main__":
    main()
