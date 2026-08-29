#!/usr/bin/env python3
"""
/split.py
将 SpiderChat.txt 拆分为原始目录结构的文件，并忽略非代码文件。
用法: python split.py
"""

import os
import re
import sys

INPUT_FILE = "SpiderChat.txt"
OUTPUT_ROOT = "./SpiderChat"  # 所有文件将放在此目录下

# 匹配文件头标记行，例如:
#   /split.py:
#   /client/__init__.py:
#   /server/chat/cross_server.py:
# 捕获组 1 = 文件相对路径（去掉前导 "/" 和尾部 ":"）
HEADER_RE = re.compile(r'^/(.+?):\s*$')


def split_files():
    if not os.path.exists(INPUT_FILE):
        print(f"错误: 找不到 {INPUT_FILE}")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    i = 0
    file_count = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip("\r\n")
        m = HEADER_RE.match(stripped)

        if m:
            rel_path = m.group(1).strip()
            if not rel_path:
                i += 1
                continue

            out_path = os.path.join(OUTPUT_ROOT, rel_path)
            print(f"正在写入: {out_path}")

            # 跳过当前 header 行，收集内容直到下一个 header
            i += 1
            content = []
            while i < len(lines):
                nxt_stripped = lines[i].rstrip("\r\n")
                if HEADER_RE.match(nxt_stripped):
                    break
                content.append(lines[i])
                i += 1

            # 去掉尾部空行，保持文件整洁
            while content and content[-1].strip() == "":
                content.pop()

            # 确保目录存在
            out_dir = os.path.dirname(out_path)
            if out_dir:
                os.makedirs(out_dir, exist_ok=True)

            with open(out_path, "w", encoding="utf-8") as f_out:
                f_out.writelines(content)

            file_count += 1
        else:
            # 忽略非文件起始行（如文件头部的说明、空行）
            i += 1

    print(f"拆分完成，共生成 {file_count} 个文件，位于 {OUTPUT_ROOT}/ 目录")


if __name__ == "__main__":
    split_files()
