#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack.py — 目录打包器
将本脚本所在目录下的全部文件（不含本脚本自身）打包成一个 TXT 文件。
TXT 文件格式（每个条目）：
    相对路径:
    [base64]   <-- 非文本/未知文件才有此标记，内容为 base64
    文件内容（文本）或 base64 内容
    ================================================================================
非文本文件 / 无法解码为 UTF-8 的文件：以 base64 存储，并在路径行后追加 "[base64]" 标记。
TXT 文件头部会内嵌一个拆包脚本（unpack 函数），拆包时读取本 TXT 即可还原目录结构。
"""

import os
import sys
import base64
import binascii
import zlib

# ============================================================
# 配置
# ============================================================
SELF_NAME = os.path.basename(__file__)          # 打包脚本自身不参与打包
OUTPUT_NAME = "packed_archive.txt"              # 输出文件名
SEPARATOR = "=" * 80                            # 条目分隔线
# 拆包脚本在 TXT 中的包裹标记：使用足够独特、不会出现在脚本源码中的字符串
_SCRIPT_BEGIN = "##### EMBEDDED_UNPACK_SCRIPT_BEGIN #####"
_SCRIPT_END = "##### EMBEDDED_UNPACK_SCRIPT_END #####"

# 常见的"应视为文本"的文件扩展名（小写）。命中即尝试按文本读取。
TEXT_EXTENSIONS = {
    ".txt", ".py", ".md", ".rst", ".json", ".js", ".ts", ".html", ".htm",
    ".css", ".scss", ".less", ".xml", ".yaml", ".yml", ".ini", ".cfg",
    ".conf", ".toml", ".csv", ".tsv", ".sh", ".bash", ".zsh", ".bat",
    ".cmd", ".ps1", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx", ".cs",
    ".java", ".kt", ".scala", ".go", ".rs", ".rb", ".php", ".pl",
    ".swift", ".m", ".mm", ".lua", ".sql", ".r", ".dart", ".groovy",
    ".dockerfile", ".gitignore", ".env", ".log", ".diff", ".patch",
}


def is_likely_text(path: str) -> bool:
    """根据扩展名判断是否应按文本处理。"""
    _, ext = os.path.splitext(path)
    if ext.lower() in TEXT_EXTENSIONS:
        return True
    # 无扩展名文件尝试按文本处理
    return ext == ""


def read_as_text(path: str) -> tuple[bool, str]:
    """
    尝试将文件按 UTF-8 文本读取。
    返回 (是否文本可读, 内容或 base64 内容)。
    若读取失败或含大量非文本字节，则返回 base64。
    """
    try:
        with open(path, "rb") as f:
            raw = f.read()
        if not raw:
            return True, ""  # 空文件视为文本
        # 检测是否含大量非文本控制字符（除常见空白/tab/换行外）
        text = raw.decode("utf-8")
        # 若解码成功且非二进制特征明显，视为文本
        # 简单启发：若文本中 NUL 字符占比高，视为二进制
        if "\x00" in text:
            raise UnicodeDecodeError("utf-8", raw, 0, 1, "null byte")
        return True, text
    except (UnicodeDecodeError, OSError):
        # 回退为 base64
        return False, base64.b64encode(raw).decode("ascii")


def collect_files(root: str) -> list[str]:
    """收集 root 目录下所有文件路径（相对路径），排除自身与输出文件。"""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # 排除隐藏目录（如 .git）
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fname in sorted(filenames):
            if fname == SELF_NAME or fname == OUTPUT_NAME:
                continue
            full = os.path.join(dirpath, fname)
            rel = os.path.relpath(full, root)
            files.append(rel)
    return sorted(files)


# ============================================================
# 内嵌拆包脚本源码（以字符串形式嵌入到输出 TXT 头部）
# 拆包脚本读取本 TXT，解析条目，还原文件。
# ============================================================
UNPACKER_SOURCE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
unpack.py（内嵌于打包 TXT 头部）
读取同目录下的 packed_archive.txt，将其中的文件还原到 ./unpacked/ 目录，
保留原始相对路径。自动识别 base64 条目并解码。
用法：python unpack.py [archive.txt]
若不指定参数，默认读取本脚本所在目录的 packed_archive.txt。
"""

import os
import sys
import base64

SEPARATOR = "=" * 80


def find_archive(default_dir):
    """定位打包 TXT：优先使用命令行参数，其次在同目录查找。"""
    if len(sys.argv) > 1:
        return sys.argv[1]
    for name in ("packed_archive.txt", "archive.txt"):
        cand = os.path.join(default_dir, name)
        if os.path.exists(cand):
            return cand
    for f in sorted(os.listdir(default_dir)):
        if f.endswith(".txt") and os.path.isfile(os.path.join(default_dir, f)):
            return os.path.join(default_dir, f)
    return None


def parse_archive(text):
    """
    解析打包 TXT 数据区，返回 [(rel_path, is_base64, content_str), ...]。
    数据区以固定锚点 "----- DATA_SECTION_BEGIN -----" 标识起点，
    每条文件条目以 SEPARATOR（80 个 '='）行分隔。
    条目首行是 "路径:"（文本）或 "路径:[base64]"（二进制/base64）。
    """
    anchor = "----- DATA_SECTION_BEGIN -----"
    a_idx = text.find(anchor)
    if a_idx == -1:
        # 兼容旧格式：回退到首个 SEPARATOR
        a_idx = text.find(SEPARATOR)
    if a_idx == -1:
        return []
    # 从锚点之后开始解析；先定位锚点后第一个 SEPARATOR 作为数据区第一条目前置分隔线
    rest = text[a_idx:]
    sep_idx = rest.find(SEPARATOR)
    if sep_idx == -1:
        return []
    data = rest[sep_idx:]  # 从首个数据区分隔线开始
    lines = data.split("\n")
    entries = []
    cur_path = None
    cur_b64 = False
    cur_body = []

    def flush():
        if cur_path is not None:
            entries.append((cur_path, cur_b64, "\n".join(cur_body)))

    i = 0
    while i < len(lines):
        line = lines[i]
        if line == SEPARATOR:
            flush()
            cur_path = None
            cur_b64 = False
            cur_body = []
            i += 1
            continue
        if cur_path is None:
            stripped = line.rstrip()
            if not stripped:
                i += 1
                continue
            if stripped.endswith(":[base64]"):
                cur_path = stripped[:-len(":[base64]")].strip()
                cur_b64 = True
            elif stripped.endswith(":"):
                cur_path = stripped[:-1].strip()
                cur_b64 = False
            else:
                i += 1
                continue
            cur_body = []
        else:
            cur_body.append(line)
        i += 1
    flush()
    return entries


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    archive = find_archive(here)
    if not archive or not os.path.exists(archive):
        print("[UNPACK] 未找到打包文件 packed_archive.txt")
        sys.exit(1)
    with open(archive, "r", encoding="utf-8") as f:
        text = f.read()
    entries = parse_archive(text)
    if not entries:
        print("[UNPACK] 未解析到任何文件条目")
        sys.exit(1)
    out_root = os.path.join(here, "unpacked")
    os.makedirs(out_root, exist_ok=True)
    count_text = 0
    count_bin = 0
    for rel_path, is_b64, content in entries:
        dest = os.path.join(out_root, rel_path)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if is_b64:
            raw = base64.b64decode(content)
            with open(dest, "wb") as f:
                f.write(raw)
            count_bin += 1
        else:
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            count_text += 1
        print("  +", rel_path)
    print("[UNPACK] 完成：%d 个文本文件 + %d 个二进制文件 -> %s" % (count_text, count_bin, out_root))


if __name__ == "__main__":
    main()
'''


def build_archive(root: str, files: list[str]) -> str:
    """构建打包 TXT 的全部内容（含内嵌拆包脚本 + 数据条目）。"""
    parts = []
    # ---- 头部：说明 + 拆包脚本 ----
    parts.append("=" * 80)
    parts.append("PACKED ARCHIVE")
    parts.append("=" * 80)
    parts.append("本文件由 pack.py 生成，包含若干文件条目。")
    parts.append("条目格式：")
    parts.append('    "相对路径:"')
    parts.append('    [可选] "[base64]" 标记行（仅二进制/未知文件）')
    parts.append("    文件内容（文本原文 或 base64 字符串）")
    parts.append('每条目以一行 "' + "=" * 80 + '" 分隔。')
    parts.append("")
    parts.append("【拆包方法】将下方内嵌的 unpack.py 保存为 unpack.py，")
    parts.append("             与本文档置于同一目录后运行：  python unpack.py")
    parts.append("             还原后的文件位于 ./unpacked/ 目录。")
    parts.append("")
    parts.append(SEPARATOR)
    parts.append("----- 以下是内嵌拆包脚本 (unpack.py) 开始 -----")
    parts.append(_SCRIPT_BEGIN)
    parts.append(UNPACKER_SOURCE)
    parts.append(_SCRIPT_END)
    parts.append("----- 以上是内嵌拆包脚本 (unpack.py) 结束 -----")
    parts.append(SEPARATOR)
    parts.append("----- DATA_SECTION_BEGIN -----")
    parts.append("以下为打包数据区，每条文件条目以分隔线（80 个 '='）分隔。")
    parts.append(SEPARATOR)

    # ---- 数据区：逐个文件条目 ----
    for rel in files:
        full = os.path.join(root, rel)
        rel_disp = rel.replace(os.sep, "/")  # 统一用正斜杠
        if is_likely_text(full):
            ok, content = read_as_text(full)
            if ok:
                parts.append(f"{rel_disp}:")
                parts.append(content)
            else:
                # 文本扩展名但实为二进制 -> base64
                parts.append(f"{rel_disp}:[base64]")
                parts.append(content)  # 已是 base64
        else:
            # 非文本：base64
            with open(full, "rb") as f:
                raw = f.read()
            b64 = base64.b64encode(raw).decode("ascii")
            parts.append(f"{rel_disp}:[base64]")
            parts.append(b64)
        parts.append(SEPARATOR)
    return "\n".join(parts) + "\n"


def main():
    root = os.path.dirname(os.path.abspath(__file__))
    print(f"[PACK] 扫描目录：{root}")
    files = collect_files(root)
    if not files:
        print("[PACK] 目录下无可打包文件（除本脚本外）。")
        sys.exit(0)
    print(f"[PACK] 共发现 {len(files)} 个文件")
    archive = build_archive(root, files)
    out_path = os.path.join(root, OUTPUT_NAME)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(archive)
    size = os.path.getsize(out_path)
    print(f"[PACK] 打包完成：{out_path}  ({size/1024:.1f} KB)")
    print(f"[PACK] 拆包方法：将输出文件与下方保存的 unpack.py 放于同目录，运行 unpack.py 即可还原。")


if __name__ == "__main__":
    main()
