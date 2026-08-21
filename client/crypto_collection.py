"""
Spider — Collection 消息辅助模块
处理加密货币地址卡片消息的解析、构建与渲染。
消息格式（明文）:  Collection:货币名称:地址:网络
示例:              Collection:BTC:bc1qtnpzgam83dzlyqnmnfvqec96uzm409kzs4rl8s:Bitcoin
                    Collection:USDC:GNZknFF64eMnAUhDzVJHo4LnT2f68j5pPsEVQYqE5Np3:Solana（这两个地址和网络是我的哦，你们如果闲的发慌可以给我转钱）
服务端只将其视为普通文本消息；客户端负责识别并渲染为卡片。
"""

import os
import json
import re
import hashlib

# 不再需要 client.utils.config 中的 get_data_dir
# from client.utils.config import get_data_dir

# 硬编码标识前缀
COLLECTION_TAG = "Collection"

# 加密货币数据 JSON 文件名（放在 client/ 目录下）
CRYPTO_DATA_FILE = "crypto_data.json"

# 卡片 UI 配色
CARD_BG_SENT = "#1A3A2A"       # 深绿底（发送方）
CARD_BG_RECV = "#1A2A3A"       # 深蓝底（接收方）
CARD_ACCENT = "#00C896"         # 青绿强调色
CARD_TEXT = "#E8E8E8"          # 主文本
CARD_SUB = "#AAAAAA"            # 次要文本


def is_collection_text(text: str) -> bool:
    """判断一段明文是否为 Collection 消息。"""
    if not isinstance(text, str):
        return False
    return text.startswith(COLLECTION_TAG + ":")


def parse_collection(text: str) -> dict | None:
    """
    解析 Collection 文本。
    返回 {tag, currency, address, network} 或 None（格式不合法时）。
    """
    if not is_collection_text(text):
        return None
    # Collection:货币:地址:网络  —— 地址中可能含冒号极少，但按 4 段切分
    parts = text.split(":", 3)
    if len(parts) != 4:
        return None
    tag, currency, address, network = parts
    currency = currency.strip()
    address = address.strip()
    network = network.strip()
    if not currency or not address or not network:
        return None
    return {
        "tag": tag.strip(),
        "currency": currency,
        "address": address,
        "network": network,
    }


def build_collection_text(currency: str, address: str, network: str) -> str:
    """由字段组装 Collection 明文（用于发送前填入输入框/直接发送）。"""
    return f"{COLLECTION_TAG}:{currency.strip()}:{address.strip()}:{network.strip()}"


def crypto_data_path() -> str:
    """
    返回 crypto_data.json 的绝对路径。
    修改后：直接从 client/ 目录读取，随仓库发布。
    """
    # 当前文件在 client/crypto_collection.py，取其所在目录（即 client/）
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), CRYPTO_DATA_FILE)


def load_crypto_data() -> dict:
    """
    加载本地加密货币/网络名称数据。
    JSON 格式: {"Cryptocurrency": ["BTC","ETH",...], "blockchain": ["Bitcoin","Solana",...]}
    文件不存在或解析失败时返回空分类字典。
    """
    path = crypto_data_path()
    if not os.path.exists(path):
        return {"Cryptocurrency": [], "blockchain": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"Cryptocurrency": [], "blockchain": []}
        data.setdefault("Cryptocurrency", [])
        data.setdefault("blockchain", [])
        # 去重保序
        data["Cryptocurrency"] = _dedupe(data["Cryptocurrency"])
        data["blockchain"] = _dedupe(data["blockchain"])
        return data
    except Exception as e:
        print(f"[COLLECTION] load_crypto_data error: {e}")
        return {"Cryptocurrency": [], "blockchain": []}


def _dedupe(lst):
    seen = set()
    out = []
    for x in lst:
        if isinstance(x, str) and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def match_prefix(names: list, prefix: str) -> list:
    """对名称列表做大小写不敏感的前缀匹配，返回按原顺序的匹配项（最多 12 条）。"""
    if not prefix:
        return names[:12]
    p = prefix.lower()
    return [n for n in names if n.lower().startswith(p)][:12]


def short_address(addr: str, head: int = 8, tail: int = 6) -> str:
    """将长地址缩写为 前:后 形式便于展示。"""
    if len(addr) <= head + tail + 1:
        return addr
    return f"{addr[:head]}…{addr[-tail:]}"
