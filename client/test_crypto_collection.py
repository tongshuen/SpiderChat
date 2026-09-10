"""
crypto_collection 冒号转义单元测试。

覆盖：
  - 不含冒号的普通地址（向后兼容）
  - 含冒号的地址（如 bitcoin:bc1q... URI 形式）
  - 多个冒号混合（字段内多个冒号 + 分隔冒号）
  - 转义冒号与普通分隔冒号混合
  - build -> parse 往返一致性

直接运行：python3 -m client.test_crypto_collection
"""

from client.crypto_collection import (
    COLLECTION_TAG,
    is_collection_text,
    parse_collection,
    build_collection_text,
    escape_field,
)


def _assert_roundtrip(currency, address, network):
    """build 再 parse 应原样还原三个字段。"""
    text = build_collection_text(currency, address, network)
    assert is_collection_text(text), f"应识别为 Collection 消息: {text}"
    parsed = parse_collection(text)
    assert parsed is not None, f"解析失败: {text}"
    assert parsed["currency"] == currency.strip(), \
        f"currency 不匹配: {parsed['currency']!r} != {currency.strip()!r}"
    assert parsed["address"] == address.strip(), \
        f"address 不匹配: {parsed['address']!r} != {address.strip()!r}"
    assert parsed["network"] == network.strip(), \
        f"network 不匹配: {parsed['network']!r} != {network.strip()!r}"
    return parsed


def test_no_colon():
    """不含冒号的普通地址（旧格式向后兼容）。"""
    parsed = parse_collection(
        "Collection:BTC:bc1qtnpzgam83dzlyqnmnfvqec96uzm409kzs4rl8s:Bitcoin"
    )
    assert parsed is not None
    assert parsed["currency"] == "BTC"
    assert parsed["address"] == "bc1qtnpzgam83dzlyqnmnfvqec96uzm409kzs4rl8s"
    assert parsed["network"] == "Bitcoin"
    print("[OK] 不含冒号地址解析正确")


def test_address_with_colon():
    """地址含冒号（bitcoin:bc1q... URI 形式），build 转义后 parse 还原。"""
    _assert_roundtrip("BTC", "bitcoin:bc1qtnpzgam83dzlyqnmnfvqec96uzm409kzs4rl8s", "Bitcoin")
    print("[OK] 含冒号地址 build->parse 往返正确")


def test_multiple_colons():
    """字段内多个冒号 + 字段间分隔冒号混合。"""
    parsed = _assert_roundtrip("USDT", "ethereum:mainnet:0xabcdef123456", "Ethereum")
    assert parsed["address"] == "ethereum:mainnet:0xabcdef123456"
    print("[OK] 多个冒号混合解析正确")


def test_escaped_separator_mixed():
    """转义冒号作字面量，未转义冒号作分隔符。"""
    # 手工构造：currency=BTC, address="a:b:c", network="x:y"
    # build 后应为 Collection:BTC:a\:b\:c:x\:y
    text = build_collection_text("BTC", "a:b:c", "x:y")
    assert text == r"Collection:BTC:a\:b\:c:x\:y", f"转义结果异常: {text!r}"
    parsed = parse_collection(text)
    assert parsed["address"] == "a:b:c"
    assert parsed["network"] == "x:y"
    # 未转义的冒号仍是分隔符：4 段未转义冒号 -> 只取前 3 段，其余并入 network
    manual = "Collection:BTC:a:b:c:Bitcoin"
    p2 = parse_collection(manual)
    # 这里 currency=BTC, address=a, network="b:c:Bitcoin"（maxsplit=2）
    assert p2["currency"] == "BTC" and p2["address"] == "a"
    print("[OK] 转义冒号/分隔冒号混合解析正确")


def test_backslash_escaping():
    """反斜杠与冒号同时存在时不串义（原样往返）。"""
    # 字段值本就含反斜杠+冒号，往返后应保留原内容 "abc\:def"
    parsed = _assert_roundtrip("DOGE", "abc\\:def", "Dogecoin")
    assert parsed["address"] == "abc\\:def"
    print("[OK] 反斜杠转义往返正确")


def test_invalid():
    """非法格式返回 None。"""
    assert parse_collection("Collection:BTC") is None
    assert parse_collection("NotACollection:BTC:addr:Net") is None
    assert parse_collection("") is None
    print("[OK] 非法格式正确返回 None")


def run_all():
    test_no_colon()
    test_address_with_colon()
    test_multiple_colons()
    test_escaped_separator_mixed()
    test_backslash_escaping()
    test_invalid()
    print("ALL COLON ESCAPE TESTS PASSED")


if __name__ == "__main__":
    run_all()
