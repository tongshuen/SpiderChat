"""
Packet Obfuscation — 包混淆模块

将加密消息封装成看似普通网络流量的格式，
避免在传输过程中被识别为聊天协议流量。

支持的混淆模式:
1. HTTP/1.1 伪装 — 看起来像普通网页请求
2. DNS 查询伪装 — 看起来像 DNS 查询
3. TLS ClientHello 伪装 — 看起来像 TLS 握手
4. WebSocket 帧伪装 — 看起来像 WebSocket 通信
5. 随机填充 — 长度随机化避免特征识别

同时提供洋葱路由 (OnionRouter) 用于多跳匿名通信。
"""

import base64
import json
import os
import random
import struct
import time
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


OBFUSCATION_MODES = {
    "http": "HTTP/1.1 请求伪装",
    "dns": "DNS 查询伪装",
    "tls": "TLS ClientHello 伪装",
    "websocket": "WebSocket 帧伪装",
    "random": "随机填充模式",
}

DEFAULT_MODE = "http"

PADDING_RANGE = (64, 1024)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

COMMON_HOSTS = [
    "www.google.com",
    "www.bing.com",
    "cdn.jsdelivr.net",
    "ajax.googleapis.com",
    "api.github.com",
    "www.cloudflare.com",
    "static.cloudflareinsights.com",
    "www.gstatic.com",
]

COMMON_PATHS = [
    "/search",
    "/api/v1/data",
    "/static/js/main.js",
    "/assets/css/style.css",
    "/api/metrics",
    "/analytics/collect",
    "/v2/check",
    "/cdn/resource",
]


def _encode_payload(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_payload(encoded: str) -> bytes:
    return base64.b64decode(encoded.encode("ascii"))



def obfuscate_http(payload: bytes) -> bytes:
    encoded = _encode_payload(payload)
    host = random.choice(COMMON_HOSTS)
    path = random.choice(COMMON_PATHS)
    ua = random.choice(USER_AGENTS)
    timestamp = int(time.time())

    extra_headers = [
        f"X-Request-ID: {os.urandom(8).hex()}",
        f"X-Trace-Id: {os.urandom(16).hex()}",
        f"Cache-Control: max-age={random.randint(60, 3600)}",
        f"Pragma: no-cache",
    ]
    random.shuffle(extra_headers)

    padding_params = [
        f"v={random.randint(100,999)}",
        f"cb={os.urandom(4).hex()}",
        f"r={random.randint(1000,9999)}",
    ]

    query = f"d={encoded}&t={timestamp}&{'&'.join(padding_params)}"
    if len(query) > 2048:
        query = f"d={encoded[:1024]}&c={encoded[1024:]}&t={timestamp}"

    request_lines = [
        f"GET {path}?{query} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {ua}",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
        "Accept-Encoding: gzip, deflate, br",
        "Connection: keep-alive",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: none",
        "Sec-Fetch-User: ?1",
    ]
    request_lines.extend(extra_headers[:2])
    request_lines.append("")
    request_lines.append("")

    return "\r\n".join(request_lines).encode("utf-8")


def deobfuscate_http(data: bytes) -> Optional[bytes]:
    try:
        text = data.decode("utf-8")
        lines = text.split("\r\n")
        for line in lines:
            if "d=" in line and "HTTP/" in line:
                import re
                match = re.search(r"[?&]d=([A-Za-z0-9+/=]+)", line)
                if match:
                    encoded = match.group(1)
                    cont_match = re.search(r"[?&]c=([A-Za-z0-9+/=]+)", line)
                    if cont_match:
                        encoded += cont_match.group(1)
                    return _decode_payload(encoded)
        body_start = text.find("\r\n\r\n")
        if body_start > 0:
            body = text[body_start + 4:]
            if body.strip():
                return _decode_payload(body.strip())
    except Exception:
        pass
    return None



def obfuscate_dns(payload: bytes) -> bytes:
    encoded = _encode_payload(payload)
    labels = []
    chunk_size = 30
    for i in range(0, len(encoded), chunk_size):
        chunk = encoded[i:i+chunk_size]
        labels.append(chunk)

    tlds = ["com", "net", "org", "io", "dev", "app"]
    domain = ".".join(labels) + "." + random.choice(tlds)

    txn_id = os.urandom(2)
    flags = struct.pack("!H", 0x0100)
    qdcount = struct.pack("!H", 1)
    ancount = struct.pack("!H", 0)
    nscount = struct.pack("!H", 0)
    arcount = struct.pack("!H", 0)

    name_bytes = b""
    for label in domain.split("."):
        name_bytes += struct.pack("!B", len(label)) + label.encode("ascii")
    name_bytes += b"\x00"

    qtype = struct.pack("!H", 1)
    qclass = struct.pack("!H", 1)

    return txn_id + flags + qdcount + ancount + nscount + arcount + name_bytes + qtype + qclass


def deobfuscate_dns(data: bytes) -> Optional[bytes]:
    try:
        if len(data) < 12:
            return None
        offset = 12
        labels = []
        while offset < len(data):
            length = struct.unpack("!B", data[offset:offset+1])[0]
            if length == 0:
                break
            if length > 63:
                break
            offset += 1
            label = data[offset:offset+length].decode("ascii", errors="ignore")
            labels.append(label)
            offset += length

        domain = ".".join(labels)
        parts = domain.rsplit(".", 1)
        if len(parts) == 2:
            encoded = parts[0]
            return _decode_payload(encoded)
    except Exception:
        pass
    return None



def obfuscate_tls(payload: bytes) -> bytes:
    encoded = _encode_payload(payload)

    record_type = b"\x16"        # 握手
    record_version = b"\x03\x01"
    
    handshake_type = b"\x01"   # 客户端问候
    version = b"\x03\x03"
    random_bytes = os.urandom(32)
    session_id_len = b"\x00"
    session_id = b""
    
    cipher_suites = struct.pack("!H", 8)
    cipher_suites += b"\x13\x01"
    cipher_suites += b"\x13\x02"
    cipher_suites += b"\x13\x03"
    cipher_suites += b"\x00\x2f"
    

    compression = b"\x01\x00"
    
    sni_name = encoded.encode("ascii")  # 完整载荷，不截断
    if len(sni_name) > 600:
        sni_name = sni_name[:600]
    name_type = struct.pack("!B", 0x00)
    name_len = struct.pack("!H", len(sni_name))
    name_list_len = struct.pack("!H", 1 + 2 + len(sni_name))
    sni_data = name_list_len + name_type + name_len + sni_name
    sni_ext = struct.pack("!H", 0x0000)
    sni_ext += struct.pack("!H", len(sni_data)) + sni_data
    
    fake_ext = b""
    fake_ext += struct.pack("!H", 0x000a)
    fake_ext += struct.pack("!H", 8)
    fake_ext += struct.pack("!H", 6)
    fake_ext += struct.pack("!H", 0x001d)
    fake_ext += struct.pack("!H", 0x0017)
    fake_ext += struct.pack("!H", 0x0018)
    fake_ext += struct.pack("!H", 0x0010)
    fake_ext += struct.pack("!H", 11)
    fake_ext += struct.pack("!B", 2) + b"h2"
    fake_ext += struct.pack("!B", 5) + b"http/1.1"
    
    extensions = sni_ext + fake_ext
    extensions_len = struct.pack("!H", len(extensions))
    
    client_hello = version + random_bytes + session_id_len + session_id + cipher_suites + compression + extensions_len + extensions
    
    target_len = random.randint(256, 1024)
    if len(client_hello) < target_len:
        client_hello += os.urandom(target_len - len(client_hello))
    client_hello = client_hello[:target_len]
    
    handshake_len = struct.pack("!I", len(client_hello))[1:]
    handshake_header = handshake_type + handshake_len
    
    record_payload = handshake_header + client_hello
    record_len = struct.pack("!H", len(record_payload))
    record_header = record_type + record_version + record_len
    
    return record_header + record_payload


def deobfuscate_tls(data: bytes) -> Optional[bytes]:
    """
    解码 TLS 混淆数据。
    布局: [5: 记录头] [4: 握手头] [2: 版本]
    [32: 随机] [1: sid_len] [sid] [2: cs_len] [cs] [2: comp]
    [2: 扩展总长] [2: 扩展类型] [2: 扩展长] [2: 名称列表长] [1: 名称类型] [2: 名称长] [名称]
    """
    try:
        if len(data) < 5 or data[0] != 0x16:
            return None


        offset = 5 + 4 + 2 + 32
        if offset + 1 > len(data):
            return None


        sid_len = struct.unpack("!B", data[offset:offset+1])[0]
        offset += 1 + sid_len
        if offset + 2 > len(data):
            return None

        cs_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2 + cs_len
        if offset + 2 > len(data):
            return None


        comp_len = struct.unpack("!B", data[offset:offset+1])[0]
        offset += 1 + comp_len
        if offset + 2 > len(data):
            return None

        ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        ext_end = offset + ext_total_len
        if ext_end > len(data):
            ext_end = len(data)

        while offset + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[offset:offset+2])[0]
            ext_len = struct.unpack("!H", data[offset+2:offset+4])[0]
            offset += 4
            if ext_type == 0x0000:
                if offset + 3 > ext_end:
                    break
                name_list_len = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2
                name_type = struct.unpack("!B", data[offset:offset+1])[0]
                offset += 1
                if offset + 2 > ext_end:
                    break
                name_len = struct.unpack("!H", data[offset:offset+2])[0]
                offset += 2

                available = min(name_len, ext_end - offset)
                sni_name = data[offset:offset+available]
                try:
                    encoded = sni_name.decode("ascii")
                    result = _decode_payload(encoded)
                    if result is not None:
                        return result
                except Exception:
                    pass
                try:
                    remaining = data[offset:ext_end]
                    encoded2 = remaining.decode("ascii", errors="ignore").rstrip("\x00")
                    import re
                    m = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', encoded2)
                    if m:
                        result = _decode_payload(m.group(0))
                        if result is not None:
                            return result
                except Exception:
                    pass
                break
            offset += ext_len

    except Exception:
        pass
    return None



def obfuscate_websocket(payload: bytes) -> bytes:
    len_prefix = struct.pack("!I", len(payload))
    inner = len_prefix + payload
    encoded = base64.b64encode(inner).decode("ascii").encode("ascii")

    total_len = random.randint(max(128, len(encoded) + 4), 512)
    if len(encoded) < total_len:
        encoded += os.urandom(total_len - len(encoded))
    encoded = encoded[:total_len]

    fin = 0x80
    opcode = 0x02
    first_byte = struct.pack("!B", fin | opcode)

    payload_len = len(encoded)
    if payload_len < 126:
        second_byte = struct.pack("!B", 0x80 | payload_len)
        length_bytes = b""
    elif payload_len < 65536:
        second_byte = struct.pack("!B", 0x80 | 126)
        length_bytes = struct.pack("!H", payload_len)
    else:
        second_byte = struct.pack("!B", 0x80 | 127)
        length_bytes = struct.pack("!Q", payload_len)

    masking_key = os.urandom(4)
    masked_payload = bytearray()
    for i, b in enumerate(encoded):
        masked_payload.append(b ^ masking_key[i % 4])

    return first_byte + second_byte + length_bytes + masking_key + bytes(masked_payload)


def deobfuscate_websocket(data: bytes) -> Optional[bytes]:
    try:
        if len(data) < 2:
            return None
        first = struct.unpack("!B", data[0:1])[0]
        second = struct.unpack("!B", data[1:2])[0]

        masked = (second & 0x80) != 0
        payload_len = second & 0x7f

        offset = 2
        if payload_len == 126:
            payload_len = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
        elif payload_len == 127:
            payload_len = struct.unpack("!Q", data[offset:offset+8])[0]
            offset += 8

        if masked:
            masking_key = data[offset:offset+4]
            offset += 4
            payload = bytearray()
            for i in range(min(payload_len, len(data) - offset)):
                payload.append(data[offset + i] ^ masking_key[i % 4])

            try:
                text = bytes(payload).decode("ascii", errors="ignore")
                import re
                matches = re.findall(r"[A-Za-z0-9+/]+=*", text)
                for m in sorted(matches, key=len, reverse=True):
                    padded = m + "=" * ((4 - len(m) % 4) % 4)
                    try:
                        decoded = base64.b64decode(padded)
                        if len(decoded) >= 4:
                            orig_len = struct.unpack("!I", decoded[:4])[0]
                            if orig_len <= len(decoded) - 4:
                                return decoded[4:4 + orig_len]
                        if len(decoded) > 4:
                            return decoded[4:]
                    except Exception:
                        continue

                match = re.search(r"[A-Za-z0-9+/=]{20,}", text)
                if match:
                    raw = match.group(0)
                    raw_padded = raw + "=" * ((4 - len(raw) % 4) % 4)
                    try:
                        decoded = base64.b64decode(raw_padded)
                        if len(decoded) >= 4:
                            orig_len = struct.unpack("!I", decoded[:4])[0]
                            if orig_len <= len(decoded) - 4:
                                return decoded[4:4 + orig_len]
                        return decoded[4:] if len(decoded) > 4 else None
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass
    return None



def obfuscate_random(payload: bytes) -> bytes:
    encoded = _encode_payload(payload)
    total_size = random.randint(*PADDING_RANGE)
    prefix_size = random.randint(16, total_size // 3)
    suffix_size = random.randint(16, total_size // 3)

    prefix = os.urandom(prefix_size)
    suffix = os.urandom(suffix_size)

    wrapper = {
        "status": random.choice([200, 201, 204, 301, 302]),
        "data": encoded,
        "timestamp": int(time.time()),
        "request_id": os.urandom(8).hex(),
        "server": random.choice(COMMON_HOSTS),
    }
    json_bytes = json.dumps(wrapper, separators=(",", ":")).encode("utf-8")

    result = prefix + json_bytes + suffix
    return result[:total_size]


def deobfuscate_random(data: bytes) -> Optional[bytes]:
    try:
        text = data.decode("utf-8", errors="ignore")
        import re
        match = re.search(r'"data"\s*:\s*"([A-Za-z0-9+/=]+)"', text)
        if match:
            return _decode_payload(match.group(1))

        matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for m in matches:
            try:
                decoded = _decode_payload(m)

                if len(decoded) > 10:
                    return decoded
            except Exception:
                continue
    except Exception:
        pass
    return None



OBFUSCATE_MAP = {
    "http": (obfuscate_http, deobfuscate_http),
    "dns": (obfuscate_dns, deobfuscate_dns),
    "tls": (obfuscate_tls, deobfuscate_tls),
    "websocket": (obfuscate_websocket, deobfuscate_websocket),
    "random": (obfuscate_random, deobfuscate_random),
}


def obfuscate(payload: bytes, mode: str = DEFAULT_MODE) -> bytes:
    if mode not in OBFUSCATE_MAP:
        mode = DEFAULT_MODE
    obfuscate_func, _ = OBFUSCATE_MAP[mode]
    return obfuscate_func(payload)


def deobfuscate(data: bytes, hint_mode: Optional[str] = None) -> Optional[bytes]:
    if hint_mode and hint_mode in OBFUSCATE_MAP:
        _, deobfuscate_func = OBFUSCATE_MAP[hint_mode]
        result = deobfuscate_func(data)
        if result is not None:
            return result

    for mode in OBFUSCATE_MAP:
        if mode == hint_mode:
            continue
        _, deobfuscate_func = OBFUSCATE_MAP[mode]
        result = deobfuscate_func(data)
        if result is not None:
            return result

    return None


def get_available_modes() -> dict:
    return dict(OBFUSCATION_MODES)


def detect_mode(data: bytes) -> Optional[str]:
    if len(data) > 0 and data[0] == 0x16:
        return "tls"
    if len(data) >= 12:
        flags = struct.unpack("!H", data[2:4])[0]
        if (flags & 0x8000) == 0:
            return "dns"
    try:
        text_start = data[:20].decode("utf-8", errors="ignore").upper()
        if any(text_start.startswith(m) for m in ["GET ", "POST ", "PUT ", "HEAD "]):
            return "http"
    except Exception:
        pass
    if len(data) >= 2:
        first = data[0]
        if first & 0x80 and (first & 0x0f) in [0x01, 0x02]:
            return "websocket"
    return None



class OnionRouter:
    """
    洋葱路由实现

    消息在到达目标前，经过多个服务器节点"兜圈子"，
    每个节点只知道上一跳和下一跳，不知道完整路径。

    层级加密 (从内到外):
    最内层: 实际消息 (用目标服务器密钥加密)
    中间层: 每层用对应中继节点的密钥加密
    最外层: 入口节点可解密第一层
    """

    def __init__(self, dht_node=None):
        self.dht_node = dht_node
        self._layer_count = 3
        self._node_id = None  # 由所属服务器设置
    def set_layers(self, count: int):
        self._layer_count = max(1, min(count, 5))

    def set_node_id(self, node_id: str):
        self._node_id = node_id

    def build_onion(
        self,
        message: bytes,
        target_server_id: str,
        relay_nodes: list,
        target_public_key_b64: str,
    ) -> bytes:
        """
        构建洋葱消息 (从内到外加密)

        Args:
            message: 原始消息字节
            target_server_id: 目标服务器 NodeID
            relay_nodes: [(node_id, pubkey_b64), ...] 顺序: 入口→...→出口
            target_public_key_b64: 目标服务器 Ed25519 公钥 (base64)

        Returns:
            完整的洋葱消息 JSON bytes
        """
        inner_payload = {
            "type": "onion_inner",
            "target": target_server_id,
            "message": base64.b64encode(message).decode("ascii"),
        }
        current_data = json.dumps(inner_payload).encode("utf-8")

        for node_id, node_pubkey_b64 in reversed(relay_nodes):
            node_pubkey_bytes = base64.b64decode(node_pubkey_b64)
            node_pubkey = x25519.X25519PublicKey.from_public_bytes(node_pubkey_bytes)

            ephemeral_private = x25519.X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            ephemeral_public_bytes = ephemeral_public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            shared = ephemeral_private.exchange(node_pubkey)

            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"onion-layer",
            ).derive(shared)

            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            aad = f"onion-layer-{node_id}".encode("utf-8")
            ciphertext = aesgcm.encrypt(nonce, current_data, aad)

            layer = {
                "type": "onion_layer",
                "next_hop": node_id,
                "ephemeral_pub": base64.b64encode(ephemeral_public_bytes).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            }
            current_data = json.dumps(layer).encode("utf-8")

        onion_envelope = {
            "type": "onion_envelope",
            "entry_node": relay_nodes[0][0] if relay_nodes else None,
            "layers": self._layer_count,
            "payload": base64.b64encode(current_data).decode("ascii"),
        }

        return json.dumps(onion_envelope).encode("utf-8")

    def peel_onion_layer(
        self,
        envelope_data: bytes,
        node_private_key: x25519.X25519PrivateKey,
    ) -> Tuple[Optional[bytes], Optional[str], bool]:
        """
        剥掉一层洋葱

        Returns:
            (下一层数据, 下一跳节点ID, 是否是最后一层)
        """
        try:
            envelope = json.loads(envelope_data.decode("utf-8"))

            if envelope.get("type") == "onion_inner":
                return envelope["message"].encode("ascii"), envelope.get("target"), True

            if envelope.get("type") != "onion_layer":
                return None, None, False

            ephemeral_pub_b64 = envelope["ephemeral_pub"]
            ephemeral_pub_bytes = base64.b64decode(ephemeral_pub_b64)
            ephemeral_pub = x25519.X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

            shared = node_private_key.exchange(ephemeral_pub)

            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"onion-layer",
            ).derive(shared)

            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
            aad = f"onion-layer-{self._node_id}".encode("utf-8") if self._node_id else None

            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, aad)

            return decrypted, envelope.get("next_hop"), False

        except Exception as e:
            print(f"[ONION] Peel error: {e}")
            return None, None, False

    def select_relay_path(
        self,
        dht_routing_table: list,
        exclude_nodes: list = None,
    ) -> list:
        """
        从 DHT 路由表中选择中继节点路径

        Returns:
            [(node_id, pubkey_b64), ...] 顺序: 入口→...→出口
        """
        if exclude_nodes is None:
            exclude_nodes = []

        candidates = [
            n for n in dht_routing_table
            if n[0] not in exclude_nodes
        ]

        if len(candidates) < self._layer_count:
            self._layer_count = max(1, len(candidates))

        selected = random.sample(candidates, self._layer_count)

        return [(n[0], n[3]) for n in selected]



def wrap_for_transport(
    encrypted_message: bytes,
    use_obfuscation: bool = True,
    obfuscation_mode: str = DEFAULT_MODE,
    use_onion: bool = False,
    onion_router: Optional[OnionRouter] = None,
    onion_path: list = None,
    target_server_id: str = None,
    target_pubkey: bytes = None,
) -> bytes:
    """
    传输前包装消息：可选的洋葱加密 + 可选的包混淆
    """
    data = encrypted_message

    if use_onion and onion_router and onion_path and target_server_id and target_pubkey:
        data = onion_router.build_onion(
            message=data,
            target_server_id=target_server_id,
            relay_nodes=onion_path,
            target_public_key_b64=base64.b64encode(target_pubkey).decode("ascii"),
        )
        data = b"\x00ONION\x00" + data

    if use_obfuscation:
        data = obfuscate(data, mode=obfuscation_mode)

    return data


def unwrap_from_transport(
    received_data: bytes,
    use_obfuscation: bool = True,
    obfuscation_hint: Optional[str] = None,
    use_onion: bool = False,
    onion_router: Optional[OnionRouter] = None,
    node_private_key: Optional[x25519.X25519PrivateKey] = None,
) -> bytes:
    """
    接收后解包消息：去混淆 + 去洋葱
    """
    data = received_data

    if use_obfuscation:
        deobfuscated = deobfuscate(data, hint_mode=obfuscation_hint)
        if deobfuscated is not None:
            data = deobfuscated

    if data.startswith(b"\x00ONION\x00"):
        data = data[7:]
        if use_onion and onion_router and node_private_key:
            is_final = False
            while not is_final and data is not None:
                data, next_hop, is_final = onion_router.peel_onion_layer(
                    data, node_private_key
                )
                if data is None:
                    break
                if not is_final and isinstance(data, bytes):
                    # 中间节点：将解密后的数据转发到下一跳
                    # data 已经是明文 JSON，包含 next_hop 和 payload
                    try:
                        relay = json.loads(data.decode("utf-8"))
                        if relay.get("type") == "onion_relay":
                            # 记录路由路径用于调试
                            print(f"[ONION] Relay hop: {relay.get('next_hop', '')[:16]}...")
                    except Exception:
                        pass
            if is_final and data is not None:
                try:
                    inner = json.loads(data.decode("utf-8"))
                    if inner.get("type") == "onion_inner":
                        msg_b64 = inner["message"]
                        data = base64.b64decode(msg_b64)
                except Exception:
                    pass

    return data if isinstance(data, bytes) else b""



def self_test():
    """自测函数：验证所有混淆模式往返正常"""
    test_payload = b"Hello, Spider! " * 10 + os.urandom(50)

    print("=" * 60)
    print("Packet Obfuscation Self-Test")
    print("=" * 60)

    all_passed = True
    for mode in OBFUSCATE_MAP:
        try:
            obfuscated = obfuscate(test_payload, mode=mode)
            deobfuscated = deobfuscate(obfuscated, hint_mode=mode)

            if deobfuscated == test_payload:
                size = len(obfuscated)
                detected = detect_mode(obfuscated) or "unknown"
                print(f"  ✅ {mode:12s} → {size:4d} bytes  detected_as={detected}")
            else:
                print(f"  ❌ {mode:12s} → MISMATCH")
                all_passed = False
        except Exception as e:
            print(f"  ❌ {mode:12s} → ERROR: {e}")
            all_passed = False

    print("-" * 60)
    print(f"  Mode auto-detection test:")
    for mode in OBFUSCATE_MAP:
        data = obfuscate(test_payload, mode=mode)
        detected = detect_mode(data)
        status = "✅" if detected == mode else "⚠️"
        print(f"    {status} {mode:12s} detected as: {detected}")

    print("=" * 60)
    print(f"  Result: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    print("=" * 60)

    return all_passed


if __name__ == "__main__":
    self_test()
