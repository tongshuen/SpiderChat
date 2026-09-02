"""
Spider 服务端 — 主入口

启动所有服务端组件：
- DHT 节点（Kademlia UDP）
- 聊天 TCP 服务端（客户端连接 + 中继）
- 跨服务器中继（服务器间 TCP）
- UDP 局域网广播发现
- P2P 节点（客户端也可作为微型服务端）
- 全数据包传输加密
- 可选包混淆 + 洋葱路由
- 管理员接口

支持模式：
- 有显示器：tkinter 弹窗交互
- 无显示器（headless）：环境变量 / CLI 参数 / stdin
"""

import sys
import os
import time
import json
import threading
import signal
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server.config.loader import load_config, get_data_dir
from server.keyring_store.credentials import (
    get_server_keys, verify_admin_pin, get_node_id,
)
from server.keyring_store.backend import check_keyring_or_exit, detect_headless
from server.dht.node import DHTNode
from server.dht.bootstrap import load_guide as read_guide_file
from server.chat.server import ChatServer
from server.chat.cross_server import CrossServerRelay
from server.chat.group import GroupManager
from server.discovery.broadcast import UDPBroadcast
from server.logs.logger import get_logger
from server.p2p import P2PNode, SecureTransport, TransportConfig
from shared.protocol import (
    DEFAULT_DHT_PORT, DEFAULT_INTERSERVER_PORT, DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT, DEFAULT_DIRECT_CONNECT_PORT,
    DEFAULT_OBFUSCATION_MODE, TRANSPORT_KEY_ROTATION_SEC,
)

SOFTWARE_NAME = "Spider"
SOFTWARE_VERSION = "1.0.0"
MAX_DIRECT_CONNECTIONS = 50


def parse_args():
    """解析命令行参数（无显示器环境优先使用）"""
    parser = argparse.ArgumentParser(
        description=f"{SOFTWARE_NAME} 端到端加密聊天服务端"
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="配置文件路径（默认：<data_dir>/server_config.json）"
    )
    parser.add_argument(
        "--admin-pin",
        default=None,
        help="管理员 PIN（6 位数字，也可通过环境变量 SPIDER_ADMIN_PIN 设置）"
    )
    parser.add_argument(
        "--keyring-passphrase",
        default=None,
        help="keyring 主密码（无显示器模式必需，也可通过环境变量 SPIDER_KEYRING_PASSPHRASE 设置）"
    )
    parser.add_argument(
        "--host",
        default=None,
        help="绑定主机地址（覆盖配置文件中的 public_host）"
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=None,
        help="客户端 TCP 端口（覆盖配置文件）"
    )
    parser.add_argument(
        "--dht-port",
        type=int,
        default=None,
        help="DHT UDP 端口（覆盖配置文件）"
    )
    parser.add_argument(
        "--interserver-port",
        type=int,
        default=None,
        help="跨服务器 TCP 端口（覆盖配置文件）"
    )
    parser.add_argument(
        "--hidden",
        action="store_true",
        help="启动时进入隐藏模式（不响应非白名单 DHT 查询）"
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARN", "ERROR"],
        default=None,
        help="日志级别"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="禁用彩色日志输出（适合写入文件）"
    )
    return parser.parse_args()


def apply_env_overrides(config, args):
    """环境变量和 CLI 参数覆盖配置"""
    # keyring 主密码
    passphrase = args.keyring_passphrase or os.environ.get("SPIDER_KEYRING_PASSPHRASE")
    if passphrase:
        os.environ["SPIDER_KEYRING_PASSPHRASE"] = passphrase

    # 管理员 PIN
    pin = args.admin_pin or os.environ.get("SPIDER_ADMIN_PIN")
    if pin:
        os.environ["SPIDER_ADMIN_PIN"] = pin

    # CLI 覆盖
    if args.host:
        config["public_host"] = args.host
    if args.tcp_port:
        config["tcp_port"] = args.tcp_port
    if args.dht_port:
        config["dht_port"] = args.dht_port
    if args.interserver_port:
        config["interserver_port"] = args.interserver_port
    if args.hidden:
        config["hidden_mode"] = True
    if args.log_level:
        config.setdefault("logging", {})["level"] = args.log_level

    return config


def print_startup_banner(config, node_id, headless):
    """打印启动横幅"""
    mode = "headless（无显示器）" if headless else "GUI（有显示器）"
    hidden = config.get("hidden_mode", False)
    obf = config.get("obfuscation_mode", DEFAULT_OBFUSCATION_MODE)
    onion = config.get("onion_enabled", False)

    print()
    print("=" * 60)
    print(f"  {SOFTWARE_NAME} Server v{SOFTWARE_VERSION}")
    print(f"  运行模式: {mode}")
    print(f"  NodeID:  {node_id[:24]}...")
    print(f"  隐藏模式: {'是' if hidden else '否'}")
    print(f"  传输加密: AES-256-GCM (全包加密)")
    print(f"  包混淆:   {obf}")
    print(f"  洋葱路由: {'启用' if onion else '禁用'}")
    print("=" * 60)
    print()


def main():
    args = parse_args()
    headless = detect_headless()

    print_startup_banner({"hidden_mode": False}, "pending...", headless)

    # 1. 检查 keyring 可用性
    check_keyring_or_exit()

    # 2. 加载配置 + 应用覆盖
    config = load_config(args.config)
    config = apply_env_overrides(config, args)

    data_dir = get_data_dir()
    print(f"[{SOFTWARE_NAME}] 数据目录: {data_dir}")
    print(f"[{SOFTWARE_NAME}] 配置已加载")

    # 3. 获取密钥
    keys = get_server_keys()
    node_id = get_node_id()
    print(f"[{SOFTWARE_NAME}] NodeID: {node_id[:24]}...")

    # 4. 初始化日志
    logger = get_logger(config)

    # 5. 启动 DHT 节点
    dht_config = config.get("dht", {})
    dht_port = config.get("dht_port", DEFAULT_DHT_PORT)
    hidden = config.get("hidden_mode", False)
    whitelist = config.get("dht_whitelist", [])

    dht_node = DHTNode(
        node_id=node_id,
        host="0.0.0.0",
        dht_port=dht_port,
        config=dht_config,
        hidden=hidden,
        whitelist=whitelist,
    )
    dht_node.start()
    logger.info(f"DHT 节点已启动，UDP 端口: {dht_port}")

    # 6. 引导
    guide_path = os.path.join(data_dir, "guide.txt")
    bootstrap_nodes = read_guide_file(guide_path)
    if bootstrap_nodes:
        logger.info(f"从 {len(bootstrap_nodes)} 个引导节点启动...")
        found = dht_node.bootstrap(bootstrap_nodes)
        logger.info(f"引导完成，发现 {found} 个可达节点")
    else:
        logger.info("未找到 guide.txt，作为种子节点启动")

    # 7. 跨服务器中继
    interserver_port = config.get("interserver_port", DEFAULT_INTERSERVER_PORT)
    cross_server = CrossServerRelay(config, dht_node=dht_node)
    cross_server.start(listen_port=interserver_port)
    logger.info(f"跨服务器中继已启动，TCP 端口: {interserver_port}")

    # 8. 聊天服务端
    tcp_port = config.get("tcp_port", DEFAULT_TCP_PORT)
    chat_server = ChatServer(config)
    chat_server.set_dht_node(dht_node)
    chat_server.set_cross_server(cross_server)
    cross_server.chat_server = chat_server

    # 9. P2P 节点
    p2p_config = {
        "port": config.get("p2p_port", config.get("direct_connect_port", DEFAULT_DIRECT_CONNECT_PORT)),
        "max_peers": config.get("p2p_max_peers", MAX_DIRECT_CONNECTIONS),
        "host": "0.0.0.0",
        "key_rotation_sec": config.get("transport_key_rotation_sec", TRANSPORT_KEY_ROTATION_SEC),
    }
    p2p_identity = {
        "uuid": f"server-{node_id[:8]}",
        "ed25519_priv": keys["server_ed25519_priv"],
        "ed25519_pub": keys["server_ed25519_pub"],
        "x25519_priv": keys["server_x25519_priv"],
        "x25519_pub": keys["server_x25519_pub"],
    }
    p2p_node = P2PNode(p2p_identity, p2p_config)
    p2p_node.start()
    logger.info(f"P2P 节点已启动，TCP 端口: {p2p_config['port']}")

    # 10. UDP 广播
    udp_port = config.get("udp_port", DEFAULT_UDP_PORT)
    broadcast = UDPBroadcast(
        udp_port=udp_port,
        tcp_port=tcp_port,
        node_id=node_id,
        server_name=config.get("server_name", f"{SOFTWARE_NAME} Server"),
    )
    broadcast.start()
    logger.info(f"UDP 广播已启动，端口: {udp_port}")

    # 11. DHT 宣告
    server_info = json.dumps({
        "node_id": node_id,
        "host": config.get("public_host", ""),
        "tcp_port": tcp_port,
        "interserver_port": interserver_port,
        "dht_port": dht_port,
        "p2p_port": p2p_config["port"],
        "name": config.get("server_name", f"{SOFTWARE_NAME} Server"),
        "software": SOFTWARE_NAME,
        "version": SOFTWARE_VERSION,
        "started_at": int(time.time()),
        "headless": headless,
    })
    dht_node.store(f"server:{node_id}", server_info, ttl=7200)

    # 12. 打印状态
    print()
    print(f"[{SOFTWARE_NAME}] 聊天服务已就绪，TCP 端口: {tcp_port}")
    print(f"[{SOFTWARE_NAME}] 服务器名称: {config.get('server_name', 'Spider Server')}")
    print(f"[{SOFTWARE_NAME}] 隐藏模式: {'开启' if hidden else '关闭'}")
    print(f"[{SOFTWARE_NAME}] 传输加密: 开启 (AES-256-GCM)")
    print(f"[{SOFTWARE_NAME}] 包混淆: {config.get('obfuscation_mode', DEFAULT_OBFUSCATION_MODE)}")
    print(f"[{SOFTWARE_NAME}] 洋葱路由: {'开启' if config.get('onion_enabled') else '关闭'}")
    print(f"[{SOFTWARE_NAME}] 按 Ctrl+C 停止服务")
    print()

    # 13. 信号处理
    def signal_handler(sig, frame):
        print(f"\n[{SOFTWARE_NAME}] 收到停止信号...")
        logger.info("收到停止信号，正在关闭...")
        chat_server.stop()
        dht_node.stop()
        cross_server.stop()
        p2p_node.stop()
        broadcast.stop()
        logger.info("所有组件已停止")
        print(f"[{SOFTWARE_NAME}] 所有组件已停止。再见！")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # 14. 主循环
    try:
        chat_server.start()
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
