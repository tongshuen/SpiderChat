"""
Spider — UDP 发现模块

发现：
1. Spider 服务器（通过 SERVER_ANNOUNCE 广播）
2. P2P 对端（通过 DC_ANNOUNCE 广播）
3. 支持可配置端口（非硬编码）

使用 UDP 组播/广播在本地网络上工作。
"""

import socket
import json
import threading
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.protocol import *


class UDPDiscovery:
    """
    监听局域网上的 Spider 服务器/对端通告。
    也可主动探测网络。
    """

    def __init__(self, broadcast_port: int = DEFAULT_UDP_PORT,
                 dc_port: int = DEFAULT_DIRECT_CONNECT_PORT):
        self.broadcast_port = broadcast_port
        self.dc_port = dc_port
        self._sock = None
        self._running = False
        self._thread = None
        self.on_server_found: callable = None
        self.on_peer_found: callable = None
        self._discovered_servers: dict = {}
        self._discovered_peers: dict = {}


    def start_listening_servers(self):
        """启动服务器通告的后台监听器。"""
        self._running = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(("", self.broadcast_port))
        except OSError:
            self.broadcast_port += 1
            self._sock.bind(("", self.broadcast_port))
        self._sock.settimeout(1.0)
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()

    def discover_servers(self, timeout: float = 3.0) -> list:
        """
        通过发送 DISCOVER 并收集回复来主动发现服务器。
    返回服务器信息字典列表。
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)


        discover_msg = json.dumps({
            "type": "DISCOVER",
            "software": SOFTWARE_NAME,
            "version": SOFTWARE_VERSION,
            "timestamp": int(time.time()),
        }).encode("utf-8")

        sock.sendto(discover_msg, ("<broadcast>", self.broadcast_port))

        for addr in ["192.168.1.255", "192.168.0.255", "10.0.0.255"]:
            try:
                sock.sendto(discover_msg, (addr, self.broadcast_port))
            except:
                pass

        start = time.time()
        results = []
        seen = set()

        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(65536)
                msg = json.loads(data.decode("utf-8"))
                if msg.get("type") in (SERVER_ANNOUNCE, DISCOVER_REPLY):
                    nid = msg.get("node_id", "")
                    if nid and nid not in seen:
                        seen.add(nid)
                        info = {
                            "node_id": nid,
                            "host": msg.get("host", addr[0]),
                            "tcp_port": msg.get("tcp_port", DEFAULT_TCP_PORT),
                            "dht_port": msg.get("dht_port", DEFAULT_DHT_PORT),
                            "p2p_port": msg.get("p2p_port", self.dc_port),
                            "name": msg.get("name", "Unknown"),
                            "hidden": msg.get("hidden", False),
                            "software": msg.get("software", ""),
                            "from_addr": addr[0],
                        }
                        results.append(info)
                        self._discovered_servers[nid] = info
                        if self.on_server_found:
                            self.on_server_found(info)
            except socket.timeout:
                break
            except Exception:
                continue

        sock.close()


        for nid, info in self._discovered_servers.items():
            if nid not in seen:
                results.append(info)
                seen.add(nid)

        return results


    def discover_peers(self, timeout: float = 3.0, port: int = None) -> list:
        """
        通过 DC_ANNOUNCE 发现局域网上的 P2P 对端。
        """
        if port is None:
            port = self.dc_port + 1

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)


        msg = json.dumps({
            "type": "DC_DISCOVER",
            "software": SOFTWARE_NAME,
            "timestamp": int(time.time()),
        }).encode("utf-8")

        sock.sendto(msg, ("<broadcast>", port))

        start = time.time()
        results = []
        seen = set()

        while time.time() - start < timeout:
            try:
                data, addr = sock.recvfrom(65536)
                msg = json.loads(data.decode("utf-8"))
                if msg.get("type") in ("DC_ANNOUNCE", "DC_NODE_INFO"):
                    nid = msg.get("node_id", "")
                    if nid and nid not in seen:
                        seen.add(nid)
                        info = {
                            "node_id": nid,
                            "uuid": msg.get("uuid", ""),
                            "ed25519_pub": msg.get("ed25519_pub", ""),
                            "x25519_pub": msg.get("x25519_pub", ""),
                            "address": f"{addr[0]}:{msg.get('port', self.dc_port)}",
                            "port": msg.get("port", self.dc_port),
                            "host": addr[0],
                            "connect_type": "lan",
                            "software": msg.get("software", ""),
                        }
                        results.append(info)
                        self._discovered_peers[nid] = info
                        if self.on_peer_found:
                            self.on_peer_found(info)
            except socket.timeout:
                break
            except Exception:
                continue

        sock.close()
        return results


    def _listen_loop(self):
        """所有 UDP 通告的后台监听器。"""
        while self._running and self._sock:
            try:
                data, addr = self._sock.recvfrom(65536)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_packet(self, data: bytes, addr: tuple):
        try:
            msg = json.loads(data.decode("utf-8"))
        except:
            return

        msg_type = msg.get("type")


        if msg_type == SERVER_ANNOUNCE:
            info = {
                "node_id": msg.get("node_id", ""),
                "host": msg.get("host", addr[0]),
                "tcp_port": msg.get("tcp_port", DEFAULT_TCP_PORT),
                "dht_port": msg.get("dht_port", DEFAULT_DHT_PORT),
                "p2p_port": msg.get("p2p_port", self.dc_port),
                "name": msg.get("name", "Unknown"),
                "hidden": msg.get("hidden", False),
                "software": msg.get("software", ""),
                "from_addr": addr[0],
            }
            if info["node_id"]:
                self._discovered_servers[info["node_id"]] = info
                if self.on_server_found:
                    self.on_server_found(info)

        elif msg_type == DC_ANNOUNCE:
            info = {
                "node_id": msg.get("node_id", ""),
                "uuid": msg.get("uuid", ""),
                "ed25519_pub": msg.get("ed25519_pub", ""),
                "x25519_pub": msg.get("x25519_pub", ""),
                "address": f"{addr[0]}:{msg.get('port', self.dc_port)}",
                "port": msg.get("port", self.dc_port),
                "host": addr[0],
                "connect_type": "lan",
                "software": msg.get("software", ""),
            }
            if info["node_id"]:
                self._discovered_peers[info["node_id"]] = info
                if self.on_peer_found:
                    self.on_peer_found(info)


    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except:
                pass


    def get_discovered_servers(self) -> list:
        return list(self._discovered_servers.values())

    def get_discovered_peers(self) -> list:
        return list(self._discovered_peers.values())

    def clear(self):
        self._discovered_servers.clear()
        self._discovered_peers.clear()
