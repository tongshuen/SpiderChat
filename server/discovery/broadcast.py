"""
UDP 广播 — 在局域网上通告服务器存在。
客户端无需手动配置即可发现服务器。
"""

import socket
import json
import threading
import time


class UDPBroadcast:
    """在局域网上广播服务器信息并监听客户端发现请求。"""

    def __init__(self, udp_port: int, tcp_port: int, node_id: str,
                 server_name: str = "E2EE Server"):
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.node_id = node_id
        self.server_name = server_name
        self._sock = None
        self._running = False
        self._thread = None
        self._listen_thread = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._running = True


        self._thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self._thread.start()


        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listen_thread.start()

        print(f"[BROADCAST] UDP broadcast active on port {self.udp_port}")

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except:
                pass

    def _broadcast_loop(self):
        """定期广播服务器通告。"""
        bc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        bc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        bc_sock.settimeout(1.0)

        while self._running:
            try:
                msg = json.dumps({
                    "type": "SERVER_ANNOUNCE",
                    "node_id": self.node_id,
                    "tcp_port": self.tcp_port,
                    "name": self.server_name,
                    "timestamp": int(time.time()),
                })
                bc_sock.sendto(msg.encode(), ("<broadcast>", self.udp_port))
                time.sleep(10)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[BROADCAST] Error: {e}")
                time.sleep(5)

        try:
            bc_sock.close()
        except:
            pass

    def _listen_loop(self):
        """监听客户端发现请求。"""
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock.bind(("", self.udp_port))
        except Exception as e:
            print(f"[BROADCAST] Bind failed: {e}")
            return

        listen_sock.settimeout(1.0)
        while self._running:
            try:
                data, addr = listen_sock.recvfrom(4096)
                try:
                    msg = json.loads(data.decode())
                except:
                    continue

                if msg.get("type") == "CLIENT_DISCOVER":
                    response = json.dumps({
                        "type": "SERVER_REPLY",
                        "node_id": self.node_id,
                        "tcp_port": self.tcp_port,
                        "name": self.server_name,
                        "timestamp": int(time.time()),
                    })
                    listen_sock.sendto(response.encode(), addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    print(f"[BROADCAST] Listen error: {e}")

        try:
            listen_sock.close()
        except:
            pass
