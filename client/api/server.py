"""
Spider HTTP API 服务器。

提供 REST API 让外部程序操控 Spider 客户端，功能与 GUI 一致。
- 用户自定端口
- API Key 认证（X-API-Key header）
- 细粒度权限控制
- 攻击面过宽警告（总权限>15项）

通过 AppBridge 与主 GUI 通信，不直接操作 GUI 组件。
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from client.storage.api_keys import (
    verify_api_key, has_permission, ALL_PERMISSIONS,
    is_attack_surface_warning, get_total_permission_count,
)


class AppBridge:
    """
    API 服务器与主应用之间的桥接接口。
    主窗口注册回调函数，API 服务器通过回调操作应用状态。
    所有回调返回 (success: bool, data: any, error: str)
    """

    def __init__(self):
        self._callbacks = {}

    def register(self, action, callback):
        self._callbacks[action] = callback

    def call(self, action, **kwargs):
        cb = self._callbacks.get(action)
        if not cb:
            return False, None, f"未注册的操作: {action}"
        try:
            return cb(**kwargs)
        except Exception as e:
            return False, None, str(e)


# 全局桥接实例，主窗口在启动时注册回调
bridge = AppBridge()


class APIHandler(BaseHTTPRequestHandler):
    """HTTP API 请求处理器。"""

    def log_message(self, format, *args):
        # 静默日志，避免污染控制台
        pass

    def _send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except Exception:
            return None

    def _authenticate(self, required_permission):
        """验证 API key 和权限。返回 (entry, error_response)。"""
        api_key = self.headers.get("X-API-Key", "")
        if not api_key:
            return None, (401, {"error": "缺少 X-API-Key header"})
        entry = verify_api_key(api_key)
        if not entry:
            return None, (401, {"error": "API Key 无效或已过期"})
        if not has_permission(entry, required_permission):
            return None, (403, {"error": f"权限不足，需要: {required_permission}"})
        return entry, None

    def _require_body(self):
        body = self._read_body()
        if body is None:
            self._send_json(400, {"error": "请求体不是有效的 JSON"})
            return None
        return body

    # ===== 路由 =====

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        # 无需认证的端点
        if path == "/api/info":
            self._send_json(200, {
                "name": "Spider HTTP API",
                "version": "1.0.0",
                "permissions": ALL_PERMISSIONS,
                "attack_surface_warning": is_attack_surface_warning(),
                "total_permissions": get_total_permission_count(),
            })
            return

        # 需要认证的端点
        routes = {
            "/api/messages/history": ("messages:read", "get_message_history", {"query": query}),
            "/api/contacts": ("contacts:read", "get_contacts", {}),
            "/api/profile": ("profile:read", "get_profile", {}),
            "/api/settings": ("settings:read", "get_settings", {}),
            "/api/deadman": ("deadman:read", "get_deadman_config", {}),
            "/api/groups": ("groups:read", "get_groups", {}),
        }

        # 处理带参数的路径 /api/messages/{id}, /api/contacts/{uuid}, /api/files/{id}
        if path.startswith("/api/files/"):
            file_id = path[len("/api/files/"):]
            routes[path] = ("files:download", "download_file", {"file_id": file_id})

        if path in routes:
            perm, action, kwargs = routes[path]
            entry, err = self._authenticate(perm)
            if err:
                self._send_json(err[0], err[1])
                return
            ok, data, error = bridge.call(action, **kwargs)
            self._send_json(200 if ok else 500, {"success": ok, "data": data, "error": error})
        else:
            self._send_json(404, {"error": "端点不存在"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        routes = {
            "/api/messages/send": ("messages:send", "send_message"),
            "/api/contacts": ("contacts:add", "add_contact"),
            "/api/groups": ("groups:write", "create_group"),
            "/api/files/send": ("files:send", "send_file"),
        }

        if path in routes:
            perm, action = routes[path]
            entry, err = self._authenticate(perm)
            if err:
                self._send_json(err[0], err[1])
                return
            body = self._require_body()
            if body is None:
                return
            ok, data, error = bridge.call(action, **body)
            self._send_json(200 if ok else 500, {"success": ok, "data": data, "error": error})
        else:
            self._send_json(404, {"error": "端点不存在"})

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        routes = {
            "/api/profile": ("profile:write", "update_profile"),
            "/api/settings": ("settings:write", "update_settings"),
            "/api/deadman": ("deadman:write", "update_deadman_config"),
        }

        if path in routes:
            perm, action = routes[path]
            entry, err = self._authenticate(perm)
            if err:
                self._send_json(err[0], err[1])
                return
            body = self._require_body()
            if body is None:
                return
            ok, data, error = bridge.call(action, **body)
            self._send_json(200 if ok else 500, {"success": ok, "data": data, "error": error})
        else:
            self._send_json(404, {"error": "端点不存在"})

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # /api/messages/{id}
        if path.startswith("/api/messages/"):
            msg_id = path[len("/api/messages/"):]
            entry, err = self._authenticate("messages:delete")
            if err:
                self._send_json(err[0], err[1])
                return
            ok, data, error = bridge.call("delete_message", message_id=msg_id)
            self._send_json(200 if ok else 500, {"success": ok, "data": data, "error": error})
            return

        # /api/contacts/{uuid}
        if path.startswith("/api/contacts/"):
            uuid = path[len("/api/contacts/"):]
            entry, err = self._authenticate("contacts:delete")
            if err:
                self._send_json(err[0], err[1])
                return
            ok, data, error = bridge.call("delete_contact", uuid=uuid)
            self._send_json(200 if ok else 500, {"success": ok, "data": data, "error": error})
            return

        self._send_json(404, {"error": "端点不存在"})


class APIServer:
    """API 服务器管理类。"""

    def __init__(self):
        self._server = None
        self._thread = None
        self._port = None
        self._running = False

    @property
    def is_running(self):
        return self._running

    @property
    def port(self):
        return self._port

    def start(self, port: int):
        """在指定端口启动 API 服务器。"""
        if self._running:
            return False, "API 服务器已在运行"
        try:
            self._server = HTTPServer(("127.0.0.1", port), APIHandler)
            self._port = port
            self._running = True
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return True, f"API 服务器已启动，端口: {port}"
        except OSError as e:
            return False, f"端口 {port} 无法绑定: {e}"

    def stop(self):
        """停止 API 服务器。"""
        if not self._running:
            return
        self._running = False
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        if self._thread:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None
        self._port = None


# 全局服务器实例
api_server = APIServer()
