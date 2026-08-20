"""
管理员命令处理器 — 处理所有 ADMIN_CMD 消息。
"""

import time
import json
import threading
import sys
import os
from shared.protocol import *


class AdminCommandHandler:
    """将管理员命令路由到相应子系统。"""

    def __init__(self, chat_server, config: dict):
        self.server = chat_server
        self.config = config
        self.user_mgr = chat_server.user_manager
        self.rate_limiter = chat_server.rate_limiter
        self.offline_store = chat_server.offline_store

    def execute(self, command: str, params: dict, conn) -> dict:
        """执行管理员命令并返回结果字典。"""
        try:
            if command == CMD_LIST_ONLINE:
                users = self.user_mgr.list_online_users()
                return {"count": len(users), "users": users}

            elif command == CMD_LIST_ALL_USERS:
                users = self.user_mgr.list_all_users()
                return {"count": len(users), "users": users}

            elif command == CMD_BAN_USER:
                uuid_str = params.get("uuid", "")
                reason = params.get("reason", "")
                ok = self.user_mgr.ban_user(uuid_str)
                if uuid_str in self.server.connections:
                    try:
                        self.server.connections[uuid_str].sock.close()
                    except:
                        pass
                    del self.server.connections[uuid_str]
                return {"ok": ok, "uuid": uuid_str}

            elif command == CMD_UNBAN_USER:
                uuid_str = params.get("uuid", "")
                ok = self.user_mgr.unban_user(uuid_str)
                return {"ok": ok, "uuid": uuid_str}

            elif command == CMD_KICK_USER:
                uuid_str = params.get("uuid", "")
                if uuid_str in self.server.connections:
                    try:
                        self.server.connections[uuid_str].sock.close()
                    except:
                        pass
                    del self.server.connections[uuid_str]
                    return {"ok": True}
                return {"ok": False, "reason": "Not online"}

            elif command == CMD_CREATE_USER:
                name = params.get("name", "user")
                result = self.user_mgr.create_user_for_admin(name)
                if result:
                    return {"ok": True, **result}
                return {"ok": False, "reason": "Failed to create user (MAC unavailable)"}

            elif command == CMD_DELETE_USER:
                uuid_str = params.get("uuid", "")
                ok = self.user_mgr.delete_user(uuid_str)
                return {"ok": ok}

            elif command == CMD_USER_INFO:
                uuid_str = params.get("uuid", "")
                user = self.user_mgr.get_user(uuid_str)
                if user:
                    return {"ok": True, "user": user}
                return {"ok": False, "reason": "Not found"}

            elif command == CMD_SET_HIDDEN:
                hidden = bool(params.get("hidden", False))
                self.server.dht_node.set_hidden(hidden)
                self.config.setdefault("dht", {})["hidden_mode"] = hidden
                return {"ok": True, "hidden": hidden}

            elif command == CMD_ADD_DHT_WHITELIST:
                node_id = params.get("node_id", "")
                self.server.dht_node.add_whitelist(node_id)
                return {"ok": True, "node_id": node_id}

            elif command == CMD_REMOVE_DHT_WHITELIST:
                node_id = params.get("node_id", "")
                self.server.dht_node.remove_whitelist(node_id)
                return {"ok": True}

            elif command == CMD_DHT_ROUTING_TABLE:
                return {"ok": True, "routing": self.server.dht_node.get_routing_info()}

            elif command == CMD_DHT_NODE_COUNT:
                return {"ok": True, "count": self.server.dht_node.routing_table.total_nodes()}

            elif command == CMD_ADD_BOOTSTRAP:
                host = params.get("host", "")
                port = int(params.get("port", 7892))
                found = self.server.dht_node.ping(host, port)
                return {"ok": found, "host": host, "port": port}

            elif command == CMD_DHT_DISCONNECT:
                node_id = params.get("node_id", "")
                self.server.dht_node.routing_table.remove_node(node_id)
                return {"ok": True}

            elif command == CMD_SET_RATE_LIMIT:
                seconds = float(params.get("seconds", 0.5))
                self.rate_limiter.set_global_rate(seconds)
                self.config.setdefault("rate_limit", {})["global_seconds_per_msg"] = seconds
                return {"ok": True, "seconds_per_msg": seconds}

            elif command == CMD_SET_USER_RATE:
                uuid_str = params.get("uuid", "")
                seconds = float(params.get("seconds", 0.5))
                self.rate_limiter.set_user_rate(uuid_str, seconds)
                return {"ok": True}

            elif command == CMD_SET_RATE_BURST:
                burst = int(params.get("burst", 5))
                self.rate_limiter.set_burst(burst)
                self.config.setdefault("rate_limit", {})["burst_capacity"] = burst
                return {"ok": True, "burst": burst}

            elif command == CMD_RATE_LIMIT_STATUS:
                return {"ok": True, "status": self.rate_limiter.get_status()}

            elif command == CMD_MUTE_USER:
                uuid_str = params.get("uuid", "")
                duration = int(params.get("duration_sec", 300))
                self.user_mgr.mute_user(uuid_str, duration)
                return {"ok": True, "muted_until": time.time() + duration}

            elif command == CMD_SET_MAX_FILE_SIZE:
                mb = int(params.get("mb", 100))
                self.config.setdefault("file_transfer", {})["max_file_size_mb"] = mb
                return {"ok": True, "max_mb": mb}

            elif command == CMD_SET_FILE_RETENTION:
                days = int(params.get("days", 7))
                self.config.setdefault("file_transfer", {})["retention_days"] = days
                self.offline_store.retention_days = days
                return {"ok": True, "days": days}

            elif command == CMD_FILE_STATS:
                return {"ok": True, "stats": self._file_stats()}

            elif command == CMD_CLEANUP_FILES:
                deleted = self.offline_store.cleanup_expired()
                return {"ok": True, "deleted": deleted}

            elif command == CMD_SET_FILE_ENABLED:
                enabled = bool(params.get("enabled", True))
                self.config.setdefault("file_transfer", {})["enabled"] = enabled
                return {"ok": True, "enabled": enabled}

            elif command == CMD_CHANGE_ADMIN_PIN:
                old_pin = params.get("old_pin", "")
                new_pin = params.get("new_pin", "")
                ok = self.server.admin_auth.change_pin(old_pin, new_pin)
                return {"ok": ok}

            elif command == CMD_GET_LOGS:
                lines = int(params.get("lines", 50))
                return {"ok": True, "logs": self._read_logs(lines)}

            elif command == CMD_SET_LOG_LEVEL:
                level = params.get("level", "info")
                self.config.setdefault("logging", {})["level"] = level
                return {"ok": True, "level": level}

            elif command == CMD_CONN_STATS:
                return {"ok": True, "stats": self.server.get_stats()}

            elif command == CMD_BROADCAST_MSG:
                text = params.get("text", "")
                self.server.broadcast(text)
                return {"ok": True}

            elif command == CMD_MAINTENANCE_MODE:
                mode = bool(params.get("mode", False))
                if mode:

                    self.server._maintenance_mode = True
                else:
                    self.server._maintenance_mode = False
                return {"ok": True, "maintenance": mode}

            elif command == CMD_SHUTDOWN:

                threading.Thread(target=self._graceful_shutdown, daemon=True).start()
                return {"ok": True, "message": "Shutting down..."}

            elif command == CMD_FORCE_SHUTDOWN:
                self.server.stop()
                return {"ok": True}

            elif command == CMD_RELOAD_CONFIG:

                from server.config.loader import reload_config
                new_config = reload_config()
                self.config.update(new_config)
                return {"ok": True}

            elif command == CMD_SET_SERVER_NAME:
                name = params.get("name", "")
                self.config["server_name"] = name
                return {"ok": True, "name": name}

            elif command == CMD_SET_MAX_CONNECTIONS:
                n = int(params.get("max", 1000))
                self.config.setdefault("user_management", {})["max_connections"] = n
                return {"ok": True, "max": n}

            elif command == CMD_SET_MIN_CLIENT_VERSION:
                ver = params.get("version", "1.0.0")
                self.config.setdefault("user_management", {})["min_client_version"] = ver
                return {"ok": True, "version": ver}

            else:
                return {"ok": False, "reason": f"Unknown command: {command}"}

        except Exception as e:
            return {"ok": False, "reason": str(e)}


    def _file_stats(self) -> dict:
        import os
        data_dir = os.path.dirname(self.offline_store.db_path)
        total_size = 0
        count = 0
        for f in os.listdir(data_dir):
            fp = os.path.join(data_dir, f)
            if os.path.isfile(fp) and f.startswith("file_"):
                total_size += os.path.getsize(fp)
                count += 1
        return {"count": count, "total_bytes": total_size}

    def _read_logs(self, lines: int) -> list:
        log_path = os.path.join(os.path.dirname(self.server.config.get("log_path", "server.log")), "server.log")
        if not os.path.exists(log_path):
            return []
        with open(log_path) as f:
            all_lines = f.readlines()
        return [l.strip() for l in all_lines[-lines:]]

    def _graceful_shutdown(self):
        """等待消息排空后关闭。"""
        print("[ADMIN] Graceful shutdown initiated...")

        for _ in range(30):
            if self.server.offline_store.count_pending() == 0:
                break
            time.sleep(1)
        self.server.stop()
        sys.exit(0)
