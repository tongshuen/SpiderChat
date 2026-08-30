"""
死人开关（Dead Man's Switch）客户端管理。

功能：
- 管理死人开关配置（开关、警告消息、收件人、宽限期）
- 在登录、编辑警告消息、编辑收件人时，将最新警告消息同步到服务器
- 服务器将其作为特殊离线消息存储，到期用户未登录时先推送警告再执行胁迫操作

这样哪怕客户端炸了，警告消息也能按时发送。
"""
import time
from client.utils.config import load_config, save_config


class DeadmanManager:
    """死人开关客户端管理器。"""

    def __init__(self, tcp_client=None, get_uuid=None):
        """
        Args:
            tcp_client: 已连接的 TCPClient 实例（用于发送 STORE_DEADMAN_MSG）
            get_uuid: 回调函数，返回当前用户 UUID
        """
        self.tcp_client = tcp_client
        self.get_uuid = get_uuid
        self._last_sync_time = 0
        self._sync_in_progress = False

    def is_enabled(self) -> bool:
        """死人开关是否启用。"""
        cfg = load_config()
        return cfg.get("deadman_enabled", False)

    def get_config(self) -> dict:
        """获取死人开关完整配置。"""
        cfg = load_config()
        return {
            "enabled": cfg.get("deadman_enabled", False),
            "warning_message": cfg.get("deadman_warning_message", ""),
            "recipient_uuid": cfg.get("deadman_recipient_uuid", ""),
            "grace_days": cfg.get("deadman_grace_days", 7),
        }

    def set_config(self, enabled: bool = None, warning_message: str = None,
                   recipient_uuid: str = None, grace_days: int = None,
                   auto_sync: bool = True) -> bool:
        """
        更新死人开关配置。
        更新后自动同步到服务器（如果启用且已连接）。

        Args:
            enabled: 是否启用
            warning_message: 警告消息内容
            recipient_uuid: 预定收件人 UUID
            grace_days: 宽限期（天）
            auto_sync: 是否自动同步到服务器

        Returns:
            True 表示配置已保存，False 表示验证失败
        """
        cfg = load_config()

        if enabled is not None:
            cfg["deadman_enabled"] = bool(enabled)
        if warning_message is not None:
            cfg["deadman_warning_message"] = warning_message
        if recipient_uuid is not None:
            cfg["deadman_recipient_uuid"] = recipient_uuid
        if grace_days is not None:
            grace_days = int(grace_days)
            if grace_days < 1:
                grace_days = 1
            if grace_days > 365:
                grace_days = 365
            cfg["deadman_grace_days"] = grace_days

        save_config(cfg)

        # 如果启用了且配置完整，自动同步到服务器
        if auto_sync and cfg.get("deadman_enabled"):
            self.sync_to_server()

        return True

    def is_config_complete(self) -> bool:
        """检查配置是否完整（启用时需要警告消息和收件人）。"""
        cfg = self.get_config()
        if not cfg["enabled"]:
            return True
        return bool(cfg["warning_message"] and cfg["recipient_uuid"])

    def sync_to_server(self) -> bool:
        """
        将最新的死人开关警告消息同步到服务器。
        在登录、编辑警告消息、编辑收件人时调用。

        服务器行为：
        - 作为特殊离线消息存储
        - 删除上一条旧的警告消息（如有）
        - 暂时不推送给其他用户
        - 到期用户未登录时，先推送给预定收件人再执行胁迫操作

        Returns:
            True 表示已发送，False 表示未发送（未启用/未连接/配置不完整）
        """
        if self._sync_in_progress:
            return False

        cfg = self.get_config()
        if not cfg["enabled"]:
            return False
        if not cfg["warning_message"] or not cfg["recipient_uuid"]:
            print("[DEADMAN] 配置不完整，跳过同步（需要警告消息和收件人）")
            return False
        if not self.tcp_client:
            print("[DEADMAN] 未连接服务器，跳过同步")
            return False

        uuid_str = ""
        if self.get_uuid:
            uuid_str = self.get_uuid()
        if not uuid_str:
            print("[DEADMAN] 无法获取 UUID，跳过同步")
            return False

        grace_period_sec = int(cfg["grace_days"]) * 86400

        self._sync_in_progress = True
        try:
            self.tcp_client.send_deadman_message(
                uuid_str=uuid_str,
                recipient_uuid=cfg["recipient_uuid"],
                message_text=cfg["warning_message"],
                grace_period_sec=grace_period_sec,
            )
            self._last_sync_time = time.time()
            print(f"[DEADMAN] 警告消息已同步到服务器 "
                  f"(收件人={cfg['recipient_uuid'][:16]}..., 宽限={cfg['grace_days']}天)")
            return True
        except Exception as e:
            print(f"[DEADMAN] 同步失败: {e}")
            return False
        finally:
            self._sync_in_progress = False

    def get_last_sync_time(self) -> float:
        """获取上次同步时间戳。"""
        return self._last_sync_time

    def get_status_summary(self) -> str:
        """获取死人开关状态摘要。"""
        cfg = self.get_config()
        if not cfg["enabled"]:
            return "死人开关：未启用"
        status = f"死人开关：已启用，宽限 {cfg['grace_days']} 天"
        if cfg["warning_message"]:
            preview = cfg["warning_message"][:30]
            if len(cfg["warning_message"]) > 30:
                preview += "..."
            status += f"，警告消息：\"{preview}\""
        if cfg["recipient_uuid"]:
            status += f"，收件人：{cfg['recipient_uuid'][:16]}..."
        if self._last_sync_time:
            elapsed = int(time.time() - self._last_sync_time)
            status += f"，上次同步：{elapsed}秒前"
        return status
