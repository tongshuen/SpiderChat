"""
管理面板 — 服务器管理界面。
核心管理 UI 内置于 MainWindow._build_admin_panel_*。
本模块提供独立的辅助函数和命令定义。
"""

from shared.protocol import *



ADMIN_COMMANDS = {
    CMD_LIST_ONLINE: "查看在线用户",
    CMD_LIST_ALL_USERS: "查看所有用户",
    CMD_BAN_USER: "封禁用户",
    CMD_UNBAN_USER: "解封用户",
    CMD_KICK_USER: "踢下线",
    CMD_CREATE_USER: "创建用户",
    CMD_DELETE_USER: "删除用户",
    CMD_USER_INFO: "查看用户详情",
    CMD_SET_HIDDEN: "设置隐藏模式",
    CMD_ADD_DHT_WHITELIST: "添加DHT白名单",
    CMD_REMOVE_DHT_WHITELIST: "移除DHT白名单",
    CMD_DHT_ROUTING_TABLE: "查看路由表",
    CMD_DHT_NODE_COUNT: "DHT节点数",
    CMD_ADD_BOOTSTRAP: "添加引导节点",
    CMD_DHT_DISCONNECT: "断开DHT节点",

    CMD_SET_RATE_LIMIT: "设置全局限速",
    CMD_SET_USER_RATE: "设置用户限速",
    CMD_SET_RATE_BURST: "设置burst容量",
    CMD_RATE_LIMIT_STATUS: "限速状态",
    CMD_MUTE_USER: "禁言用户",

    CMD_SET_MAX_FILE_SIZE: "设置最大文件",
    CMD_SET_FILE_RETENTION: "设置文件保留期",
    CMD_FILE_STATS: "文件统计",
    CMD_CLEANUP_FILES: "清理文件",
    CMD_SET_FILE_ENABLED: "开关文件传输",
    CMD_CHANGE_ADMIN_PIN: "修改管理员PIN",
    CMD_GET_LOGS: "查看日志",
    CMD_SET_LOG_LEVEL: "设置日志级别",
    CMD_CONN_STATS: "连接统计",
    CMD_BROADCAST_MSG: "广播通知",
    CMD_MAINTENANCE_MODE: "维护模式",
    CMD_SHUTDOWN: "优雅关机",
    CMD_FORCE_SHUTDOWN: "强制关机",
    CMD_RELOAD_CONFIG: "重载配置",
    CMD_SET_SERVER_NAME: "设置服务器名",
    CMD_SET_MAX_CONNECTIONS: "最大连接数",
    CMD_SET_MIN_CLIENT_VERSION: "最低客户端版本",
}


def get_command_help(cmd: str) -> str:
    """获取管理员命令的中文描述。"""
    return ADMIN_COMMANDS.get(cmd, "未知命令")
