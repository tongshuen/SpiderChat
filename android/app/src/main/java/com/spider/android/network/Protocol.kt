package com.spider.android.network

/**
 * Spider 协议常量 — 与 Python 服务端 shared/protocol.py 完全对齐。
 */
object Protocol {
    // 协议版本（整数，与服务端 PROTOCOL_VERSION = 3 对齐）
    const val PROTOCOL_VERSION = 3

    // ===== 客户端 → 服务端 =====
    const val REGISTER = "REGISTER"
    const val LOGIN = "LOGIN"
    const val SEND_MSG = "SEND_MSG"
    const val QUERY_PUBKEY = "QUERY_PUBKEY"
    const val STORE_PUBKEY = "STORE_PUBKEY"
    const val COMPROMISED = "COMPROMISED"
    const val STORE_DEADMAN_MSG = "STORE_DEADMAN_MSG"
    const val DEADMAN_ACK = "DEADMAN_ACK"
    const val ADMIN_AUTH = "ADMIN_AUTH"
    const val ADMIN_CMD = "ADMIN_CMD"
    const val SEARCH_CONTACTS = "SEARCH_CONTACTS"
    const val LOOKUP_USER = "LOOKUP_USER"
    const val PING = "PING"
    const val PONG = "PONG"
    const val DELIVERY_RECEIPT = "DELIVERY_RECEIPT"
    const val READ_RECEIPT = "READ_RECEIPT"

    // ===== 服务端 → 客户端 =====
    const val LOGIN_OK = "LOGIN_OK"
    const val LOGIN_FAIL = "LOGIN_FAIL"
    const val REGISTER_OK = "REGISTER_OK"
    const val RECV_MSG = "RECV_MSG"
    const val OFFLINE_QUEUE = "OFFLINE_QUEUE"
    const val SEND_OK = "SEND_OK"
    const val READ_RECEIPT_DISABLED = "READ_RECEIPT_DISABLED"
    const val PUBKEY_RESULT = "PUBKEY_RESULT"
    const val COMPROMISED_ACK = "COMPROMISED_ACK"
    const val ADMIN_AUTH_OK = "ADMIN_AUTH_OK"
    const val ADMIN_AUTH_FAIL = "ADMIN_AUTH_FAIL"
    const val CMD_RESULT = "CMD_RESULT"
    const val BROADCAST = "BROADCAST"
    const val RATE_LIMITED = "RATE_LIMITED"
    const val ERROR = "ERROR"
    const val LOOKUP_USER_RESULT = "LOOKUP_USER_RESULT"

    // ===== 群组 =====
    const val CREATE_GROUP = "CREATE_GROUP"
    const val JOIN_GROUP = "JOIN_GROUP"
    const val LEAVE_GROUP = "LEAVE_GROUP"
    const val GROUP_ADD_MEMBER = "GROUP_ADD_MEMBER"
    const val GROUP_REMOVE_MEMBER = "GROUP_REMOVE_MEMBER"
    const val SEND_GROUP_MSG = "SEND_GROUP_MSG"
    const val LIST_MY_GROUPS = "LIST_MY_GROUPS"
    const val GET_GROUP_INFO = "GET_GROUP_INFO"
    const val SEARCH_GROUPS = "SEARCH_GROUPS"
    const val GROUP_EVENT = "GROUP_EVENT"
    const val GROUP_MSG = "GROUP_MSG"

    // ===== 文件传输 =====
    const val FILE_CHUNK = "FILE_CHUNK"

    // 默认端口
    const val DEFAULT_TCP_PORT = 7891
    const val DEFAULT_DHT_PORT = 7892
    const val DEFAULT_UDP_PORT = 7893

    // 安全参数
    const val PBKDF2_ITERATIONS = 200_000
    const val SALT_SIZE = 16
    const val NONCE_SIZE = 12
    const val KEY_SIZE = 32
    const val TAG_SIZE = 16

    // 心跳间隔（毫秒）
    const val HEARTBEAT_INTERVAL_MS = 30_000L

    // 死人开关默认值
    const val DEFAULT_DEADMAN_GRACE_DAYS = 7
}
