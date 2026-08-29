package com.spider.minecraft.protocol;

/**
 * Spider 标准协议信令类型。
 *
 * <p>完全对齐 Spider 经典客户端 /shared/protocol.py 中的常量定义。
 * SpiderMinecraft 的 TCP 直连端口发出的数据包在结构上与 Spider 客户端完全一致，
 * 因此可以直接对接 Spider 官方服务端程序。
 */
public final class Protocol {

    private Protocol() {}

    // ===== 认证信令 =====
    /** 客户端→服务器：注册新身份（首次使用） */
    public static final String REGISTER = "REGISTER";
    /** 客户端→服务器：登录已有身份 */
    public static final String LOGIN = "LOGIN";
    /** 服务器→客户端：注册/登录成功 */
    public static final String AUTH_OK = "AUTH_OK";
    /** 服务器→客户端：注册/登录失败 */
    public static final String AUTH_FAIL = "AUTH_FAIL";

    // ===== 消息信令 =====
    /** 客户端→服务器：发送消息（加密信封） */
    public static final String SEND_MSG = "SEND_MSG";
    /** 服务器→客户端：投递消息给接收方 */
    public static final String RECV_MSG = "RECV_MSG";
    /** 服务器→发送方：消息已送达对方 */
    public static final String DELIVERY_RECEIPT = "DELIVERY_RECEIPT";
    /** 接收方→发送方：消息已读 */
    public static final String READ_RECEIPT = "READ_RECEIPT";

    // ===== 离线信令 =====
    /** 服务器→客户端：离线消息队列推送 */
    public static final String OFFLINE_QUEUE = "OFFLINE_QUEUE";
    /** 客户端→服务器：请求离线消息 */
    public static final String REQUEST_OFFLINE = "REQUEST_OFFLINE";

    // ===== 安全信令 =====
    /** 客户端→服务器：本机已被胁迫，通知所有联系人 */
    public static final String COMPROMISED = "COMPROMISED";
    /** 服务器→客户端：胁迫通知确认 */
    public static final String COMPROMISED_ACK = "COMPROMISED_ACK";

    // ===== 群组信令 =====
    /** 创建群组 */
    public static final String GROUP_CREATE = "GROUP_CREATE";
    /** 加入群组 */
    public static final String GROUP_JOIN = "GROUP_JOIN";
    /** 离开群组 */
    public static final String GROUP_LEAVE = "GROUP_LEAVE";
    /** 群组消息 */
    public static final String GROUP_MSG = "GROUP_MSG";
    /** 群组信息 */
    public static final String GROUP_INFO = "GROUP_INFO";
    /** 群组列表 */
    public static final String GROUP_LIST = "GROUP_LIST";

    // ===== 保活 =====
    /** 心跳 */
    public static final String HEARTBEAT = "HEARTBEAT";
    /** 心跳响应 */
    public static final String HEARTBEAT_ACK = "HEARTBEAT_ACK";

    // ===== 文件传输 =====
    /** 文件传输请求 */
    public static final String FILE_SEND = "FILE_SEND";
    /** 文件数据块 */
    public static final String FILE_CHUNK = "FILE_CHUNK";
    /** 文件传输完成 */
    public static final String FILE_COMPLETE = "FILE_COMPLETE";

    // ===== 公钥查询 =====
    /** 查询用户公钥 */
    public static final String GET_PUBKEY = "GET_PUBKEY";
    /** 公钥查询结果 */
    public static final String PUBKEY_RESULT = "PUBKEY_RESULT";

    // ===== 通用 =====
    /** 错误 */
    public static final String ERROR = "ERROR";
    /** 断开连接 */
    public static final String BYE = "BYE";
}
