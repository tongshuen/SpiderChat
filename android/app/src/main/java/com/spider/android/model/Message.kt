package com.spider.android.model

/**
 * 聊天消息数据模型。
 */
data class Message(
    val id: Long = 0,
    val fromUuid: String,
    val toUuid: String,
    val text: String,
    val timestamp: Long = System.currentTimeMillis() / 1000,
    val isSent: Boolean = false,
    val deliveryStatus: String = "pending", // pending, sent, delivered, read
    val serverMsgId: String = "",
    val clientMsgId: String = "",
    val isDeadmanWarning: Boolean = false,
    val isFile: Boolean = false,
    val fileName: String = "",
    val fileSize: Long = 0,
    val filePath: String = "",
    val mimeType: String = ""
) {
    val timeString: String
        get() {
            val sdf = java.text.SimpleDateFormat("HH:mm", java.util.Locale.getDefault())
            return sdf.format(java.util.Date(timestamp * 1000))
        }
}
