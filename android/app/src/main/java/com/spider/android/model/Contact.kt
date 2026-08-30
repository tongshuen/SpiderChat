package com.spider.android.model

/**
 * 联系人数据模型。
 */
data class Contact(
    val id: Long = 0,
    val uuid: String,
    val displayName: String,
    val x25519Pub: String = "",
    val ed25519Pub: String = "",
    val isOnline: Boolean = false,
    val lastSeen: Long = 0,
    val addedAt: Long = System.currentTimeMillis() / 1000
) {
    val shortUuid: String
        get() = if (uuid.length > 8) uuid.substring(0, 8) + "..." else uuid
}
