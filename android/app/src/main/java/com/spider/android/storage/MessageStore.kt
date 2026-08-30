package com.spider.android.storage

import android.content.ContentValues
import android.content.Context
import com.spider.android.model.Message

/**
 * 消息存储 — SQLite CRUD。
 */
class MessageStore(context: Context) {

    private val dbHelper = DatabaseHelper(context)

    /**
     * 添加消息。
     */
    fun addMessage(message: Message): Long {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("from_uuid", message.fromUuid)
            put("to_uuid", message.toUuid)
            put("text", message.text)
            put("timestamp", message.timestamp)
            put("is_sent", if (message.isSent) 1 else 0)
            put("delivery_status", message.deliveryStatus)
            put("server_msg_id", message.serverMsgId)
            put("client_msg_id", message.clientMsgId)
            put("is_deadman_warning", if (message.isDeadmanWarning) 1 else 0)
            put("is_file", if (message.isFile) 1 else 0)
            put("file_name", message.fileName)
            put("file_size", message.fileSize)
            put("file_path", message.filePath)
            put("mime_type", message.mimeType)
        }
        return db.insert(DatabaseHelper.TABLE_MESSAGES, null, values)
    }

    /**
     * 获取与指定用户的聊天记录。
     */
    fun getMessagesWith(peerUuid: String, myUuid: String, limit: Int = 500): List<Message> {
        val db = dbHelper.readableDatabase
        val messages = mutableListOf<Message>()
        val cursor = db.query(
            DatabaseHelper.TABLE_MESSAGES,
            null,
            "(from_uuid = ? AND to_uuid = ?) OR (from_uuid = ? AND to_uuid = ?)",
            arrayOf(myUuid, peerUuid, peerUuid, myUuid),
            null, null,
            "timestamp ASC",
            limit.toString()
        )
        cursor.use {
            while (it.moveToNext()) {
                messages.add(cursorToMessage(it))
            }
        }
        return messages
    }

    /**
     * 按 server_msg_id 更新送达状态。
     */
    fun updateDeliveryStatus(serverMsgId: String, status: String) {
        if (serverMsgId.isEmpty()) return
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("delivery_status", status)
        }
        db.update(DatabaseHelper.TABLE_MESSAGES, values, "server_msg_id = ?", arrayOf(serverMsgId))
    }

    /**
     * 按 client_msg_id 更新送达状态。
     */
    fun updateDeliveryStatusByClientId(clientMsgId: String, status: String) {
        if (clientMsgId.isEmpty()) return
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("delivery_status", status)
        }
        db.update(DatabaseHelper.TABLE_MESSAGES, values, "client_msg_id = ?", arrayOf(clientMsgId))
    }

    /**
     * SEND_OK 到达时，将 client_msg_id 映射到 server_msg_id，并更新状态为 sent。
     */
    fun onSendOk(clientMsgId: String, serverMsgId: String) {
        if (clientMsgId.isEmpty()) return
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("delivery_status", "sent")
            if (serverMsgId.isNotEmpty()) put("server_msg_id", serverMsgId)
        }
        db.update(DatabaseHelper.TABLE_MESSAGES, values, "client_msg_id = ?", arrayOf(clientMsgId))
    }

    /**
     * 获取最近的会话列表（每个联系人最后一条消息）。
     */
    fun getRecentConversations(myUuid: String): List<Message> {
        val db = dbHelper.readableDatabase
        val messages = mutableListOf<Message>()
        val cursor = db.rawQuery("""
            SELECT m.* FROM ${DatabaseHelper.TABLE_MESSAGES} m
            INNER JOIN (
                SELECT MAX(timestamp) as max_ts,
                       CASE WHEN from_uuid = ? THEN to_uuid ELSE from_uuid END as peer
                FROM ${DatabaseHelper.TABLE_MESSAGES}
                WHERE from_uuid = ? OR to_uuid = ?
                GROUP BY peer
            ) latest ON m.timestamp = latest.max_ts
            ORDER BY m.timestamp DESC
        """, arrayOf(myUuid, myUuid, myUuid))
        cursor.use {
            while (it.moveToNext()) {
                messages.add(cursorToMessage(it))
            }
        }
        return messages
    }

    /**
     * 删除与指定用户的所有消息。
     */
    fun deleteMessagesWith(peerUuid: String, myUuid: String) {
        val db = dbHelper.writableDatabase
        db.delete(
            DatabaseHelper.TABLE_MESSAGES,
            "(from_uuid = ? AND to_uuid = ?) OR (from_uuid = ? AND to_uuid = ?)",
            arrayOf(myUuid, peerUuid, peerUuid, myUuid)
        )
    }

    private fun cursorToMessage(cursor: android.database.Cursor): Message {
        return Message(
            id = cursor.getLong(cursor.getColumnIndexOrThrow("id")),
            fromUuid = cursor.getString(cursor.getColumnIndexOrThrow("from_uuid")),
            toUuid = cursor.getString(cursor.getColumnIndexOrThrow("to_uuid")),
            text = cursor.getString(cursor.getColumnIndexOrThrow("text")),
            timestamp = cursor.getLong(cursor.getColumnIndexOrThrow("timestamp")),
            isSent = cursor.getInt(cursor.getColumnIndexOrThrow("is_sent")) == 1,
            deliveryStatus = cursor.getString(cursor.getColumnIndexOrThrow("delivery_status")) ?: "pending",
            serverMsgId = cursor.getString(cursor.getColumnIndexOrThrow("server_msg_id")) ?: "",
            clientMsgId = cursor.getString(cursor.getColumnIndexOrThrow("client_msg_id")) ?: "",
            isDeadmanWarning = cursor.getInt(cursor.getColumnIndexOrThrow("is_deadman_warning")) == 1,
            isFile = cursor.getInt(cursor.getColumnIndexOrThrow("is_file")) == 1,
            fileName = cursor.getString(cursor.getColumnIndexOrThrow("file_name")) ?: "",
            fileSize = cursor.getLong(cursor.getColumnIndexOrThrow("file_size")),
            filePath = cursor.getString(cursor.getColumnIndexOrThrow("file_path")) ?: "",
            mimeType = cursor.getString(cursor.getColumnIndexOrThrow("mime_type")) ?: ""
        )
    }
}
