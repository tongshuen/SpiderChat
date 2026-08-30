package com.spider.android.file

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import com.spider.android.crypto.CryptoManager
import com.spider.android.crypto.KeyManager
import com.spider.android.model.Message
import com.spider.android.network.Protocol
import com.spider.android.network.SpiderClient
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 文件传输管理器 — 加密文件传输（通过服务器中继）。
 *
 * 文件以 AES-256-GCM 加密后 base64 编码，作为 SEND_MSG 的
 * encrypted_payload（type=file）发送。接收方解密后保存到应用私有存储。
 *
 * 对齐 Spider Python 客户端的文件加密方式，但通过服务器中继而非 P2P 直连。
 */
class FileTransferManager(
    private val context: Context,
    private val keyManager: KeyManager,
    private val cryptoManager: CryptoManager,
    private val spiderClient: SpiderClient
) {
    private val TAG = "FileTransferManager"

    companion object {
        const val MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB 单包上限
        const val CHUNK_SIZE = 64 * 1024 // 64KB 分片（预留）
    }

    /**
     * 发送文件给指定联系人。
     */
    fun sendFile(contactUuid: String, contactX25519Pub: String,
                 uri: Uri, callback: (Boolean, String?) -> Unit) {
        try {
            // 读取文件
            val inputStream = context.contentResolver.openInputStream(uri)
                ?: run {
                    callback(false, "无法打开文件")
                    return
                }
            val fileData = inputStream.readBytes()
            inputStream.close()

            if (fileData.size > MAX_FILE_SIZE) {
                callback(false, "文件过大（最大 ${MAX_FILE_SIZE / 1024 / 1024}MB）")
                return
            }

            val fileName = getFileName(uri) ?: "file_${System.currentTimeMillis()}"
            val fileSize = fileData.size
            val mimeType = context.contentResolver.getType(uri) ?: "application/octet-stream"

            // 加密文件数据
            val encrypted = cryptoManager.encryptMessage(
                Base64.encodeToString(fileData, Base64.NO_WRAP),
                contactX25519Pub,
                keyManager.getIdentity()?.ed25519Private ?: ""
            )
            if (encrypted == null) {
                callback(false, "文件加密失败")
                return
            }

            // 构造文件类型的加密载荷
            val encryptedPayload = JSONObject().apply {
                put("type", "file")
                put("file_name", fileName)
                put("file_size", fileSize)
                put("mime_type", mimeType)
                put("ciphertext", encrypted.ciphertext)
                put("nonce", encrypted.nonce)
                put("tag", encrypted.tag)
                put("ephemeral_pubkey", encrypted.ephemeralPubKey)
                put("aad", encrypted.aad)
            }

            // 签名并发送
            val signData = "send|$contactUuid|${System.currentTimeMillis() / 1000}"
            val signature = cryptoManager.signData(
                signData.toByteArray(),
                keyManager.getIdentity()?.ed25519Private ?: ""
            ) ?: ""

            val clientMsgId = "file_${System.currentTimeMillis()}"
            spiderClient.sendMessage(contactUuid, encryptedPayload, signature, clientMsgId)

            Log.i(TAG, "File sent: $fileName (${fileSize} bytes) to $contactUuid")
            callback(true, clientMsgId)
        } catch (e: Exception) {
            Log.e(TAG, "sendFile error: ${e.message}", e)
            callback(false, e.message)
        }
    }

    /**
     * 处理接收到的文件消息，解密并保存。
     */
    fun handleReceivedFile(fromUuid: String, encryptedPayload: JSONObject,
                           senderEd25519Pub: String): Message? {
        try {
            val fileName = encryptedPayload.optString("file_name", "unknown_file")
            val fileSize = encryptedPayload.optLong("file_size", 0)
            val mimeType = encryptedPayload.optString("mime_type", "application/octet-stream")

            val encrypted = CryptoManager.EncryptedMessage(
                ciphertext = encryptedPayload.optString("ciphertext"),
                nonce = encryptedPayload.optString("nonce"),
                tag = encryptedPayload.optString("tag"),
                ephemeralPubKey = encryptedPayload.optString("ephemeral_pubkey"),
                aad = encryptedPayload.optString("aad")
            )

            // 解密
            val base64Data = cryptoManager.decryptMessage(
                encrypted,
                keyManager.getIdentity()?.x25519Private ?: "",
                senderEd25519Pub
            ) ?: return null

            val fileData = Base64.decode(base64Data, Base64.NO_WRAP)

            // 保存到应用私有存储
            val savedPath = saveReceivedFile(fileName, fileData)
            if (savedPath == null) {
                Log.e(TAG, "Failed to save received file")
                return null
            }

            Log.i(TAG, "File received and saved: $fileName (${fileData.size} bytes) -> $savedPath")

            return Message(
                fromUuid = fromUuid,
                toUuid = keyManager.getUuid(),
                text = "📎 $fileName (${formatFileSize(fileData.size)})",
                isSent = false,
                isFile = true,
                fileName = fileName,
                filePath = savedPath,
                fileSize = fileData.size,
                mimeType = mimeType,
                deliveryStatus = "delivered"
            )
        } catch (e: Exception) {
            Log.e(TAG, "handleReceivedFile error: ${e.message}", e)
            return null
        }
    }

    /**
     * 保存接收到的文件到应用私有存储。
     */
    private fun saveReceivedFile(fileName: String, data: ByteArray): String? {
        return try {
            val timeStamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.getDefault()).format(Date())
            val safeName = sanitizeFileName(fileName)
            val finalName = if (safeName.contains(".")) {
                val ext = safeName.substringAfterLast(".")
                val base = safeName.substringBeforeLast(".")
                "${base}_$timeStamp.$ext"
            } else {
                "${safeName}_$timeStamp"
            }

            val file = File(context.filesDir, "spider_files/$finalName")
            file.parentFile?.mkdirs()
            FileOutputStream(file).use { it.write(data) }
            file.absolutePath
        } catch (e: Exception) {
            Log.e(TAG, "saveReceivedFile error: ${e.message}", e)
            null
        }
    }

    /**
     * 从 Uri 获取文件名。
     */
    private fun getFileName(uri: Uri): String? {
        return if (uri.scheme == "content") {
            val cursor = context.contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                val nameIndex = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                if (nameIndex >= 0 && it.moveToFirst()) {
                    it.getString(nameIndex)
                } else null
            }
        } else {
            uri.lastPathSegment
        }
    }

    private fun sanitizeFileName(name: String): String {
        return name.replace(Regex("[^a-zA-Z0-9._-]"), "_").take(200)
    }

    fun formatFileSize(bytes: Int): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            else -> "${"%.1f".format(bytes / 1024.0 / 1024.0)} MB"
        }
    }

    /**
     * 获取已接收文件的目录。
     */
    fun getReceivedFilesDir(): File {
        val dir = File(context.filesDir, "spider_files")
        dir.mkdirs()
        return dir
    }

    /**
     * 列出所有已接收文件。
     */
    fun listReceivedFiles(): List<File> {
        return getReceivedFilesDir().listFiles()?.toList() ?: emptyList()
    }
}
