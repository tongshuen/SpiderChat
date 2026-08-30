package com.spider.android.network

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.PrintWriter
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Spider TCP 客户端 — 连接到 Spider 服务端，发送/接收 JSON 协议消息。
 *
 * 对齐 Python 客户端的 tcp_client.py：
 * - JSON 行协议（每行一条 JSON 消息）
 * - 异步接收线程
 * - 心跳保活（每 30 秒发送 PING）
 * - 回调机制处理各种消息类型
 */
class SpiderClient {

    private val TAG = "SpiderClient"
    private var socket: Socket? = null
    private var writer: PrintWriter? = null
    private var reader: BufferedReader? = null
    private var receiveThread: Thread? = null
    private var heartbeatThread: Thread? = null
    private val running = AtomicBoolean(false)

    var isConnected = false
        private set

    // ===== 回调 =====
    var onMessage: ((JSONObject) -> Unit)? = null
    var onLoginOk: ((JSONObject) -> Unit)? = null
    var onLoginFail: ((String) -> Unit)? = null
    var onRegisterOk: ((JSONObject) -> Unit)? = null
    var onRecvMessage: ((JSONObject) -> Unit)? = null
    var onOfflineQueue: ((JSONArray) -> Unit)? = null
    var onSendOk: ((JSONObject) -> Unit)? = null
    var onDeliveryReceipt: ((JSONObject) -> Unit)? = null
    var onReadReceipt: ((JSONObject) -> Unit)? = null
    var onReadReceiptDisabled: ((JSONObject) -> Unit)? = null
    var onPubkeyResult: ((JSONObject) -> Unit)? = null
    var onCompromisedAck: ((JSONObject) -> Unit)? = null
    var onDeadmanAck: ((JSONObject) -> Unit)? = null
    var onRateLimited: ((String) -> Unit)? = null
    var onError: ((String) -> Unit)? = null
    var onDisconnect: (() -> Unit)? = null
    var onSearchResult: ((JSONObject) -> Unit)? = null
    var onLookupResult: ((JSONObject) -> Unit)? = null
    var onBroadcast: ((JSONObject) -> Unit)? = null
    var onPing: ((Long) -> Unit)? = null
    var onPong: ((Long) -> Unit)? = null

    /**
     * 连接到 Spider 服务器。
     */
    fun connect(host: String, port: Int, callback: (Boolean, String?) -> Unit) {
        Thread {
            try {
                socket = Socket(host, port)
                socket?.soTimeout = 0  // 无超时，靠心跳检测
                writer = PrintWriter(socket!!.getOutputStream(), true)
                reader = BufferedReader(InputStreamReader(socket!!.getInputStream()))
                running.set(true)
                isConnected = true
                startReceiveThread()
                startHeartbeat()
                Log.i(TAG, "Connected to $host:$port")
                callback(true, null)
            } catch (e: Exception) {
                Log.e(TAG, "Connection failed: ${e.message}")
                callback(false, e.message)
            }
        }.start()
    }

    /**
     * 启动接收线程。
     */
    private fun startReceiveThread() {
        receiveThread = Thread {
            try {
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    val line = reader?.readLine() ?: break
                    if (line.isBlank()) continue
                    try {
                        val msg = JSONObject(line)
                        handleMessage(msg)
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed to parse message: ${e.message}")
                    }
                }
            } catch (e: Exception) {
                if (running.get()) {
                    Log.e(TAG, "Receive error: ${e.message}")
                    onError?.invoke(e.message ?: "Unknown error")
                }
            } finally {
                isConnected = false
                onDisconnect?.invoke()
            }
        }.apply { start() }
    }

    /**
     * 启动心跳线程 — 每 30 秒发送 PING。
     */
    private fun startHeartbeat() {
        heartbeatThread = Thread {
            try {
                while (running.get() && !Thread.currentThread().isInterrupted) {
                    Thread.sleep(Protocol.HEARTBEAT_INTERVAL_MS)
                    if (running.get() && isConnected) {
                        sendPing()
                    }
                }
            } catch (_: InterruptedException) {
                // 正常退出
            }
        }.apply {
            isDaemon = true
            start()
        }
    }

    /**
     * 处理接收到的消息。
     */
    private fun handleMessage(msg: JSONObject) {
        val type = msg.optString("type", "")
        Log.d(TAG, "Received: $type")
        when (type) {
            Protocol.LOGIN_OK -> onLoginOk?.invoke(msg)
            Protocol.LOGIN_FAIL -> onLoginFail?.invoke(msg.optString("reason", "Login failed"))
            Protocol.REGISTER_OK -> onRegisterOk?.invoke(msg)
            Protocol.RECV_MSG -> onRecvMessage?.invoke(msg)
            Protocol.OFFLINE_QUEUE -> {
                val messages = msg.optJSONArray("messages") ?: JSONArray()
                onOfflineQueue?.invoke(messages)
            }
            Protocol.SEND_OK -> onSendOk?.invoke(msg)
            Protocol.DELIVERY_RECEIPT -> onDeliveryReceipt?.invoke(msg)
            Protocol.READ_RECEIPT -> onReadReceipt?.invoke(msg)
            Protocol.READ_RECEIPT_DISABLED -> onReadReceiptDisabled?.invoke(msg)
            Protocol.PUBKEY_RESULT -> onPubkeyResult?.invoke(msg)
            Protocol.COMPROMISED_ACK -> onCompromisedAck?.invoke(msg)
            Protocol.DEADMAN_ACK -> onDeadmanAck?.invoke(msg)
            Protocol.RATE_LIMITED -> onRateLimited?.invoke(msg.optString("reason", "Rate limited"))
            Protocol.ERROR -> onError?.invoke(msg.optString("reason", msg.optString("message", "Unknown error")))
            Protocol.SEARCH_CONTACTS -> onSearchResult?.invoke(msg)
            Protocol.LOOKUP_USER_RESULT -> onLookupResult?.invoke(msg)
            Protocol.BROADCAST -> onBroadcast?.invoke(msg)
            Protocol.PING -> {
                // 服务端发来 PING，立即回复 PONG
                val timestamp = msg.optLong("timestamp", System.currentTimeMillis() / 1000)
                sendPong(timestamp)
                onPing?.invoke(timestamp)
            }
            Protocol.PONG -> {
                val timestamp = msg.optLong("timestamp", 0)
                onPong?.invoke(timestamp)
            }
            else -> onMessage?.invoke(msg)
        }
    }

    /**
     * 发送 JSON 消息。
     */
    fun send(msg: JSONObject) {
        if (!isConnected || writer == null) {
            Log.e(TAG, "Not connected, cannot send")
            return
        }
        Thread {
            try {
                writer?.println(msg.toString())
                writer?.flush()
                Log.d(TAG, "Sent: ${msg.optString("type")}")
            } catch (e: Exception) {
                Log.e(TAG, "Send failed: ${e.message}")
            }
        }.start()
    }

    /**
     * 发送原始 JSON 字符串。
     */
    fun sendRaw(jsonStr: String) {
        if (!isConnected || writer == null) return
        Thread {
            try {
                writer?.println(jsonStr)
                writer?.flush()
            } catch (e: Exception) {
                Log.e(TAG, "Send raw failed: ${e.message}")
            }
        }.start()
    }

    // ===== 具体消息发送方法 =====

    fun login(uuid: String, ed25519Pub: String, signature: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.LOGIN)
            put("version", Protocol.PROTOCOL_VERSION)
            put("uuid", uuid)
            put("ed25519_pub", ed25519Pub)
            put("signature", signature)
        }
        send(msg)
    }

    fun register(uuid: String, x25519Pub: String, ed25519Pub: String,
                 macAddress: String, displayName: String, signature: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.REGISTER)
            put("version", Protocol.PROTOCOL_VERSION)
            put("uuid", uuid)
            put("x25519_pub", x25519Pub)
            put("ed25519_pub", ed25519Pub)
            put("mac_address", macAddress)
            put("display_name", displayName)
            put("signature", signature)
        }
        send(msg)
    }

    fun sendMessage(toUuid: String, encryptedPayload: JSONObject, signature: String,
                    clientMsgId: String = "") {
        val msg = JSONObject().apply {
            put("type", Protocol.SEND_MSG)
            put("version", Protocol.PROTOCOL_VERSION)
            put("to_uuid", toUuid)
            put("encrypted_payload", encryptedPayload)
            put("signature", signature)
            if (clientMsgId.isNotEmpty()) put("client_msg_id", clientMsgId)
        }
        send(msg)
    }

    fun sendDeliveryReceipt(fromUuid: String, serverMsgId: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.DELIVERY_RECEIPT)
            put("from_uuid", fromUuid)
            put("server_msg_id", serverMsgId)
        }
        send(msg)
    }

    fun sendReadReceipt(fromUuid: String, serverMsgId: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.READ_RECEIPT)
            put("from_uuid", fromUuid)
            put("server_msg_id", serverMsgId)
        }
        send(msg)
    }

    fun queryPubkey(uuid: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.QUERY_PUBKEY)
            put("uuid", uuid)
        }
        send(msg)
    }

    fun storePubkey(uuid: String, x25519Pub: String, ed25519Pub: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.STORE_PUBKEY)
            put("uuid", uuid)
            put("x25519_pub", x25519Pub)
            put("ed25519_pub", ed25519Pub)
        }
        send(msg)
    }

    fun lookupUser(query: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.LOOKUP_USER)
            put("query", query)
        }
        send(msg)
    }

    fun sendCompromised(uuid: String, signature: String) {
        val msg = JSONObject().apply {
            put("type", Protocol.COMPROMISED)
            put("version", Protocol.PROTOCOL_VERSION)
            put("uuid", uuid)
            put("signature", signature)
        }
        send(msg)
    }

    fun sendDeadmanMessage(uuid: String, recipientUuid: String, messageText: String,
                           gracePeriodSec: Int) {
        val msg = JSONObject().apply {
            put("type", Protocol.STORE_DEADMAN_MSG)
            put("version", Protocol.PROTOCOL_VERSION)
            put("uuid", uuid)
            put("recipient_uuid", recipientUuid)
            put("message_text", messageText)
            put("grace_period_sec", gracePeriodSec)
        }
        send(msg)
    }

    fun searchContacts(query: String, scope: String = "server") {
        val msg = JSONObject().apply {
            put("type", Protocol.SEARCH_CONTACTS)
            put("query", query)
            put("scope", scope)
        }
        send(msg)
    }

    fun sendPing() {
        val msg = JSONObject().apply {
            put("type", Protocol.PING)
            put("timestamp", System.currentTimeMillis() / 1000)
        }
        send(msg)
    }

    fun sendPong(timestamp: Long) {
        val msg = JSONObject().apply {
            put("type", Protocol.PONG)
            put("timestamp", timestamp)
        }
        send(msg)
    }

    /**
     * 断开连接。
     */
    fun disconnect() {
        running.set(false)
        try {
            heartbeatThread?.interrupt()
        } catch (_: Exception) {}
        try {
            receiveThread?.interrupt()
        } catch (_: Exception) {}
        try {
            writer?.close()
            reader?.close()
            socket?.close()
        } catch (_: Exception) {}
        socket = null
        writer = null
        reader = null
        isConnected = false
        Log.i(TAG, "Disconnected")
    }
}
