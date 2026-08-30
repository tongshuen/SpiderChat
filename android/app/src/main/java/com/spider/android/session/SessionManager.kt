package com.spider.android.session

import android.content.Context
import android.util.Base64
import android.util.Log
import com.spider.android.crypto.CryptoManager
import com.spider.android.crypto.KeyManager
import com.spider.android.network.Protocol
import com.spider.android.network.SpiderClient
import com.spider.android.storage.IdentityStore
import org.json.JSONObject

/**
 * 会话管理器 — 注册、登录、认证流程。
 *
 * 对齐 Spider Python 客户端的 SessionManager：
 * - REGISTER/LOGIN 认证流程
 * - 登录成功后同步死人开关警告消息
 * - 胁迫 PIN 检测（输入胁迫 PIN 时触发擦除）
 */
class SessionManager(
    private val context: Context,
    private val keyManager: KeyManager,
    private val cryptoManager: CryptoManager,
    private val spiderClient: SpiderClient,
    private val identityStore: IdentityStore
) {

    private val TAG = "SessionManager"

    enum class LoginState {
        IDLE, CONNECTING, AUTHENTICATING, AUTHENTICATED, FAILED
    }

    var loginState = LoginState.IDLE
        private set

    var onLoginSuccess: (() -> Unit)? = null
    var onLoginFailed: ((String) -> Unit)? = null
    var onRegisterSuccess: (() -> Unit)? = null
    var onDuressDetected: (() -> Unit)? = null

    init {
        setupCallbacks()
    }

    private fun setupCallbacks() {
        spiderClient.onLoginOk = { msg ->
            Log.i(TAG, "Login OK")
            loginState = LoginState.AUTHENTICATED
            // 登录成功后同步死人开关警告消息
            syncDeadmanMessage()
            onLoginSuccess?.invoke()
        }
        spiderClient.onLoginFail = { reason ->
            Log.e(TAG, "Login failed: $reason")
            loginState = LoginState.FAILED
            onLoginFailed?.invoke(reason)
        }
        spiderClient.onRegisterOk = {
            Log.i(TAG, "Register OK")
            onRegisterSuccess?.invoke()
        }
    }

    /**
     * 连接并登录。
     */
    fun login(host: String, port: Int, pin: String, callback: (Boolean, String?) -> Unit) {
        // 先检查是否是胁迫 PIN
        if (identityStore.verifyDuressPin(pin, keyManager)) {
            Log.w(TAG, "Duress PIN detected!")
            onDuressDetected?.invoke()
            callback(false, "胁迫 PIN 已触发")
            return
        }

        // 加载身份
        val identity = try {
            identityStore.loadIdentity(pin, keyManager)
        } catch (e: Exception) {
            null
        }
        if (identity == null) {
            callback(false, "PIN 错误或身份文件损坏")
            return
        }

        keyManager.setIdentity(identity)
        loginState = LoginState.CONNECTING

        spiderClient.connect(host, port) { success, error ->
            if (!success) {
                loginState = LoginState.FAILED
                callback(false, error ?: "连接失败")
                return@connect
            }
            // 发送登录请求
            loginState = LoginState.AUTHENTICATING
            val signData = "login|${identity.uuid}|${System.currentTimeMillis() / 1000}"
            val signature = cryptoManager.signData(
                signData.toByteArray(Charsets.UTF_8),
                identity.ed25519Private
            ) ?: ""
            spiderClient.login(identity.uuid, identity.ed25519Public, signature)
            callback(true, null)
        }
    }

    /**
     * 注册新身份。
     */
    fun register(host: String, port: Int, pin: String, duressPin: String,
                 displayName: String, callback: (Boolean, String?) -> Unit) {
        if (pin.length != 6 || !pin.matches(Regex("\\d{6}"))) {
            callback(false, "PIN 必须为6位数字")
            return
        }
        if (duressPin.isNotEmpty() && (duressPin.length != 6 || !duressPin.matches(Regex("\\d{6}")))) {
            callback(false, "胁迫 PIN 必须为6位数字")
            return
        }
        if (duressPin == pin) {
            callback(false, "胁迫 PIN 不能与解锁 PIN 相同")
            return
        }

        // 创建身份
        val identity = keyManager.createIdentity(host, port, displayName)
        keyManager.setIdentity(identity)

        // 保存身份（加密存储）
        identityStore.saveIdentity(identity, pin, duressPin, keyManager)

        // 连接并注册
        spiderClient.connect(host, port) { success, error ->
            if (!success) {
                callback(false, error ?: "连接失败")
                return@connect
            }
            val signData = "register|${identity.uuid}|${System.currentTimeMillis() / 1000}"
            val signature = cryptoManager.signData(
                signData.toByteArray(Charsets.UTF_8),
                identity.ed25519Private
            ) ?: ""
            spiderClient.register(
                identity.uuid, identity.x25519Public, identity.ed25519Public,
                identity.macAddress, displayName, signature
            )
            callback(true, null)
        }
    }

    /**
     * 同步死人开关警告消息到服务器（登录成功后调用）。
     */
    fun syncDeadmanMessage() {
        val prefs = context.getSharedPreferences("spider_settings", Context.MODE_PRIVATE)
        val enabled = prefs.getBoolean("deadman_enabled", false)
        if (!enabled) return
        val warningMsg = prefs.getString("deadman_warning_message", "") ?: ""
        val recipient = prefs.getString("deadman_recipient_uuid", "") ?: ""
        val graceDays = prefs.getInt("deadman_grace_days", Protocol.DEFAULT_DEADMAN_GRACE_DAYS)
        if (warningMsg.isEmpty() || recipient.isEmpty()) return

        val uuid = keyManager.getUuid()
        if (uuid.isEmpty()) return

        spiderClient.sendDeadmanMessage(uuid, recipient, warningMsg, graceDays * 86400)
        Log.i(TAG, "Deadman warning synced to server")
    }

    /**
     * 登出。
     */
    fun logout() {
        spiderClient.disconnect()
        keyManager.wipe()
        loginState = LoginState.IDLE
    }

    /**
     * 触发胁迫流程（擦除数据 + 发送 COMPROMISED）。
     */
    fun triggerDuress() {
        Log.w(TAG, "Triggering duress protocol...")
        val uuid = keyManager.getUuid()
        val identity = keyManager.getIdentity()
        if (uuid.isNotEmpty() && identity != null && spiderClient.isConnected) {
            val signData = "compromised|$uuid|${System.currentTimeMillis() / 1000}"
            val signature = cryptoManager.signData(
                signData.toByteArray(Charsets.UTF_8),
                identity.ed25519Private
            ) ?: ""
            spiderClient.sendCompromised(uuid, signature)
        }
        // 擦除本地数据
        keyManager.wipe()
        // 注意：数据库擦除由调用方处理（UI 层）
    }
}
