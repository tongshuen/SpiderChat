package com.spider.android.security

import android.content.Context
import android.util.Log
import com.spider.android.crypto.KeyManager
import com.spider.android.network.SpiderClient
import com.spider.android.session.SessionManager
import com.spider.android.storage.DatabaseHelper

/**
 * 胁迫 PIN 管理器 — 对齐 Spider 的 duress PIN 特性。
 *
 * 功能：
 * - 检测输入的 PIN 是否为胁迫 PIN
 * - 触发胁迫流程：发送 COMPROMISED + 擦除本地数据
 * - 设置/修改胁迫 PIN
 */
class DuressManager(
    private val context: Context,
    private val keyManager: KeyManager,
    private val spiderClient: SpiderClient,
    private val sessionManager: SessionManager
) {

    private val TAG = "DuressManager"

    var onDuressTriggered: (() -> Unit)? = null

    /**
     * 检查 PIN 是否为胁迫 PIN。如果是，触发胁迫流程。
     * @return true 如果是胁迫 PIN（已触发擦除），false 如果不是
     */
    fun checkAndTrigger(pin: String): Boolean {
        if (!keyManager.hasDuressPin()) return false
        if (!keyManager.checkDuressPin(pin)) return false

        Log.w(TAG, "DURESS PIN DETECTED — initiating wipe protocol")
        triggerDuress()
        return true
    }

    /**
     * 触发胁迫流程。
     */
    fun triggerDuress() {
        // 发送 COMPROMISED 信令
        val uuid = keyManager.getUuid()
        val identity = keyManager.getIdentity()
        if (uuid.isNotEmpty() && identity != null && spiderClient.isConnected) {
            val signData = "compromised|$uuid|${System.currentTimeMillis() / 1000}"
            // 注意：这里需要 cryptoManager，但为了避免循环依赖，通过 sessionManager 触发
            sessionManager.triggerDuress()
        }

        // 擦除本地数据库
        try {
            val dbHelper = DatabaseHelper(context)
            dbHelper.wipeAllData()
            Log.i(TAG, "Local data wiped")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to wipe data: ${e.message}")
        }

        // 清除 SharedPreferences
        context.getSharedPreferences("spider_settings", Context.MODE_PRIVATE).edit().clear().apply()

        onDuressTriggered?.invoke()
    }

    /**
     * 设置胁迫 PIN。
     */
    fun setDuressPin(pin: String): Boolean {
        if (pin.length != 6 || !pin.matches(Regex("\\d{6}"))) return false
        keyManager.setDuressPin(pin)
        return true
    }

    fun hasDuressPin(): Boolean = keyManager.hasDuressPin()
}
