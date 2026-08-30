package com.spider.android.security

import android.content.Context
import android.util.Log
import com.spider.android.crypto.KeyManager
import com.spider.android.location.LocationHelper
import com.spider.android.network.Protocol
import com.spider.android.network.SpiderClient

/**
 * 死人开关（Dead Man's Switch）客户端管理器。
 *
 * 功能：
 * - 管理死人开关配置（开关、警告消息、收件人、宽限期）
 * - 在登录、编辑警告消息、编辑收件人时同步到服务器
 * - 服务器将其作为特殊离线消息存储，到期用户未登录时先推送警告再执行胁迫操作
 *
 * 这样哪怕客户端炸了，警告消息也能按时发送。
 */
class DeadmanManager(
    private val context: Context,
    private val keyManager: KeyManager,
    private val spiderClient: SpiderClient,
    private val locationHelper: LocationHelper = LocationHelper(context)
) {

    private val TAG = "DeadmanManager"
    private val PREFS_NAME = "spider_settings"

    data class DeadmanConfig(
        val enabled: Boolean = false,
        val warningMessage: String = "",
        val recipientUuid: String = "",
        val graceDays: Int = Protocol.DEFAULT_DEADMAN_GRACE_DAYS
    )

    /**
     * 获取死人开关配置。
     */
    fun getConfig(): DeadmanConfig {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return DeadmanConfig(
            enabled = prefs.getBoolean("deadman_enabled", false),
            warningMessage = prefs.getString("deadman_warning_message", "") ?: "",
            recipientUuid = prefs.getString("deadman_recipient_uuid", "") ?: "",
            graceDays = prefs.getInt("deadman_grace_days", Protocol.DEFAULT_DEADMAN_GRACE_DAYS)
        )
    }

    /**
     * 更新死人开关配置。
     * 更新后自动同步到服务器（如果启用且已连接）。
     */
    fun setConfig(
        enabled: Boolean? = null,
        warningMessage: String? = null,
        recipientUuid: String? = null,
        graceDays: Int? = null,
        autoSync: Boolean = true
    ): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val editor = prefs.edit()

        if (enabled != null) editor.putBoolean("deadman_enabled", enabled)
        if (warningMessage != null) editor.putString("deadman_warning_message", warningMessage)
        if (recipientUuid != null) editor.putString("deadman_recipient_uuid", recipientUuid)
        if (graceDays != null) {
            val days = graceDays.coerceIn(1, 365)
            editor.putInt("deadman_grace_days", days)
        }
        editor.apply()

        if (autoSync) {
            syncToServer()
        }
        return true
    }

    /**
     * 检查配置是否完整。
     */
    fun isConfigComplete(): Boolean {
        val cfg = getConfig()
        if (!cfg.enabled) return true
        return cfg.warningMessage.isNotEmpty() && cfg.recipientUuid.isNotEmpty()
    }

    /**
     * 将最新的死人开关警告消息同步到服务器。
     * 在登录、编辑警告消息、编辑收件人时调用。
     */
    fun syncToServer(): Boolean {
        val cfg = getConfig()
        if (!cfg.enabled) {
            Log.d(TAG, "Deadman disabled, skipping sync")
            return false
        }
        if (cfg.warningMessage.isEmpty() || cfg.recipientUuid.isEmpty()) {
            Log.w(TAG, "Deadman config incomplete, skipping sync")
            return false
        }
        if (!spiderClient.isConnected) {
            Log.w(TAG, "Not connected to server, skipping sync")
            return false
        }
        val uuid = keyManager.getUuid()
        if (uuid.isEmpty()) {
            Log.w(TAG, "No UUID, skipping sync")
            return false
        }

        val gracePeriodSec = cfg.graceDays * 86400

        // 自动附加当前位置信息（经纬度、不确定度、定位时间）
        // 这样哪怕客户端炸了，警告消息也能携带最后已知位置
        val messageWithLocation = buildString {
            append(cfg.warningMessage)
            if (locationHelper.hasPermission()) {
                val loc = locationHelper.getCurrentLocation()
                if (loc != null) {
                    append(loc.toWarningString())
                    Log.i(TAG, "Location appended to deadman warning: " +
                            "lat=%.4f lon=%.4f acc=%.1fm".format(loc.latitude, loc.longitude, loc.accuracy))
                } else {
                    Log.w(TAG, "Location permission granted but unable to get location")
                }
            } else {
                Log.d(TAG, "No location permission, sending warning without location")
            }
        }

        spiderClient.sendDeadmanMessage(
            uuid = uuid,
            recipientUuid = cfg.recipientUuid,
            messageText = messageWithLocation,
            gracePeriodSec = gracePeriodSec
        )
        Log.i(TAG, "Deadman warning synced to server " +
                "(recipient=${cfg.recipientUuid.take(8)}..., grace=${cfg.graceDays}d)")
        return true
    }

    /**
     * 获取状态摘要。
     */
    fun getStatusSummary(): String {
        val cfg = getConfig()
        if (!cfg.enabled) return "死人开关：未启用"
        var status = "死人开关：已启用，宽限 ${cfg.graceDays} 天"
        if (cfg.warningMessage.isNotEmpty()) {
            val preview = cfg.warningMessage.take(30) +
                    if (cfg.warningMessage.length > 30) "..." else ""
            status += "，警告：\"$preview\""
        }
        if (cfg.recipientUuid.isNotEmpty()) {
            status += "，收件人：${cfg.recipientUuid.take(8)}..."
        }
        return status
    }
}
