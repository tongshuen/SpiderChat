package com.spider.android.location

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationManager
import android.os.Build
import android.os.SystemClock
import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 位置信息助手 — 获取当前经纬度、不确定度（精度）和定位时间。
 *
 * 用于死人开关警告消息中自动附加位置信息，
 * 以及聊天消息长按显示位置详情。
 */
class LocationHelper(private val context: Context) {

    private val TAG = "LocationHelper"

    data class LocationInfo(
        val latitude: Double,
        val longitude: Double,
        val accuracy: Float,         // 不确定度（米），-1 表示不可用
        val timestamp: Long,         // 定位时间（Unix 秒）
        val provider: String         // 定位提供者（gps/network/passive）
    ) {
        /** 格式化为人类可读字符串，附加到警告消息中。 */
        fun toWarningString(): String {
            val timeStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                .format(Date(timestamp * 1000))
            val accStr = if (accuracy >= 0) "±%.0f米".format(accuracy) else "未知"
            return buildString {
                appendLine()
                appendLine("── 位置信息（自动附加）──")
                appendLine("纬度：%.6f".format(latitude))
                appendLine("经度：%.6f".format(longitude))
                appendLine("精度：$accStr")
                append("定位时间：$timeStr")
            }
        }

        /** 格式化为简短字符串，用于长按弹窗。 */
        fun toShortString(): String {
            val timeStr = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                .format(Date(timestamp * 1000))
            val accStr = if (accuracy >= 0) "±%.0f米".format(accuracy) else "未知"
            return "纬度：%.6f\n经度：%.6f\n精度：%s\n定位时间：%s".format(
                latitude, longitude, accStr, timeStr
            )
        }
    }

    /**
     * 检查是否已授予定位权限。
     */
    fun hasPermission(): Boolean {
        val fine = context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION)
        val coarse = context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION)
        return fine == PackageManager.PERMISSION_GRANTED ||
                coarse == PackageManager.PERMISSION_GRANTED
    }

    /**
     * 获取当前位置。
     * 优先使用 GPS，其次网络定位，最后使用最后已知位置。
     *
     * @return LocationInfo 或 null（无权限或无法获取位置）
     */
    @SuppressLint("MissingPermission")
    fun getCurrentLocation(): LocationInfo? {
        if (!hasPermission()) {
            Log.w(TAG, "No location permission")
            return null
        }

        val locationManager = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager

        // 尝试从各个提供者获取最后已知位置
        val providers = listOf(
            LocationManager.GPS_PROVIDER,
            LocationManager.NETWORK_PROVIDER,
            LocationManager.PASSIVE_PROVIDER
        )

        var bestLocation: Location? = null
        var bestProvider = ""

        for (provider in providers) {
            try {
                if (!locationManager.isProviderEnabled(provider)) continue
                val loc = locationManager.getLastKnownLocation(provider) ?: continue
                // 选择时间最近、精度最高的位置
                if (bestLocation == null || isBetterLocation(loc, bestLocation)) {
                    bestLocation = loc
                    bestProvider = provider
                }
            } catch (e: SecurityException) {
                Log.w(TAG, "SecurityException for provider $provider: ${e.message}")
            } catch (e: Exception) {
                Log.w(TAG, "Error getting location from $provider: ${e.message}")
            }
        }

        if (bestLocation == null) {
            Log.w(TAG, "No location available from any provider")
            return null
        }

        // 计算定位时间（Unix 秒）
        val locationTime = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            // elapsedRealtimeNanos 更准确
            val elapsedDelta = (SystemClock.elapsedRealtimeNanos() - bestLocation.elapsedRealtimeNanos) / 1_000_000_000L
            (System.currentTimeMillis() / 1000) - elapsedDelta
        } else {
            bestLocation.time / 1000
        }

        return LocationInfo(
            latitude = bestLocation.latitude,
            longitude = bestLocation.longitude,
            accuracy = if (bestLocation.hasAccuracy()) bestLocation.accuracy else -1f,
            timestamp = locationTime,
            provider = bestProvider
        )
    }

    /**
     * 判断新位置是否比旧位置更好。
     */
    private fun isBetterLocation(newLocation: Location, currentBest: Location): Boolean {
        val timeDelta = newLocation.time - currentBest.time
        val isNewer = timeDelta > 0
        val isMuchNewer = timeDelta > 2 * 60 * 1000 // 2分钟
        val isMuchOlder = timeDelta < -2 * 60 * 1000

        if (isMuchNewer) return true
        if (isMuchOlder) return false

        val accuracyDelta = (newLocation.accuracy - currentBest.accuracy).toInt()
        val isLessAccurate = accuracyDelta > 0
        val isMoreAccurate = accuracyDelta < 0
        val isMuchLessAccurate = accuracyDelta > 200

        val isFromSameProvider = newLocation.provider == currentBest.provider

        return when {
            isMoreAccurate -> true
            isNewer && !isLessAccurate -> true
            isNewer && !isMuchLessAccurate && isFromSameProvider -> true
            else -> false
        }
    }

    companion object {
        /**
         * 从消息文本中解析位置信息。
         * 匹配死人开关警告消息中自动附加的位置格式。
         *
         * @return LocationInfo 或 null（消息中无位置信息）
         */
        fun parseFromMessage(text: String): LocationInfo? {
            try {
                val latMatch = Regex("纬度[：:]\\s*([-+]?\\d+\\.?\\d*)").find(text)
                val lonMatch = Regex("经度[：:]\\s*([-+]?\\d+\\.?\\d*)").find(text)
                val accMatch = Regex("精度[：:]\\s*±?(\\d+\\.?\\d*)米?").find(text)
                val timeMatch = Regex("定位时间[：:]\\s*(\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2})").find(text)

                if (latMatch == null || lonMatch == null) return null

                val latitude = latMatch.groupValues[1].toDouble()
                val longitude = lonMatch.groupValues[1].toDouble()
                val accuracy = accMatch?.groupValues?.get(1)?.toFloatOrNull() ?: -1f

                val timestamp = timeMatch?.groupValues?.get(1)?.let {
                    try {
                        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                            .parse(it)?.time?.div(1000) ?: System.currentTimeMillis() / 1000
                    } catch (e: Exception) {
                        System.currentTimeMillis() / 1000
                    }
                } ?: System.currentTimeMillis() / 1000

                return LocationInfo(
                    latitude = latitude,
                    longitude = longitude,
                    accuracy = accuracy,
                    timestamp = timestamp,
                    provider = "parsed"
                )
            } catch (e: Exception) {
                return null
            }
        }
    }
}
