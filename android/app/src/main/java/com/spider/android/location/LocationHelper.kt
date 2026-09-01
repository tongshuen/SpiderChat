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
        /** 纬度转为 DMS 格式（精确到 1″），如 30°15′20″N */
        fun latitudeDms(): String = toDms(latitude, isLat = true)

        /** 经度转为 DMS 格式（精确到 1″），如 104°03′45″E */
        fun longitudeDms(): String = toDms(longitude, isLat = false)

        /** 不确定度转为 r=xxx′ 或 r=xxx″ 格式 */
        fun accuracyR(): String = formatAccuracy(accuracy)

        /** 定位时间格式化为精确到秒的字符串 */
        fun timeString(): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .format(Date(timestamp * 1000))

        /**
         * 生成元数据字符串，附加到消息末尾（零宽字符包裹，不在消息中显示）。
         * 包含：发送时间戳、DMS 经纬度、r 不确定度。
         */
        fun toMetadataString(sendTimestamp: Long = System.currentTimeMillis() / 1000): String {
            val ts = sendTimestamp
            val lat = latitudeDms()
            val lon = longitudeDms()
            val r = accuracyR()
            return "\u200b[SPIDER-META]{\"ts\":$ts,\"lat\":\"$lat\",\"lon\":\"$lon\",\"r\":\"$r\"}[/SPIDER-META]\u200b"
        }

        /** 格式化为长按/悬停显示的完整信息（时间戳 + DMS 经纬度 + r 不确定度） */
        fun toDetailString(sendTimestamp: Long = timestamp): String {
            val sendTime = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                .format(Date(sendTimestamp * 1000))
            return buildString {
                appendLine("发送时间：$sendTime")
                appendLine("定位时间：${timeString()}")
                appendLine("纬度：${latitudeDms()}")
                appendLine("经度：${longitudeDms()}")
                append("不确定度：${accuracyR()}")
            }
        }
    }

    companion object {
        private const val ZWSP = "\u200b"
        private const val META_START = "$ZWSP[SPIDER-META]"
        private const val META_END = "[/SPIDER-META]$ZWSP"

        /** 十进制经纬度转 DMS（精确到 1″） */
        fun toDms(degrees: Double, isLat: Boolean): String {
            val abs = kotlin.math.abs(degrees)
            val d = abs.toInt()
            val mFull = (abs - d) * 60
            val m = mFull.toInt()
            val s = ((mFull - m) * 60).toInt().coerceIn(0, 59)
            val dir = when {
                isLat && degrees >= 0 -> "N"
                isLat && degrees < 0 -> "S"
                !isLat && degrees >= 0 -> "E"
                else -> "W"
            }
            return "%d°%02d′%02d″%s".format(d, m, s, dir)
        }

        /** 不确定度（米）转为 r=xxx′ 或 r=xxx″ 格式 */
        fun formatAccuracy(accuracyMeters: Float): String {
            if (accuracyMeters < 0) return "r=未知"
            // 1分纬度 ≈ 1855.3米，1秒 ≈ 30.92米
            val seconds = accuracyMeters / 30.92
            return if (seconds < 60) {
                "r=%d″".format(seconds.toInt().coerceAtLeast(1))
            } else {
                val minutes = seconds / 60
                "r=%d′".format(minutes.toInt().coerceAtLeast(1))
            }
        }

        /** 从消息文本中移除元数据部分，返回纯消息文本 */
        fun stripMetadata(text: String): String {
            val start = text.indexOf(META_START)
            if (start < 0) return text
            val end = text.indexOf(META_END, start)
            if (end < 0) return text
            return text.substring(0, start) + text.substring(end + META_END.length)
        }

        /**
         * 从消息文本中解析元数据。
         * @return Pair(LocationInfo?, sendTimestamp?) 或 null
         */
        fun parseMetadata(text: String): Pair<LocationInfo?, Long?>? {
            val start = text.indexOf(META_START)
            if (start < 0) return null
            val end = text.indexOf(META_END, start)
            if (end < 0) return null
            val jsonStr = text.substring(start + META_START.length, end)
            return try {
                val obj = org.json.JSONObject(jsonStr)
                val ts = obj.optLong("ts", 0)
                val latStr = obj.optString("lat", "")
                val lonStr = obj.optString("lon", "")
                val rStr = obj.optString("r", "")
                val lat = parseDms(latStr)
                val lon = parseDms(lonStr)
                val acc = parseR(rStr)
                if (lat == null || lon == null) return null
                Pair(LocationInfo(lat, lon, acc, ts, "meta"), ts)
            } catch (e: Exception) {
                null
            }
        }

        /** 解析 DMS 字符串为十进制度数 */
        private fun parseDms(dms: String): Double? {
            return try {
                val m = Regex("""(\d+)°(\d+)′(\d+)″([NSEW])""").find(dms) ?: return null
                val d = m.groupValues[1].toInt()
                val min = m.groupValues[2].toInt()
                val s = m.groupValues[3].toInt()
                val dir = m.groupValues[4]
                var valDeg = d + min / 60.0 + s / 3600.0
                if (dir == "S" || dir == "W") valDeg = -valDeg
                valDeg
            } catch (e: Exception) {
                null
            }
        }

        /** 解析 r=xxx′ 或 r=xxx″ 为米 */
        private fun parseR(r: String): Float {
            return try {
                val m = Regex("""r=(\d+)([′″])""").find(r) ?: return -1f
                val value = m.groupValues[1].toFloat()
                if (m.groupValues[2] == "″") (value * 30.92f) else (value * 1855.3f)
            } catch (e: Exception) {
                -1f
            }
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
}
