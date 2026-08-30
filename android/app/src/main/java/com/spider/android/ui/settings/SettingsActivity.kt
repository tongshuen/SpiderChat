package com.spider.android.ui.settings

import android.Manifest
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.spider.android.R
import com.spider.android.SpiderApp

/**
 * 设置界面 — 死人开关、胁迫 PIN、通用设置。
 */
class SettingsActivity : AppCompatActivity() {

    companion object {
        private const val REQUEST_LOCATION_PERMISSION = 1001

        /**
         * 默认警告文本 — 对齐 Minecraft 版的简洁安全警告风格，
         * 但更贴合 Android 实际（提及自动定位、手机端等）。
         */
        const val DEFAULT_WARNING_MESSAGE =
            "⚠️ 死人开关自动警告：本机用户可能已遭遇不测。\n" +
            "本消息由 Spider Android 客户端在长期未登录后自动触发。\n" +
            "最后已知位置（经纬度、精度、定位时间）已自动附加在下方。\n" +
            "请尽快联系本人或向当地警方求助。"
    }

    private val app by lazy { application as SpiderApp }

    // 死人开关
    private lateinit var swDeadman: Switch
    private lateinit var etWarningMessage: EditText
    private lateinit var etRecipientUuid: EditText
    private lateinit var etGraceDays: EditText
    private lateinit var btnSaveDeadman: Button
    private lateinit var btnUseDefaultWarning: Button
    private lateinit var tvDeadmanStatus: TextView

    // 胁迫 PIN
    private lateinit var btnChangeDuress: Button
    private lateinit var tvDuressStatus: TextView

    // 通用
    private lateinit var swAutoDownload: Switch
    private lateinit var swReadReceipts: Switch

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        initViews()
        loadSettings()
        setupListeners()
    }

    private fun initViews() {
        swDeadman = findViewById(R.id.swDeadman)
        etWarningMessage = findViewById(R.id.etWarningMessage)
        etRecipientUuid = findViewById(R.id.etRecipientUuid)
        etGraceDays = findViewById(R.id.etGraceDays)
        btnSaveDeadman = findViewById(R.id.btnSaveDeadman)
        btnUseDefaultWarning = findViewById(R.id.btnUseDefaultWarning)
        tvDeadmanStatus = findViewById(R.id.tvDeadmanStatus)
        btnChangeDuress = findViewById(R.id.btnChangeDuress)
        tvDuressStatus = findViewById(R.id.tvDuressStatus)
        swAutoDownload = findViewById(R.id.swAutoDownload)
        swReadReceipts = findViewById(R.id.swReadReceipts)
    }

    private fun loadSettings() {
        val cfg = app.deadmanManager.getConfig()
        swDeadman.isChecked = cfg.enabled
        etWarningMessage.setText(cfg.warningMessage)
        etRecipientUuid.setText(cfg.recipientUuid)
        etGraceDays.setText(cfg.graceDays.toString())
        updateDeadmanStatus()

        tvDuressStatus.text = if (app.duressManager.hasDuressPin()) {
            "胁迫 PIN：已设置"
        } else {
            "胁迫 PIN：未设置"
        }

        val prefs = getSharedPreferences("spider_settings", MODE_PRIVATE)
        swAutoDownload.isChecked = prefs.getBoolean("auto_download", true)
        swReadReceipts.isChecked = prefs.getBoolean("read_receipts", true)
    }

    private fun setupListeners() {
        btnSaveDeadman.setOnClickListener { saveDeadmanSettings() }

        btnUseDefaultWarning.setOnClickListener {
            etWarningMessage.setText(DEFAULT_WARNING_MESSAGE)
            Toast.makeText(this, "已填入默认警告文本", Toast.LENGTH_SHORT).show()
        }

        swDeadman.setOnCheckedChangeListener { _, isChecked ->
            etWarningMessage.isEnabled = isChecked
            etRecipientUuid.isEnabled = isChecked
            etGraceDays.isEnabled = isChecked
            btnUseDefaultWarning.isEnabled = isChecked
            // 启用死人开关时请求定位权限（用于自动附加位置）
            if (isChecked) {
                requestLocationPermissionIfNeeded()
            }
        }

        btnChangeDuress.setOnClickListener { showChangeDuressDialog() }

        swAutoDownload.setOnCheckedChangeListener { _, isChecked ->
            getSharedPreferences("spider_settings", MODE_PRIVATE)
                .edit().putBoolean("auto_download", isChecked).apply()
        }
        swReadReceipts.setOnCheckedChangeListener { _, isChecked ->
            getSharedPreferences("spider_settings", MODE_PRIVATE)
                .edit().putBoolean("read_receipts", isChecked).apply()
        }
    }

    /**
     * 请求定位权限（如果尚未授予）。
     * 死人开关启用时需要定位权限，以便在警告消息中自动附加经纬度。
     */
    private fun requestLocationPermissionIfNeeded() {
        val hasFine = ContextCompat.checkSelfPermission(
            this, Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        val hasCoarse = ContextCompat.checkSelfPermission(
            this, Manifest.permission.ACCESS_COARSE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED

        if (!hasFine && !hasCoarse) {
            AlertDialog.Builder(this)
                .setTitle("需要定位权限")
                .setMessage("死人开关启用后，警告消息将自动附加当前经纬度、精度和定位时间，" +
                        "以便收件人了解您的最后已知位置。是否授予定位权限？")
                .setPositiveButton("授予") { _, _ ->
                    ActivityCompat.requestPermissions(
                        this,
                        arrayOf(
                            Manifest.permission.ACCESS_FINE_LOCATION,
                            Manifest.permission.ACCESS_COARSE_LOCATION
                        ),
                        REQUEST_LOCATION_PERMISSION
                    )
                }
                .setNegativeButton("暂不", null)
                .show()
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_LOCATION_PERMISSION) {
            val granted = grantResults.isNotEmpty() &&
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
            if (granted) {
                Toast.makeText(this, "定位权限已授予，警告消息将自动附加位置", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "未授予定位权限，警告消息将不包含位置信息", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun saveDeadmanSettings() {
        val enabled = swDeadman.isChecked
        val warningMessage = etWarningMessage.text.toString().trim()
        val recipientUuid = etRecipientUuid.text.toString().trim()
        val graceDays = etGraceDays.text.toString().trim().toIntOrNull() ?: 7

        if (enabled) {
            if (warningMessage.isEmpty()) {
                Toast.makeText(this, "请输入警告消息内容", Toast.LENGTH_SHORT).show()
                return
            }
            if (recipientUuid.isEmpty()) {
                Toast.makeText(this, "请输入预定收件人 UUID", Toast.LENGTH_SHORT).show()
                return
            }
        }

        app.deadmanManager.setConfig(
            enabled = enabled,
            warningMessage = warningMessage,
            recipientUuid = recipientUuid,
            graceDays = graceDays,
            autoSync = true
        )
        updateDeadmanStatus()
        Toast.makeText(this, "死人开关设置已保存", Toast.LENGTH_SHORT).show()
    }

    private fun updateDeadmanStatus() {
        tvDeadmanStatus.text = app.deadmanManager.getStatusSummary()
    }

    private fun showChangeDuressDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_change_duress, null)
        val etOldPin = view.findViewById<EditText>(R.id.etOldPin)
        val etNewPin = view.findViewById<EditText>(R.id.etNewPin)
        val etConfirmPin = view.findViewById<EditText>(R.id.etConfirmPin)

        // 如果未设置胁迫 PIN，隐藏旧 PIN 输入
        if (!app.duressManager.hasDuressPin()) {
            etOldPin.visibility = android.view.View.GONE
        }

        AlertDialog.Builder(this)
            .setTitle("设置胁迫 PIN")
            .setView(view)
            .setPositiveButton("保存") { _, _ ->
                val oldPin = etOldPin.text.toString().trim()
                val newPin = etNewPin.text.toString().trim()
                val confirmPin = etConfirmPin.text.toString().trim()

                if (app.duressManager.hasDuressPin() && oldPin.isEmpty()) {
                    Toast.makeText(this, "请输入旧胁迫 PIN", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (newPin.length != 6 || !newPin.matches(Regex("\\d{6}"))) {
                    Toast.makeText(this, "新胁迫 PIN 必须为6位数字", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (newPin != confirmPin) {
                    Toast.makeText(this, "两次输入的 PIN 不一致", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (app.duressManager.setDuressPin(newPin)) {
                    tvDuressStatus.text = "胁迫 PIN：已设置"
                    Toast.makeText(this, "胁迫 PIN 已设置", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "设置失败", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("取消", null)
            .show()
    }
}
