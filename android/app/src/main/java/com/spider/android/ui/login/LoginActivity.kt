package com.spider.android.ui.login

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.spider.android.R
import com.spider.android.SpiderApp
import com.spider.android.ui.main.MainActivity

/**
 * 登录/注册界面。
 */
class LoginActivity : AppCompatActivity() {

    private lateinit var etServerHost: EditText
    private lateinit var etServerPort: EditText
    private lateinit var etPin: EditText
    private lateinit var etDuressPin: EditText
    private lateinit var etDisplayName: EditText
    private lateinit var btnLogin: Button
    private lateinit var btnRegister: Button
    private lateinit var tvStatus: TextView

    private val app by lazy { application as SpiderApp }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        etServerHost = findViewById(R.id.etServerHost)
        etServerPort = findViewById(R.id.etServerPort)
        etPin = findViewById(R.id.etPin)
        etDuressPin = findViewById(R.id.etDuressPin)
        etDisplayName = findViewById(R.id.etDisplayName)
        btnLogin = findViewById(R.id.btnLogin)
        btnRegister = findViewById(R.id.btnRegister)
        tvStatus = findViewById(R.id.tvStatus)

        // 如果已有身份，隐藏注册相关字段
        if (app.identityStore.hasIdentity()) {
            etDuressPin.visibility = android.view.View.GONE
            etDisplayName.visibility = android.view.View.GONE
            btnRegister.visibility = android.view.View.GONE
        }

        btnLogin.setOnClickListener { handleLogin() }
        btnRegister.setOnClickListener { handleRegister() }

        // 设置胁迫检测回调
        app.sessionManager.onDuressDetected = {
            runOnUiThread {
                Toast.makeText(this, "胁迫 PIN 已触发，数据已擦除", Toast.LENGTH_LONG).show()
                finish()
            }
        }

        app.sessionManager.onLoginSuccess = {
            runOnUiThread {
                tvStatus.text = getString(R.string.connected)
                startActivity(Intent(this, MainActivity::class.java))
                finish()
            }
        }

        app.sessionManager.onLoginFailed = { reason ->
            runOnUiThread {
                tvStatus.text = "${getString(R.string.login_failed)}: $reason"
            }
        }
    }

    private fun handleLogin() {
        val host = etServerHost.text.toString().trim()
        val portStr = etServerPort.text.toString().trim()
        val pin = etPin.text.toString().trim()

        if (host.isEmpty() || portStr.isEmpty() || pin.isEmpty()) {
            tvStatus.text = "请填写服务器地址、端口和 PIN"
            return
        }
        if (!com.spider.android.crypto.KeyManager.isValidPinFormat(pin)) {
            tvStatus.text = getString(R.string.invalid_pin)
            return
        }

        val port = portStr.toIntOrNull()
        if (port == null || port !in 1..65535) {
            tvStatus.text = "端口无效"
            return
        }

        tvStatus.text = getString(R.string.connecting)
        btnLogin.isEnabled = false

        app.sessionManager.login(host, port, pin) { success, error ->
            runOnUiThread {
                btnLogin.isEnabled = true
                if (!success && error != null) {
                    tvStatus.text = error
                }
            }
        }
    }

    private fun handleRegister() {
        val host = etServerHost.text.toString().trim()
        val portStr = etServerPort.text.toString().trim()
        val pin = etPin.text.toString().trim()
        val duressPin = etDuressPin.text.toString().trim()
        val displayName = etDisplayName.text.toString().trim()

        if (host.isEmpty() || portStr.isEmpty() || pin.isEmpty() || displayName.isEmpty()) {
            tvStatus.text = "请填写所有必填字段"
            return
        }
        if (!com.spider.android.crypto.KeyManager.isValidPinFormat(pin)) {
            tvStatus.text = "PIN 必须为 8/10/12/16 位纯数字"
            return
        }
        if (com.spider.android.crypto.KeyManager.isPalindrome(pin)) {
            tvStatus.text = "解锁 PIN 不可为回文数"
            return
        }
        if (duressPin.isNotEmpty() && !com.spider.android.crypto.KeyManager.isValidPinFormat(duressPin)) {
            tvStatus.text = "胁迫 PIN 必须为 8/10/12/16 位纯数字"
            return
        }

        val port = portStr.toIntOrNull()
        if (port == null || port !in 1..65535) {
            tvStatus.text = "端口无效"
            return
        }

        tvStatus.text = "注册中..."
        btnRegister.isEnabled = false

        app.sessionManager.register(host, port, pin, duressPin, displayName) { success, error ->
            runOnUiThread {
                btnRegister.isEnabled = true
                if (success) {
                    tvStatus.text = "注册成功，请登录"
                    etDuressPin.visibility = android.view.View.GONE
                    etDisplayName.visibility = android.view.View.GONE
                    btnRegister.visibility = android.view.View.GONE
                } else {
                    tvStatus.text = "${getString(R.string.registration_failed)}: ${error ?: "未知错误"}"
                }
            }
        }
    }
}
