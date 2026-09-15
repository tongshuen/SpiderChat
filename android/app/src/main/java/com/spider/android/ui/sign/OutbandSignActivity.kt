package com.spider.android.ui.sign

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.spider.android.R
import com.spider.android.SpiderApp
import com.spider.android.crypto.OutbandSign
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 带外签名工具界面。
 *
 * - 选择模式（账号所有权挑战 / 自定义文本签名）；
 * - 输入文本后调用 [OutbandSign.sign]，从 [SpiderApp.keyManager] 取当前身份的
 *   Ed25519 私钥与 UUID，全程本地签名，私钥不出本机；
 * - 校验区使用当前身份的 Ed25519 公钥对粘贴进来的签名串做本地闭环校验
 *   （也可用于把 Python 端生成的签名串粘进来验证跨端互通）。
 */
class OutbandSignActivity : AppCompatActivity() {

    private lateinit var rgMode: RadioGroup
    private lateinit var etInputText: EditText
    private lateinit var btnSign: Button
    private lateinit var tvSignResult: TextView
    private lateinit var btnCopySign: Button
    private lateinit var etVerifySig: EditText
    private lateinit var etVerifyOriginal: EditText
    private lateinit var btnVerify: Button
    private lateinit var tvVerifyResult: TextView

    private var lastSignedString: String = ""

    private val app by lazy { application as SpiderApp }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_outband_sign)

        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = "带外签名工具"

        rgMode = findViewById(R.id.rgMode)
        etInputText = findViewById(R.id.etInputText)
        btnSign = findViewById(R.id.btnSign)
        tvSignResult = findViewById(R.id.tvSignResult)
        btnCopySign = findViewById(R.id.btnCopySign)
        etVerifySig = findViewById(R.id.etVerifySig)
        etVerifyOriginal = findViewById(R.id.etVerifyOriginal)
        btnVerify = findViewById(R.id.btnVerify)
        tvVerifyResult = findViewById(R.id.tvVerifyResult)

        rgMode.setOnCheckedChangeListener { _, _ -> updateHint() }
        btnSign.setOnClickListener { doSign() }
        btnCopySign.setOnClickListener { copySign() }
        btnVerify.setOnClickListener { doVerify() }

        updateHint()
    }

    override fun onSupportNavigateUp(): Boolean {
        finish()
        return true
    }

    private fun currentMode(): String =
        if (rgMode.checkedRadioButtonId == R.id.rbContent) {
            OutbandSign.MODE_CONTENT
        } else {
            OutbandSign.MODE_OWNERSHIP
        }

    private fun updateHint() {
        etInputText.hint = if (currentMode() == OutbandSign.MODE_CONTENT) {
            "请输入待签名的消息原文"
        } else {
            "请输入服务器下发的挑战 nonce"
        }
    }

    private fun doSign() {
        val identity = app.keyManager.getIdentity()
        if (identity == null) {
            Toast.makeText(this, "尚未解锁身份，请先登录", Toast.LENGTH_SHORT).show()
            return
        }
        val text = etInputText.text.toString()
        if (text.isEmpty()) {
            Toast.makeText(this, "请输入待签名文本 / 挑战 nonce", Toast.LENGTH_SHORT).show()
            return
        }
        val mode = currentMode()
        val sig = OutbandSign.sign(text, mode, identity.ed25519Private, identity.uuid)
        if (sig == null) {
            lastSignedString = ""
            tvSignResult.text = "签名失败，请检查密钥"
            return
        }
        lastSignedString = sig
        tvSignResult.text = sig
    }

    private fun copySign() {
        if (lastSignedString.isEmpty()) {
            Toast.makeText(this, "还没有签名结果", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("spider-sig", lastSignedString))
        Toast.makeText(this, "签名串已复制到剪贴板", Toast.LENGTH_SHORT).show()
    }

    private fun doVerify() {
        val sigStr = etVerifySig.text.toString().trim()
        val original = etVerifyOriginal.text.toString()
        if (sigStr.isEmpty()) {
            Toast.makeText(this, "请输入待核验的签名串", Toast.LENGTH_SHORT).show()
            return
        }
        val identity = app.keyManager.getIdentity()
        if (identity == null) {
            Toast.makeText(this, "尚未解锁身份", Toast.LENGTH_SHORT).show()
            return
        }
        // 校验使用当前身份的公钥（本地自测 / 跨端互通粘贴验证）
        val result = OutbandSign.verify(sigStr, original, identity.ed25519Public)
        val ts = if (result.timestamp > 0L) {
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                .format(Date(result.timestamp * 1000L))
        } else {
            "—"
        }
        tvVerifyResult.text = buildString {
            append("校验结果：").append(if (result.valid) "✅ 有效" else "❌ 无效\n")
            if (result.error.isNotEmpty()) {
                append("原因：").append(result.error).append("\n")
            }
            append("签名账号 UUID：").append(if (result.uuid.isEmpty()) "—" else result.uuid).append("\n")
            append("签名时间：").append(ts).append("\n")
            append("签名模式：").append(result.mode.ifEmpty { "—" })
        }
    }
}
