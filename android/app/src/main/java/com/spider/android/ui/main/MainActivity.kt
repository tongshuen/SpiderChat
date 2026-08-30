package com.spider.android.ui.main

import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.spider.android.R
import com.spider.android.SpiderApp
import com.spider.android.crypto.CryptoManager
import com.spider.android.model.Contact
import com.spider.android.model.Message
import com.spider.android.ui.login.LoginActivity
import com.spider.android.ui.settings.SettingsActivity
import org.json.JSONArray
import org.json.JSONObject

/**
 * 主界面 — 底部导航切换聊天/联系人/设置。
 * 处理所有网络消息回调：离线消息、SEND_OK、送达回执、心跳等。
 */
class MainActivity : AppCompatActivity() {

    private val TAG = "MainActivity"
    private val app by lazy { application as SpiderApp }

    private lateinit var bottomNav: BottomNavigationView
    private var chatFragment: ChatFragment? = null
    private var contactsFragment: ContactsFragment? = null

    var currentContact: Contact? = null
        private set

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bottomNav = findViewById(R.id.bottomNav)
        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_chat -> {
                    showFragment(getChatFragment())
                    true
                }
                R.id.nav_contacts -> {
                    showFragment(getContactsFragment())
                    true
                }
                R.id.nav_settings -> {
                    startActivity(Intent(this, SettingsActivity::class.java))
                    true
                }
                else -> false
            }
        }

        if (savedInstanceState == null) {
            bottomNav.selectedItemId = R.id.nav_chat
        }

        setupMessageCallbacks()
    }

    private fun getChatFragment(): ChatFragment {
        if (chatFragment == null) {
            chatFragment = ChatFragment()
        }
        return chatFragment!!
    }

    private fun getContactsFragment(): ContactsFragment {
        if (contactsFragment == null) {
            contactsFragment = ContactsFragment()
        }
        return contactsFragment!!
    }

    private fun showFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragmentContainer, fragment)
            .commit()
    }

    fun selectContact(contact: Contact) {
        currentContact = contact
        bottomNav.selectedItemId = R.id.nav_chat
        getChatFragment().onContactSelected(contact)
    }

    /**
     * 发送加密消息。
     */
    fun sendMessage(text: String) {
        val contact = currentContact ?: return
        val myUuid = app.keyManager.getUuid()
        if (myUuid.isEmpty()) return

        val encrypted = app.cryptoManager.encryptMessage(
            text, contact.uuid, contact.x25519Pub, app.keyManager.getIdentity()?.ed25519Private ?: ""
        )
        if (encrypted == null) {
            Toast.makeText(this, "消息加密失败", Toast.LENGTH_SHORT).show()
            return
        }

        val encryptedPayload = JSONObject().apply {
            put("type", "text")
            put("ciphertext", encrypted.ciphertext)
            put("nonce", encrypted.nonce)
            put("tag", encrypted.tag)
            put("ephemeral_pub", encrypted.ephemeralPubKey)
            put("aad", encrypted.aad)
        }

        val signData = "send|${contact.uuid}|${System.currentTimeMillis() / 1000}"
        val signature = app.cryptoManager.signData(
            signData.toByteArray(),
            app.keyManager.getIdentity()?.ed25519Private ?: ""
        ) ?: ""

        val clientMsgId = "cli_${System.currentTimeMillis()}_${(0..9999).random()}"
        app.spiderClient.sendMessage(contact.uuid, encryptedPayload, signature, clientMsgId)

        val message = Message(
            fromUuid = myUuid,
            toUuid = contact.uuid,
            text = text,
            isSent = true,
            deliveryStatus = "pending",
            clientMsgId = clientMsgId
        )
        app.messageStore.addMessage(message)
        getChatFragment().addMessage(message)
    }

    /**
     * 发送文件给当前联系人。
     */
    fun sendFile(uri: android.net.Uri) {
        val contact = currentContact ?: return
        app.fileTransferManager.sendFile(
            contactUuid = contact.uuid,
            contactX25519Pub = contact.x25519Pub,
            uri = uri
        ) { success, error ->
            runOnUiThread {
                if (success) {
                    Toast.makeText(this, "文件已发送", Toast.LENGTH_SHORT).show()
                    currentContact?.let {
                        val myUuid = app.keyManager.getUuid()
                        val history = app.messageStore.getMessagesWith(it.uuid, myUuid)
                        getChatFragment().refreshMessages(history)
                    }
                } else {
                    Toast.makeText(this, "文件发送失败: ${error ?: "未知错误"}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun setupMessageCallbacks() {
        app.spiderClient.onRecvMessage = { msg ->
            runOnUiThread { handleReceivedMessage(msg) }
        }

        app.spiderClient.onOfflineQueue = { messages ->
            runOnUiThread { handleOfflineMessages(messages) }
        }

        app.spiderClient.onSendOk = { msg ->
            runOnUiThread {
                val clientMsgId = msg.optString("client_msg_id", "")
                val serverMsgId = msg.optString("server_msg_id", "")
                if (clientMsgId.isNotEmpty()) {
                    app.messageStore.onSendOk(clientMsgId, serverMsgId)
                    currentContact?.let {
                        val myUuid = app.keyManager.getUuid()
                        val history = app.messageStore.getMessagesWith(it.uuid, myUuid)
                        getChatFragment().refreshMessages(history)
                    }
                }
            }
        }

        app.spiderClient.onDeliveryReceipt = { msg ->
            runOnUiThread {
                val serverMsgId = msg.optString("server_msg_id", "")
                if (serverMsgId.isNotEmpty()) {
                    app.messageStore.updateDeliveryStatus(serverMsgId, "delivered")
                    currentContact?.let {
                        val myUuid = app.keyManager.getUuid()
                        val history = app.messageStore.getMessagesWith(it.uuid, myUuid)
                        getChatFragment().refreshMessages(history)
                    }
                }
            }
        }

        app.spiderClient.onReadReceipt = { msg ->
            runOnUiThread {
                val serverMsgId = msg.optString("server_msg_id", "")
                if (serverMsgId.isNotEmpty()) {
                    app.messageStore.updateDeliveryStatus(serverMsgId, "read")
                }
            }
        }

        app.spiderClient.onPubkeyResult = { msg ->
            runOnUiThread {
                val uuid = msg.optString("uuid", "")
                val x25519Pub = msg.optString("x25519_pub", "")
                val ed25519Pub = msg.optString("ed25519_pub", "")
                if (uuid.isNotEmpty() && x25519Pub.isNotEmpty()) {
                    app.contactStore.updateContactPubkeys(uuid, x25519Pub, ed25519Pub)
                    getContactsFragment().refreshContacts()
                }
            }
        }

        app.spiderClient.onDeadmanAck = { msg ->
            Log.i(TAG, "Deadman ACK: stored=${msg.optBoolean("stored")}")
        }

        app.spiderClient.onRateLimited = { reason ->
            runOnUiThread {
                Toast.makeText(this, "发送过快：$reason", Toast.LENGTH_SHORT).show()
            }
        }

        app.spiderClient.onError = { error ->
            runOnUiThread {
                Log.e(TAG, "Server error: $error")
                Toast.makeText(this, "错误：$error", Toast.LENGTH_LONG).show()
            }
        }

        app.spiderClient.onPing = { timestamp ->
            Log.d(TAG, "Server PING at $timestamp, PONG sent automatically")
        }

        app.spiderClient.onDisconnect = {
            runOnUiThread {
                Toast.makeText(this, "连接已断开", Toast.LENGTH_SHORT).show()
                startActivity(Intent(this, LoginActivity::class.java))
                finish()
            }
        }
    }

    private fun handleOfflineMessages(messages: JSONArray) {
        Log.i(TAG, "Received ${messages.length()} offline messages")
        for (i in 0 until messages.length()) {
            val msg = messages.optJSONObject(i) ?: continue
            handleReceivedMessage(msg, isOffline = true)
        }
        currentContact?.let {
            val myUuid = app.keyManager.getUuid()
            val history = app.messageStore.getMessagesWith(it.uuid, myUuid)
            getChatFragment().refreshMessages(history)
        }
    }

    private fun handleReceivedMessage(msg: JSONObject, isOffline: Boolean = false) {
        val fromUuid = msg.optString("from_uuid", "")
        val toUuid = msg.optString("to_uuid", "")
        val isDeadmanWarning = msg.optBoolean("deadman_warning", false)
        val systemMessage = msg.optString("system_message", "")

        if (isDeadmanWarning && systemMessage.isNotEmpty()) {
            val warningText = "⚠️ [死人开关警告] $systemMessage"
            val message = Message(
                fromUuid = fromUuid,
                toUuid = toUuid,
                text = warningText,
                isSent = false,
                isDeadmanWarning = true,
                deliveryStatus = "delivered"
            )
            app.messageStore.addMessage(message)
            if (app.contactStore.getContactByUuid(fromUuid) == null) {
                app.contactStore.addContact(Contact(uuid = fromUuid, displayName = "未知用户"))
            }
            if (currentContact?.uuid == fromUuid) {
                getChatFragment().addMessage(message)
            }
            Toast.makeText(this, "收到死人开关警告消息", Toast.LENGTH_LONG).show()
            return
        }

        val encryptedPayload = msg.optJSONObject("encrypted_payload")
        if (encryptedPayload == null) {
            Log.w(TAG, "Received message without encrypted_payload from $fromUuid")
            return
        }

        val payloadType = encryptedPayload.optString("type", "text")

        // 文件消息处理
        if (payloadType == "file") {
            handleReceivedFileMessage(fromUuid, toUuid, encryptedPayload, msg, isOffline)
            return
        }

        var contact = app.contactStore.getContactByUuid(fromUuid)
        if (contact == null) {
            app.spiderClient.queryPubkey(fromUuid)
            app.contactStore.addContact(Contact(uuid = fromUuid, displayName = "未知用户"))
            contact = app.contactStore.getContactByUuid(fromUuid)
        }

        if (contact?.ed25519Pub.isNullOrEmpty()) {
            Log.w(TAG, "No ed25519 pubkey for $fromUuid, querying...")
            app.spiderClient.queryPubkey(fromUuid)
            return
        }

        val encrypted = CryptoManager.EncryptedMessage(
            ciphertext = encryptedPayload.optString("ciphertext"),
            nonce = encryptedPayload.optString("nonce"),
            tag = encryptedPayload.optString("tag"),
            ephemeralPubKey = encryptedPayload.optString("ephemeral_pub", encryptedPayload.optString("ephemeral_pubkey")),
            aad = encryptedPayload.optString("aad")
        )

        val plaintext = app.cryptoManager.decryptMessage(
            encrypted,
            app.keyManager.getIdentity()?.x25519Private ?: "",
            contact.ed25519Pub
        )

        if (plaintext == null) {
            Log.e(TAG, "Failed to decrypt message from $fromUuid")
            return
        }

        val serverMsgId = msg.optString("server_msg_id", "")
        val message = Message(
            fromUuid = fromUuid,
            toUuid = toUuid,
            text = plaintext,
            isSent = false,
            deliveryStatus = "delivered",
            serverMsgId = serverMsgId
        )
        app.messageStore.addMessage(message)

        if (serverMsgId.isNotEmpty() && !isOffline) {
            app.spiderClient.sendDeliveryReceipt(fromUuid, serverMsgId)
        }

        if (currentContact?.uuid == fromUuid) {
            getChatFragment().addMessage(message)
        }
    }

    /**
     * 处理接收到的文件消息：解密、保存、显示。
     */
    private fun handleReceivedFileMessage(
        fromUuid: String, toUuid: String,
        encryptedPayload: JSONObject, msg: JSONObject, isOffline: Boolean
    ) {
        var contact = app.contactStore.getContactByUuid(fromUuid)
        if (contact == null) {
            app.spiderClient.queryPubkey(fromUuid)
            app.contactStore.addContact(Contact(uuid = fromUuid, displayName = "未知用户"))
            contact = app.contactStore.getContactByUuid(fromUuid)
        }

        if (contact?.ed25519Pub.isNullOrEmpty()) {
            Log.w(TAG, "No ed25519 pubkey for file from $fromUuid")
            app.spiderClient.queryPubkey(fromUuid)
            return
        }

        val fileMessage = app.fileTransferManager.handleReceivedFile(
            fromUuid = fromUuid,
            encryptedPayload = encryptedPayload,
            senderEd25519Pub = contact.ed25519Pub
        )

        if (fileMessage != null) {
            val serverMsgId = msg.optString("server_msg_id", "")
            val messageWithServerId = fileMessage.copy(serverMsgId = serverMsgId)
            app.messageStore.addMessage(messageWithServerId)

            if (serverMsgId.isNotEmpty() && !isOffline) {
                app.spiderClient.sendDeliveryReceipt(fromUuid, serverMsgId)
            }

            if (currentContact?.uuid == fromUuid) {
                getChatFragment().addMessage(messageWithServerId)
            }
            Toast.makeText(this, "收到文件: ${fileMessage.fileName}", Toast.LENGTH_SHORT).show()
        } else {
            Log.e(TAG, "Failed to process received file from $fromUuid")
            Toast.makeText(this, "文件接收失败", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onBackPressed() {
        if (bottomNav.selectedItemId != R.id.nav_chat) {
            bottomNav.selectedItemId = R.id.nav_chat
        } else {
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        app.spiderClient.onRecvMessage = null
        app.spiderClient.onOfflineQueue = null
        app.spiderClient.onSendOk = null
        app.spiderClient.onDeliveryReceipt = null
        app.spiderClient.onReadReceipt = null
        app.spiderClient.onPubkeyResult = null
        app.spiderClient.onDeadmanAck = null
        app.spiderClient.onRateLimited = null
        app.spiderClient.onError = null
        app.spiderClient.onPing = null
        app.spiderClient.onDisconnect = null
    }
}
