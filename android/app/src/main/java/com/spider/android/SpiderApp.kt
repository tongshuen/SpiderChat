package com.spider.android

import android.app.Application
import android.util.Log
import com.spider.android.crypto.CryptoManager
import com.spider.android.crypto.KeyManager
import com.spider.android.file.FileTransferManager
import com.spider.android.network.SpiderClient
import com.spider.android.security.DeadmanManager
import com.spider.android.security.DuressManager
import com.spider.android.session.SessionManager
import com.spider.android.storage.ContactStore
import com.spider.android.storage.IdentityStore
import com.spider.android.storage.MessageStore
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/**
 * Spider Android 应用入口 — 全局单例管理。
 */
class SpiderApp : Application() {

    companion object {
        lateinit var instance: SpiderApp
            private set
    }

    lateinit var keyManager: KeyManager
        private set
    lateinit var cryptoManager: CryptoManager
        private set
    lateinit var spiderClient: SpiderClient
        private set
    lateinit var identityStore: IdentityStore
        private set
    lateinit var messageStore: MessageStore
        private set
    lateinit var contactStore: ContactStore
        private set
    lateinit var sessionManager: SessionManager
        private set
    lateinit var duressManager: DuressManager
        private set
    lateinit var deadmanManager: DeadmanManager
        private set
    lateinit var fileTransferManager: FileTransferManager
        private set

    override fun onCreate() {
        super.onCreate()
        instance = this

        // 初始化 BouncyCastle
        if (Security.getProvider("BC") == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        Log.i("SpiderApp", "BouncyCastle initialized")

        // 初始化核心组件
        keyManager = KeyManager(this)
        cryptoManager = CryptoManager(keyManager)
        spiderClient = SpiderClient()
        identityStore = IdentityStore(this)
        messageStore = MessageStore(this)
        contactStore = ContactStore(this)
        sessionManager = SessionManager(this, keyManager, cryptoManager, spiderClient, identityStore)
        duressManager = DuressManager(this, keyManager, spiderClient, sessionManager)
        deadmanManager = DeadmanManager(this, keyManager, spiderClient)
        fileTransferManager = FileTransferManager(this, keyManager, cryptoManager, spiderClient)

        Log.i("SpiderApp", "All components initialized")
    }
}
