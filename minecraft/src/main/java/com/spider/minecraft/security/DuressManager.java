package com.spider.minecraft.security;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.crypto.KeyManager;
import com.spider.minecraft.network.SessionManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 胁迫 PIN 管理器 — 对齐 Spider 的 duress PIN 特性。
 *
 * <p>由于 Minecraft 聊天栏无法输入隐藏字符，无法实现"登录时输入胁迫 PIN"。
 * 因此实现"命令式胁迫"：
 * <ul>
 *   <li>用户输入 /spiderminecraft duress <pin></li>
 *   <li>如果 PIN 匹配身份文件中的胁迫 PIN 哈希</li>
 *   <li>立即执行 wipe_all_data()（删除 identity.json 和密钥）</li>
 *   <li>自动向服务端发送 COMPROMISED 加密信令</li>
 * </ul>
 *
 * <p>胁迫 PIN 为 6 位数字，存储 SHA-256 哈希，不存储明文。
 */
public class DuressManager {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);

    private final KeyManager keyManager;
    private final SessionManager sessionManager;

    public DuressManager(KeyManager keyManager, SessionManager sessionManager) {
        this.keyManager = keyManager;
        this.sessionManager = sessionManager;
    }

    /**
     * 触发胁迫流程。
     *
     * @param pin 用户输入的 PIN
     * @return true 如果是胁迫 PIN（已触发擦除），false 如果不是
     */
    public boolean triggerDuress(String pin) {
        if (pin == null || pin.length() != SpiderMinecraft.DURESS_PIN_LENGTH || !pin.matches("\\d+")) {
            return false;
        }

        if (!keyManager.checkDuressPin(pin)) {
            return false;
        }

        LOGGER.warn("[SpiderMinecraft] DURESS PIN DETECTED — initiating wipe protocol");

        // 1. 先发送 COMPROMISED 信令（在密钥还在内存中时签名）
        if (sessionManager != null && sessionManager.isAuthenticated()) {
            sessionManager.sendCompromised();
            // 给服务器一点时间接收
            try { Thread.sleep(500); } catch (InterruptedException ignored) {}
        }

        // 2. 执行 wipe_all_data()
        keyManager.wipeAllData();

        // 3. 断开连接
        if (sessionManager != null) {
            sessionManager.logout();
        }

        LOGGER.warn("[SpiderMinecraft] Wipe protocol complete — all data erased");
        return true;
    }

    /**
     * 设置胁迫 PIN（需要先解锁身份）。
     */
    public boolean setDuressPin(String pin) {
        if (pin == null || pin.length() != SpiderMinecraft.DURESS_PIN_LENGTH || !pin.matches("\\d+")) {
            return false;
        }
        if (!keyManager.isUnlocked()) {
            return false;
        }
        try {
            keyManager.setDuressPin(pin);
            LOGGER.info("[SpiderMinecraft] Duress PIN set");
            return true;
        } catch (Exception e) {
            LOGGER.error("[SpiderMinecraft] Failed to set duress PIN: {}", e.getMessage());
            return false;
        }
    }

    public boolean hasDuressPin() {
        return keyManager.hasDuressPin();
    }
}
