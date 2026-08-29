package com.spider.minecraft.security;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.storage.MessageStore;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 阅后即焚引擎 — 对齐 Spider 的 EphemeralEngine，但做了裁剪。
 *
 * <p>Spider 原版支持三种规则：全局、按 UUID 列表、正则表达式。
 * SpiderMinecraft 裁剪为仅支持"按每个人全开全关"：
 * <ul>
 *   <li>不能全局全开全关</li>
 *   <li>不能正则表达式匹配</li>
 *   <li>只能对每个联系人单独设置开启/关闭</li>
 * </ul>
 *
 * <p>当接收到携带 expire_after_read 标记的消息时：
 * <ol>
 *   <li>渲染消息到聊天框</li>
 *   <li>启动定时器（默认 10 秒后删除）</li>
 *   <li>超时后从本地消息缓存和数据库中删除该条消息</li>
 * </ol>
 */
public class EphemeralEngine {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);

    /** 阅后即焚延迟（毫秒）— 消息渲染后多久删除 */
    private static final long BURN_DELAY_MS = 10000;

    private final MessageStore messageStore;

    /** 每个联系人的阅后即焚开关: peerUuid -> enabled */
    private final ConcurrentHashMap<String, Boolean> perPersonBurn = new ConcurrentHashMap<>();

    /** 正在等待焚烧的消息: msgId -> timer thread */
    private final ConcurrentHashMap<String, Thread> burningMessages = new ConcurrentHashMap<>();

    public EphemeralEngine(MessageStore messageStore) {
        this.messageStore = messageStore;
    }

    /**
     * 设置某个联系人的阅后即焚开关。
     * 这是唯一的控制方式 — 不能全局开关，不能正则。
     */
    public void setBurnForPerson(String peerUuid, boolean enabled) {
        perPersonBurn.put(peerUuid, enabled);
        LOGGER.info("[SpiderMinecraft] Burn-after-read for {}: {}", peerUuid.substring(0, 8), enabled);
    }

    /**
     * 获取某个联系人的阅后即焚状态。
     */
    public boolean isBurnEnabledForPerson(String peerUuid) {
        return perPersonBurn.getOrDefault(peerUuid, false);
    }

    /**
     * 消息已渲染 — 如果携带 expire_after_read 标记，启动焚烧定时器。
     */
    public void onMessageRendered(String msgId, String fromUuid, boolean expireAfterRead) {
        // 只有当消息本身携带 expire_after_read 标记时才焚烧
        // （发送方的 perPersonBurn 决定是否在发送时设置此标记）
        if (!expireAfterRead) return;

        // 如果已经在焚烧队列中，先取消
        Thread existing = burningMessages.remove(msgId);
        if (existing != null) existing.interrupt();

        Thread timer = new Thread(() -> {
            try {
                Thread.sleep(BURN_DELAY_MS);
                // 焚烧：从数据库删除
                messageStore.deleteMessage(msgId);
                burningMessages.remove(msgId);
                LOGGER.info("[SpiderMinecraft] Message burned: {}", msgId);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, "SpiderMC-Burn-" + msgId.substring(0, 8));
        timer.setDaemon(true);
        timer.start();
        burningMessages.put(msgId, timer);
    }

    /**
     * 发送消息前检查 — 如果对目标联系人开启了阅后即焚，返回 true。
     */
    public boolean shouldMarkExpireAfterRead(String toUuid) {
        return isBurnEnabledForPerson(toUuid);
    }

    /**
     * 取消所有正在等待的焚烧（退出时调用）。
     */
    public void shutdown() {
        burningMessages.values().forEach(Thread::interrupt);
        burningMessages.clear();
    }
}
