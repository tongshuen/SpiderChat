package com.spider.minecraft.server;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 令牌桶限速器 — 模仿原版 Spider 服务端的限速功能。
 *
 * <p>支持：
 * <ul>
 *   <li>全局限速（所有用户共享）</li>
 *   <li>用户级限速（每个用户独立配额）</li>
 *   <li>突发容量（允许短时突发）</li>
 *   <li>禁言（完全阻止消息发送）</li>
 * </ul>
 */
public class RateLimiter {

    private static class TokenBucket {
        double tokens;
        final double rate; // 每秒补充的令牌数
        final double capacity; // 桶容量
        long lastRefill;

        TokenBucket(double rate, double capacity) {
            this.rate = rate;
            this.capacity = capacity;
            this.tokens = capacity;
            this.lastRefill = System.currentTimeMillis();
        }

        synchronized boolean tryConsume(double amount) {
            refill();
            if (tokens >= amount) {
                tokens -= amount;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            double elapsed = (now - lastRefill) / 1000.0;
            tokens = Math.min(capacity, tokens + elapsed * rate);
            lastRefill = now;
        }

        synchronized void setRate(double newRate) {
            this.rate = newRate;
        }
    }

    private TokenBucket globalBucket;
    private final Map<String, TokenBucket> userBuckets = new ConcurrentHashMap<>();
    private final Map<String, Long> mutedUsers = new ConcurrentHashMap<>(); // uuid -> 禁言截止时间
    private double globalRate = 100.0; // 全局每秒消息数
    private double globalCapacity = 200.0; // 全局突发容量
    private double userRate = 10.0; // 每用户每秒消息数
    private double userCapacity = 20.0; // 每用户突发容量

    public RateLimiter() {
        this.globalBucket = new TokenBucket(globalRate, globalCapacity);
    }

    /**
     * 检查用户是否可以发送消息。
     * @param userUuid 用户UUID
     * @param cost 本次消耗的令牌数（默认1.0）
     * @return true=允许发送, false=被限速或禁言
     */
    public boolean canSend(String userUuid, double cost) {
        // 检查禁言
        Long muteUntil = mutedUsers.get(userUuid);
        if (muteUntil != null) {
            if (System.currentTimeMillis() < muteUntil) {
                return false;
            } else {
                mutedUsers.remove(userUuid); // 禁言到期自动解除
            }
        }

        // 全局限速
        if (!globalBucket.tryConsume(cost)) {
            return false;
        }

        // 用户级限速
        TokenBucket userBucket = userBuckets.computeIfAbsent(userUuid,
                k -> new TokenBucket(userRate, userCapacity));
        return userBucket.tryConsume(cost);
    }

    /**
     * 简化版：默认消耗1个令牌。
     */
    public boolean canSend(String userUuid) {
        return canSend(userUuid, 1.0);
    }

    /**
     * 禁言用户指定秒数。
     */
    public void muteUser(String userUuid, int seconds) {
        mutedUsers.put(userUuid, System.currentTimeMillis() + seconds * 1000L);
    }

    /**
     * 永久禁言（直到手动解除）。
     */
    public void muteUserPermanent(String userUuid) {
        mutedUsers.put(userUuid, Long.MAX_VALUE);
    }

    /**
     * 解除禁言。
     */
    public void unmuteUser(String userUuid) {
        mutedUsers.remove(userUuid);
    }

    /**
     * 检查用户是否被禁言。
     */
    public boolean isMuted(String userUuid) {
        Long muteUntil = mutedUsers.get(userUuid);
        if (muteUntil == null) return false;
        if (System.currentTimeMillis() >= muteUntil) {
            mutedUsers.remove(userUuid);
            return false;
        }
        return true;
    }

    /**
     * 获取禁言剩余秒数。
     */
    public long getMuteRemainingSeconds(String userUuid) {
        Long muteUntil = mutedUsers.get(userUuid);
        if (muteUntil == null) return 0;
        if (muteUntil == Long.MAX_VALUE) return -1; // 永久禁言
        long remaining = (muteUntil - System.currentTimeMillis()) / 1000;
        return Math.max(0, remaining);
    }

    // ===== 配置方法 =====

    public void setGlobalRate(double rate) {
        this.globalRate = rate;
        this.globalBucket.setRate(rate);
    }

    public void setGlobalCapacity(double capacity) {
        this.globalCapacity = capacity;
        this.globalBucket = new TokenBucket(globalRate, capacity);
    }

    public void setUserRate(double rate) {
        this.userRate = rate;
        userBuckets.values().forEach(b -> b.setRate(rate));
    }

    public void setUserCapacity(double capacity) {
        this.userCapacity = capacity;
    }

    public double getGlobalRate() { return globalRate; }
    public double getUserRate() { return userRate; }
    public int getMutedCount() { return mutedUsers.size(); }

    /**
     * 获取限速状态摘要（用于管理员面板）。
     */
    public String getStatusSummary() {
        return String.format("全局: %.0f/s (容量%.0f), 用户: %.0f/s (容量%.0f), 禁言: %d人",
                globalRate, globalCapacity, userRate, userCapacity, mutedUsers.size());
    }
}
