package com.spider.minecraft.gui.tabs;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.crypto.CryptoManager;
import com.spider.minecraft.crypto.KeyManager;
import com.spider.minecraft.gui.SpiderMainScreen;
import com.spider.minecraft.protocol.Protocol;
import com.spider.minecraft.storage.MessageStore;
import com.spider.minecraft.util.JsonUtil;
import com.google.gson.JsonObject;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.List;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * 聊天标签页 — 显示和发送加密消息。
 * 模仿原版 Spider 客户端的聊天界面。
 * 消息元数据（时间戳+位置）通过鼠标悬停显示，不在消息文本中显示。
 */
public class ChatTab {

    private static final String META_START = "\u200b[SPIDER-META]";
    private static final String META_END = "[/SPIDER-META]\u200b";

    /** 从消息文本中移除元数据部分 */
    private static String stripMetadata(String text) {
        int start = text.indexOf(META_START);
        if (start < 0) return text;
        int end = text.indexOf(META_END, start);
        if (end < 0) return text;
        return text.substring(0, start) + text.substring(end + META_END.length());
    }

    /** 从消息文本中解析元数据 JSON */
    private static com.google.gson.JsonObject parseMetadata(String text) {
        int start = text.indexOf(META_START);
        if (start < 0) return null;
        int end = text.indexOf(META_END, start);
        if (end < 0) return null;
        String jsonStr = text.substring(start + META_START.length(), end);
        try {
            return com.google.gson.JsonParser.parseString(jsonStr).getAsJsonObject();
        } catch (Exception e) {
            return null;
        }
    }

    private final SpiderMainScreen parent;
    private final int x, y, width, height;
    private boolean visible = false;

    private EditBox targetUuidBox;
    private EditBox messageBox;
    private Button sendButton;
    private Button refreshButton;

    private List<String> messageLog = new ArrayList<>();
    private int scrollOffset = 0;
    private static final int MAX_VISIBLE_MESSAGES = 12;

    public ChatTab(SpiderMainScreen parent, int x, int y, int width, int height) {
        this.parent = parent;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        initWidgets();
    }

    private void initWidgets() {
        int inputY = y + height - 30;

        targetUuidBox = new EditBox(parent.getMinecraft().font, x + 4, inputY, 150, 18,
                Component.literal("对方UUID"));
        targetUuidBox.setMaxLength(64);
        targetUuidBox.setHint("对方 UUID 或名称");

        messageBox = new EditBox(parent.getMinecraft().font, x + 160, inputY, width - 250, 18,
                Component.literal("消息"));
        messageBox.setMaxLength(500);
        messageBox.setHint("输入加密消息...");

        sendButton = Button.builder(Component.literal("发送"), btn -> sendMessage())
                .bounds(x + width - 85, inputY - 1, 80, 20)
                .build();

        refreshButton = Button.builder(Component.literal("刷新"), btn -> refresh())
                .bounds(x + width - 85, y + 2, 80, 16)
                .build();

        parent.addRenderableWidget(targetUuidBox);
        parent.addRenderableWidget(messageBox);
        parent.addRenderableWidget(sendButton);
        parent.addRenderableWidget(refreshButton);
    }

    private void sendMessage() {
        SpiderMinecraftMod mod = parent.getMod();
        if (mod == null || !mod.getSessionManager().isAuthenticated()) {
            parent.sendClientMessage("§c请先登录");
            return;
        }
        String target = targetUuidBox.getValue().trim();
        String text = messageBox.getValue().trim();
        if (target.isEmpty() || text.isEmpty()) {
            parent.sendClientMessage("§c请填写对方UUID和消息内容");
            return;
        }

        try {
            CryptoManager cm = mod.getCryptoManager();
            KeyManager km = mod.getKeyManager();
            JsonObject encrypted = cm.encryptMessage(text, target, "", "");

            JsonObject msg = new JsonObject();
            msg.addProperty("type", Protocol.SEND_MSG);
            msg.addProperty("from_uuid", km.getIdentityUuid());
            msg.addProperty("to_uuid", target);
            msg.addProperty("msg_id", java.util.UUID.randomUUID().toString());
            msg.addProperty("timestamp", System.currentTimeMillis() / 1000);
            msg.add("encrypted_envelope", encrypted);

            if (mod.getEphemeralEngine() != null && mod.getEphemeralEngine().shouldMarkExpireAfterRead(target)) {
                msg.addProperty("expire_after_read", true);
            }

            String connId = mod.getSessionManager().getCurrentConnectionId();
            if (connId != null) {
                mod.getDirectConnector().sendMessage(connId, JsonUtil.toJson(msg));
                messageLog.add("§a[我 -> " + target.substring(0, Math.min(8, target.length())) + "] §r" + text);
                messageBox.setValue("");
                parent.sendClientMessage("§a消息已加密发送");
            } else {
                parent.sendClientMessage("§c无可用连接");
            }
        } catch (Exception e) {
            parent.sendClientMessage("§c发送失败: " + e.getMessage());
        }
    }

    public void refresh() {
        messageLog.clear();
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getMessageStore() != null && mod.getKeyManager() != null) {
            try {
                MessageStore store = mod.getMessageStore();
                // 加载最近消息
                messageLog.add("§7=== 最近消息 ===");
                messageLog.add("§7消息存储已就绪，共 " + store.getMessageCount() + " 条");
                messageLog.add("§7提示: 输入对方UUID后即可发送加密消息");
            } catch (Exception e) {
                messageLog.add("§c加载消息失败: " + e.getMessage());
            }
        } else {
            messageLog.add("§e请先登录以查看消息");
        }
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!visible) return;

        // 消息区域背景
        int msgAreaY = y + 22;
        int msgAreaHeight = height - 55;
        graphics.fill(x, msgAreaY, x + width, msgAreaY + msgAreaHeight, 0xFF0F1923);
        graphics.fill(x + 1, msgAreaY + 1, x + width - 1, msgAreaY + msgAreaHeight - 1, 0xFF1A1A2E);

        // 渲染消息（过滤元数据，只显示纯文本）
        int lineY = msgAreaY + 4;
        int startIdx = Math.max(0, Math.min(scrollOffset, Math.max(0, messageLog.size() - MAX_VISIBLE_MESSAGES)));
        int endIdx = Math.min(messageLog.size(), startIdx + MAX_VISIBLE_MESSAGES);

        int hoveredIdx = -1;
        for (int i = startIdx; i < endIdx; i++) {
            String rawMsg = messageLog.get(i);
            String displayMsg = stripMetadata(rawMsg);
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(displayMsg),
                        x + 6, lineY, 0xFFFFFFFF, false);
            }
            // 检测鼠标悬停
            if (mouseX >= x && mouseX <= x + width &&
                mouseY >= lineY - 2 && mouseY <= lineY + 10) {
                hoveredIdx = i;
            }
            lineY += 12;
        }

        // 悬停 tooltip（显示发送时间 + 位置元数据）
        if (hoveredIdx >= 0) {
            String rawMsg = messageLog.get(hoveredIdx);
            com.google.gson.JsonObject meta = parseMetadata(rawMsg);
            List<String> tooltipLines = new ArrayList<>();
            if (meta != null && meta.has("ts")) {
                long ts = meta.get("ts").getAsLong();
                String timeStr = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(ts * 1000));
                tooltipLines.add("发送时间：" + timeStr);
            }
            if (meta != null) {
                if (meta.has("lat")) tooltipLines.add("纬度：" + meta.get("lat").getAsString());
                if (meta.has("lon")) tooltipLines.add("经度：" + meta.get("lon").getAsString());
                if (meta.has("r")) tooltipLines.add("不确定度：" + meta.get("r").getAsString());
            }
            if (!tooltipLines.isEmpty()) {
                int tx = mouseX + 12;
                int ty = mouseY + 12;
                int tw = 180;
                int th = tooltipLines.size() * 12 + 8;
                graphics.fill(tx - 2, ty - 2, tx + tw, ty + th, 0xFF000000);
                graphics.fill(tx - 1, ty - 1, tx + tw - 1, ty + th - 1, 0xFF222222);
                for (int j = 0; j < tooltipLines.size(); j++) {
                    graphics.drawString(parent.getMinecraft().font, Component.literal(tooltipLines.get(j)),
                            tx + 4, ty + 4 + j * 12, 0xFFDDDDDD, false);
                }
            }
        }

        // 滚动提示
        if (messageLog.size() > MAX_VISIBLE_MESSAGES) {
            String scrollInfo = (startIdx + 1) + "-" + endIdx + " / " + messageLog.size();
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(scrollInfo),
                        x + width - 60, msgAreaY + msgAreaHeight - 12, 0xFF888888, false);
            }
        }
    }

    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (!visible) return false;
        scrollOffset -= (int) Math.signum(scrollY);
        scrollOffset = Math.max(0, Math.min(scrollOffset, Math.max(0, messageLog.size() - MAX_VISIBLE_MESSAGES)));
        return true;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
        targetUuidBox.setVisible(visible);
        messageBox.setVisible(visible);
        sendButton.visible = visible;
        refreshButton.visible = visible;
    }
}
