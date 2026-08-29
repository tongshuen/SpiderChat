package com.spider.minecraft.gui.tabs;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.config.SpiderConfig;
import com.spider.minecraft.gui.SpiderMainScreen;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Checkbox;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 设置标签页 — 颜色、自动下载、已读回执、发现等配置。
 */
public class SettingsTab {

    private final SpiderMainScreen parent;
    private final int x, y, width, height;
    private boolean visible = false;

    private Checkbox autoDownloadCheck;
    private Checkbox readReceiptsCheck;
    private Checkbox autoDiscoveryCheck;
    private Checkbox showNotificationsCheck;
    private Checkbox showHudButtonCheck;
    private Checkbox burnModeCheck;
    private Button saveButton;
    private Button resetButton;
    private Button wipeDataButton;
    private List<String> infoLines = new ArrayList<>();

    public SettingsTab(SpiderMainScreen parent, int x, int y, int width, int height) {
        this.parent = parent;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        initWidgets();
    }

    @SuppressWarnings("unchecked")
    private void initWidgets() {
        int col1 = x + 8;
        int col2 = x + width / 2 + 8;
        int row1 = y + 8;
        int row2 = y + 34;
        int row3 = y + 60;

        autoDownloadCheck = Checkbox.builder(Component.literal("自动下载文件"), parent.getMinecraft().font)
                .pos(col1, row1)
                .selected(SpiderConfig.CLIENT.autoDownload.get())
                .onValueChange((cb, val) -> {})
                .build();

        readReceiptsCheck = Checkbox.builder(Component.literal("已读回执"), parent.getMinecraft().font)
                .pos(col1, row2)
                .selected(SpiderConfig.CLIENT.readReceipts.get())
                .onValueChange((cb, val) -> {})
                .build();

        autoDiscoveryCheck = Checkbox.builder(Component.literal("自动服务发现"), parent.getMinecraft().font)
                .pos(col1, row3)
                .selected(SpiderConfig.CLIENT.autoDiscovery.get())
                .onValueChange((cb, val) -> {})
                .build();

        showNotificationsCheck = Checkbox.builder(Component.literal("显示发现通知"), parent.getMinecraft().font)
                .pos(col2, row1)
                .selected(SpiderConfig.CLIENT.showDiscoveryNotifications.get())
                .onValueChange((cb, val) -> {})
                .build();

        showHudButtonCheck = Checkbox.builder(Component.literal("显示HUD按钮"), parent.getMinecraft().font)
                .pos(col2, row2)
                .selected(SpiderConfig.CLIENT.showHudButton.get())
                .onValueChange((cb, val) -> {})
                .build();

        burnModeCheck = Checkbox.builder(Component.literal("全局阅后即焚"), parent.getMinecraft().font)
                .pos(col2, row3)
                .selected(false)
                .onValueChange((cb, val) -> {})
                .build();

        saveButton = Button.builder(Component.literal("保存设置"), btn -> saveSettings())
                .bounds(x + 8, y + height - 60, 100, 20)
                .build();

        resetButton = Button.builder(Component.literal("恢复默认"), btn -> resetSettings())
                .bounds(x + 115, y + height - 60, 100, 20)
                .build();

        wipeDataButton = Button.builder(Component.literal("§c擦除所有数据").withStyle(s -> s.withColor(0xFFFF5555)), btn -> wipeData())
                .bounds(x + width - 130, y + height - 60, 120, 20)
                .build();

        parent.addRenderableWidget(autoDownloadCheck);
        parent.addRenderableWidget(readReceiptsCheck);
        parent.addRenderableWidget(autoDiscoveryCheck);
        parent.addRenderableWidget(showNotificationsCheck);
        parent.addRenderableWidget(showHudButtonCheck);
        parent.addRenderableWidget(burnModeCheck);
        parent.addRenderableWidget(saveButton);
        parent.addRenderableWidget(resetButton);
        parent.addRenderableWidget(wipeDataButton);
    }

    private void saveSettings() {
        try {
            SpiderConfig.CLIENT.autoDownload.set(autoDownloadCheck.selected());
            SpiderConfig.CLIENT.readReceipts.set(readReceiptsCheck.selected());
            SpiderConfig.CLIENT.autoDiscovery.set(autoDiscoveryCheck.selected());
            SpiderConfig.CLIENT.showDiscoveryNotifications.set(showNotificationsCheck.selected());
            SpiderConfig.CLIENT.showHudButton.set(showHudButtonCheck.selected());
            parent.sendClientMessage("§a设置已保存");
            refreshInfo();
        } catch (Exception e) {
            parent.sendClientMessage("§c保存失败: " + e.getMessage());
        }
    }

    private void resetSettings() {
        autoDownloadCheck.selected = true;
        readReceiptsCheck.selected = true;
        autoDiscoveryCheck.selected = true;
        showNotificationsCheck.selected = true;
        showHudButtonCheck.selected = true;
        burnModeCheck.selected = false;
        parent.sendClientMessage("§e已恢复默认（点击保存生效）");
    }

    private void wipeData() {
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getDuressManager() != null && mod.getKeyManager() != null) {
            // 需要胁迫PIN确认
            parent.sendClientMessage("§c危险操作！请使用 /spiderminecraft duress <pin> 命令擦除数据");
        }
    }

    private void refreshInfo() {
        infoLines.clear();
        infoLines.add("§7=== 版本信息 ===");
        infoLines.add("§fSpiderMinecraft v1.0.0 (MC 26.2 + NeoForge)");
        infoLines.add("");
        infoLines.add("§7=== 安全状态 ===");
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null) {
            if (mod.getKeyManager() != null && mod.getKeyManager().isUnlocked()) {
                infoLines.add("§a身份已解锁");
                infoLines.add("§fUUID: " + mod.getKeyManager().getIdentityUuid());
                infoLines.add("§f胁迫PIN: " + (mod.getKeyManager().hasDuressPin() ? "§a已设置" : "§e未设置"));
            } else {
                infoLines.add("§e身份未解锁");
            }
            if (mod.getCryptoManager() != null) {
                infoLines.add("§a加密引擎: AES-256-GCM + X25519 + Ed25519");
            }
        }
        infoLines.add("");
        infoLines.add("§7=== 提示 ===");
        infoLines.add("§7所有设置保存在 config/spiderminecraft-client.toml");
        infoLines.add("§7CLI 命令仍然完全可用: /spiderminecraft help");
    }

    public void refresh() {
        refreshInfo();
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!visible) return;

        // 信息区域
        int infoY = y + 90;
        int infoHeight = height - 100;
        graphics.fill(x, infoY, x + width, infoY + infoHeight, 0xFF0F1923);
        graphics.fill(x + 1, infoY + 1, x + width - 1, infoY + infoHeight - 1, 0xFF1A1A2E);

        int lineY = infoY + 6;
        for (String line : infoLines) {
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(line),
                        x + 8, lineY, 0xFFFFFFFF, false);
            }
            lineY += 12;
        }
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
        autoDownloadCheck.visible = visible;
        readReceiptsCheck.visible = visible;
        autoDiscoveryCheck.visible = visible;
        showNotificationsCheck.visible = visible;
        showHudButtonCheck.visible = visible;
        burnModeCheck.visible = visible;
        saveButton.visible = visible;
        resetButton.visible = visible;
        wipeDataButton.visible = visible;
    }
}
