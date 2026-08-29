package com.spider.minecraft.gui;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.config.SpiderConfig;
import net.minecraft.client.Minecraft;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.network.chat.Component;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.client.event.RenderGuiEvent;

/**
 * Spider HUD 覆盖层 — 在游戏界面右上角显示 Spider 按钮。
 * 点击后打开 Spider 主 GUI 界面。
 * CLI 命令仍然完全可用，GUI 是额外的交互入口。
 */
@EventBusSubscriber(modid = "spiderminecraft", value = Dist.CLIENT)
public class SpiderHudOverlay {

    private static Button spiderButton;
    private static int buttonX = 0;
    private static int buttonY = 0;
    private static boolean initialized = false;

    @SubscribeEvent
    public static void onRenderGui(RenderGuiEvent.Post event) {
        Minecraft mc = Minecraft.getInstance();
        if (mc.player == null || mc.options.hideGui) return;
        if (!SpiderConfig.CLIENT.showHudButton.get()) return;

        GuiGraphics graphics = event.getGuiGraphics();
        int width = mc.getWindow().getGuiScaledWidth();

        // 按钮位置：右上角，在小地图/状态栏下方
        buttonX = width - 70;
        buttonY = 5;

        // 绘制按钮背景
        int statusColor = 0xFF00AA00; // 绿色=在线
        if (SpiderMinecraftMod.get() != null && SpiderMinecraftMod.get().getSessionManager() != null) {
            if (!SpiderMinecraftMod.get().getSessionManager().isAuthenticated()) {
                statusColor = 0xFFAAAA00; // 黄色=未登录
            }
        } else {
            statusColor = 0xFFAA0000; // 红色=未初始化
        }

        // 绘制状态指示灯
        graphics.fill(buttonX - 8, buttonY + 4, buttonX - 2, buttonY + 14, statusColor);
        graphics.fill(buttonX - 7, buttonY + 5, buttonX - 3, buttonY + 13, 0xFF000000 | (statusColor & 0x00FFFFFF));

        // 绘制按钮文字
        Component label = Component.literal("Spider").withStyle(style -> style.withBold(true));
        graphics.drawString(mc.font, label, buttonX, buttonY + 5, 0xFFFFFFFF, true);

        // 绘制下划线（可点击提示）
        graphics.fill(buttonX, buttonY + 16, buttonX + 42, buttonY + 17, 0x80FFFFFF);

        // 处理点击（通过鼠标事件）
        if (!initialized) {
            initialized = true;
        }
    }

    /**
     * 检查鼠标点击是否命中 Spider 按钮。
     * 在 ClientEventHandler 的鼠标点击事件中调用。
     */
    public static boolean handleClick(double mouseX, double mouseY, int width, int height) {
        int bx = width - 70;
        int by = 5;
        if (mouseX >= bx - 10 && mouseX <= bx + 50 && mouseY >= by - 2 && mouseY <= by + 20) {
            openSpiderGui();
            return true;
        }
        return false;
    }

    /**
     * 打开 Spider 主 GUI 界面。
     */
    public static void openSpiderGui() {
        Minecraft mc = Minecraft.getInstance();
        if (mc.player != null) {
            mc.setScreen(new SpiderMainScreen());
        }
    }

    /**
     * 获取按钮显示状态文本（用于 tooltip）。
     */
    public static Component getStatusTooltip() {
        if (SpiderMinecraftMod.get() == null) {
            return Component.literal("Spider: 未初始化");
        }
        var sm = SpiderMinecraftMod.get().getSessionManager();
        if (sm == null) {
            return Component.literal("Spider: 初始化中...");
        }
        if (sm.isAuthenticated()) {
            return Component.literal("Spider: 已连接 — " + sm.getCurrentServerHost());
        }
        return Component.literal("Spider: 未登录 — 点击打开 GUI");
    }
}
