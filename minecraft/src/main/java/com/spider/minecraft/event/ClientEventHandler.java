package com.spider.minecraft.event;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.config.SpiderConfig;
import com.spider.minecraft.gui.SpiderHudOverlay;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.network.chat.Component;
import net.neoforged.api.distmarker.Dist;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.fml.common.EventBusSubscriber;
import net.neoforged.neoforge.client.event.ClientPlayerNetworkEvent;
import net.neoforged.neoforge.client.event.InputEvent;
import net.neoforged.neoforge.client.event.RenderGuiEvent;
import net.neoforged.neoforge.event.tick.ClientTickEvent;

/**
 * 客户端事件处理器。
 *
 * <p>负责：
 * <ul>
 *   <li>HUD 覆盖层渲染（Spider 按钮）</li>
 *   <li>HUD 按钮点击检测（打开 Spider GUI）</li>
 *   <li>玩家加入/离开时的会话管理</li>
 *   <li>服务发现定期清理</li>
 * </ul>
 *
 * <p>CLI 命令仍然完全可用，GUI 是额外的图形交互入口。
 */
@EventBusSubscriber(modid = "spiderminecraft", value = Dist.CLIENT)
public class ClientEventHandler {

    private final SpiderMinecraftMod mod;
    private int tickCounter = 0;

    public ClientEventHandler(SpiderMinecraftMod mod) {
        this.mod = mod;
    }

    @SubscribeEvent
    public void onClientTick(ClientTickEvent.Post event) {
        tickCounter++;
        if (tickCounter % 100 == 0 && mod.getDiscovery() != null) {
            mod.getDiscovery().cleanupExpired();
        }
    }

    /**
     * 渲染 HUD 覆盖层（Spider 按钮）。
     */
    @SubscribeEvent
    public static void onRenderGui(RenderGuiEvent.Post event) {
        SpiderHudOverlay.onRenderGui(event);
    }

    /**
     * 处理鼠标点击，检测是否点击了 HUD 上的 Spider 按钮。
     */
    @SubscribeEvent
    public static void onMouseClick(InputEvent.MouseButton.Pre event) {
        if (event.getButton() != 0) return;
        Minecraft mc = Minecraft.getInstance();
        if (mc.player == null || mc.screen != null) return;
        if (!SpiderConfig.CLIENT.showHudButton.get()) return;

        int width = mc.getWindow().getGuiScaledWidth();
        int height = mc.getWindow().getGuiScaledHeight();
        double mouseX = mc.mouseHandler.xpos() * width / mc.getWindow().getWidth();
        double mouseY = mc.mouseHandler.ypos() * height / mc.getWindow().getHeight();

        if (SpiderHudOverlay.handleClick(mouseX, mouseY, width, height)) {
            event.setCanceled(true);
        }
    }

    @SubscribeEvent
    public void onPlayerJoin(ClientPlayerNetworkEvent.LoggingIn event) {
        if (SpiderConfig.CLIENT.showDiscoveryNotifications.get()) {
            event.getPlayer().displayClientMessage(
                    Component.literal("[SpiderMinecraft] 已连接。点击右上角 Spider 按钮打开GUI，或输入 /spiderminecraft help 查看命令")
                            .withStyle(ChatFormatting.DARK_AQUA), false);
        }
    }

    @SubscribeEvent
    public void onPlayerLeave(ClientPlayerNetworkEvent.LoggingOut event) {
        if (mod.getSessionManager() != null) {
            mod.getSessionManager().logout();
        }
        if (mod.getEphemeralEngine() != null) {
            mod.getEphemeralEngine().shutdown();
        }
    }
}
