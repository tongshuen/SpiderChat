package com.spider.minecraft.network;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import net.minecraft.server.level.ServerPlayer;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.neoforge.network.PacketDistributor;
import net.neoforged.neoforge.network.event.RegisterPayloadHandlersEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import net.neoforged.neoforge.network.registration.PayloadRegistrar;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;

/**
 * SpiderMinecraft 网络管理器 — 注册自定义网络通道与数据包处理器。
 *
 * <p>使用 NeoForge 自定义 payload 通道，完全独立于 Minecraft 原版协议。
 * 未安装本模组的客户端/服务端忽略此通道，原版互联不受影响。
 */
public class SpiderNetwork {

    private final ConcurrentHashMap<String, BiConsumer<SpiderPacket, IPayloadContext>> handlers =
            new ConcurrentHashMap<>();

    public void register() {
        SpiderMinecraftMod.get().getModEventBus().addListener(this::onRegisterPayloads);
    }

    @SubscribeEvent
    public void onRegisterPayloads(RegisterPayloadHandlersEvent event) {
        PayloadRegistrar registrar = event.registrar(SpiderMinecraft.MOD_ID)
                .versioned(String.valueOf(SpiderMinecraft.PROTOCOL_VERSION_INT));

        registrar.playToServer(SpiderPacket.TYPE, SpiderPacket.STREAM_CODEC, this::handleServerBound);
        registrar.playToClient(SpiderPacket.TYPE, SpiderPacket.STREAM_CODEC, this::handleClientBound);

        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Network channel registered: {}", SpiderPacket.CHANNEL_ID);
    }

    public void registerHandler(String messageType, BiConsumer<SpiderPacket, IPayloadContext> handler) {
        handlers.put(messageType, handler);
    }

    private void handleServerBound(SpiderPacket packet, IPayloadContext context) {
        context.enqueueWork(() -> {
            BiConsumer<SpiderPacket, IPayloadContext> handler = handlers.get(packet.getMessageType());
            if (handler != null) handler.accept(packet, context);
        });
    }

    private void handleClientBound(SpiderPacket packet, IPayloadContext context) {
        context.enqueueWork(() -> {
            BiConsumer<SpiderPacket, IPayloadContext> handler = handlers.get(packet.getMessageType());
            if (handler != null) handler.accept(packet, context);
        });
    }

    public static void sendToServer(SpiderPacket packet) {
        PacketDistributor.sendToServer(packet);
    }

    public static void sendToPlayer(ServerPlayer player, SpiderPacket packet) {
        PacketDistributor.sendToPlayer(player, packet);
    }

    public static void broadcast(SpiderPacket packet) {
        PacketDistributor.sendToAllPlayers(packet);
    }
}
