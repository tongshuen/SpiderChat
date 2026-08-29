package com.spider.minecraft.network;

import com.spider.minecraft.SpiderMinecraft;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.resources.ResourceLocation;

/**
 * SpiderMinecraft 自定义数据包 — 通过 Minecraft 网络通道传输 Spider 协议信令。
 *
 * <p>所有 Spider 协议消息（REGISTER/LOGIN/SEND_MSG/RECV_MSG/回执等）共用此数据包类型，
 * 通过 messageType 字段区分具体信令。使用 JSON 字符串作为 payload，与 Spider 协议兼容。
 */
public class SpiderPacket implements CustomPacketPayload {

    public static final ResourceLocation CHANNEL_ID = ResourceLocation.fromNamespaceAndPath(
            SpiderMinecraft.MOD_ID, "main");

    private final String messageType;
    private final String payload;

    public SpiderPacket(String messageType, String payload) {
        this.messageType = messageType;
        this.payload = payload;
    }

    public String getMessageType() { return messageType; }
    public String getPayload() { return payload; }

    @Override
    public Type<? extends CustomPacketPayload> type() {
        return TYPE;
    }

    public static final Type<SpiderPacket> TYPE = new Type<>(CHANNEL_ID);

    public static final StreamCodec<FriendlyByteBuf, SpiderPacket> STREAM_CODEC = StreamCodec.of(
            (buf, packet) -> {
                buf.writeUtf(packet.messageType, 64);
                buf.writeUtf(packet.payload, 65536);
            },
            buf -> new SpiderPacket(buf.readUtf(64), buf.readUtf(65536))
    );
}
