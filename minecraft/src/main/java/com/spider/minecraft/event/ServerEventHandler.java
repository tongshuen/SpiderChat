package com.spider.minecraft.event;

import com.google.gson.JsonObject;
import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.command.SpiderCommand;
import com.spider.minecraft.config.SpiderConfig;
import com.spider.minecraft.crypto.CryptoManager;
import com.spider.minecraft.network.DirectConnector;
import com.spider.minecraft.network.SpiderNetwork;
import com.spider.minecraft.network.SpiderPacket;
import com.spider.minecraft.network.SessionManager;
import com.spider.minecraft.protocol.Protocol;
import com.spider.minecraft.storage.OfflineStore;
import com.spider.minecraft.util.JsonUtil;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.neoforged.bus.api.SubscribeEvent;
import net.neoforged.neoforge.event.RegisterCommandsEvent;
import net.neoforged.neoforge.event.entity.player.PlayerEvent;
import net.neoforged.neoforge.event.server.ServerStartingEvent;
import net.neoforged.neoforge.event.server.ServerStoppingEvent;
import net.neoforged.neoforge.network.handling.IPayloadContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 服务端事件处理器 — 处理 Spider 协议信令、命令注册、玩家事件。
 */
public class ServerEventHandler {

    private static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);

    private final SpiderMinecraftMod mod;
    private MinecraftServer server;

    public ServerEventHandler(SpiderMinecraftMod mod) {
        this.mod = mod;
    }

    @SubscribeEvent
    public void onRegisterCommands(RegisterCommandsEvent event) {
        SpiderCommand.register(event.getDispatcher());
    }

    @SubscribeEvent
    public void onServerStarting(ServerStartingEvent event) {
        this.server = event.getServer();
        LOGGER.info("[SpiderMinecraft] Server starting...");

        // 注册 TCP 直连消息处理器
        DirectConnector dc = mod.getDirectConnector();
        if (dc != null) {
            dc.setOnMessageReceived(this::handleDirectMessage);
            dc.startServer();
        }

        // 注册 MC 网络通道处理器
        SpiderNetwork network = mod.getNetwork();
        if (network != null) {
            network.registerHandler(Protocol.SEND_MSG, this::handleSendMsg);
            network.registerHandler(Protocol.REGISTER, this::handleRegister);
            network.registerHandler(Protocol.LOGIN, this::handleLogin);
        }

        if (SpiderConfig.COMMON.announceServer.get() && mod.getDiscovery() != null) {
            mod.getDiscovery().startServer();
        }
        LOGGER.info("[SpiderMinecraft] Server networking initialized.");
    }

    @SubscribeEvent
    public void onServerStopping(ServerStoppingEvent event) {
        LOGGER.info("[SpiderMinecraft] Server stopping...");
        if (mod.getDiscovery() != null) mod.getDiscovery().stopServer();
        if (mod.getDirectConnector() != null) mod.getDirectConnector().stopServer();
        if (mod.getDatabaseManager() != null) mod.getDatabaseManager().close();
    }

    @SubscribeEvent
    public void onPlayerJoin(PlayerEvent.PlayerLoggedInEvent event) {
        if (event.getEntity() instanceof ServerPlayer player) {
            String uuid = player.getUUID().toString();
            LOGGER.info("[SpiderMinecraft] Player joined: {} ({})", player.getName().getString(), uuid.substring(0, 8));

            // 推送离线消息
            OfflineStore os = mod.getOfflineStore();
            if (os != null && os.getQueueSize(uuid) > 0) {
                var messages = os.drainQueue(uuid);
                for (var msg : messages) {
                    SpiderPacket packet = new SpiderPacket(msg.msgType, msg.payload);
                    SpiderNetwork.sendToPlayer(player, packet);
                }
                LOGGER.info("[SpiderMinecraft] Pushed {} offline messages to {}", messages.size(), uuid.substring(0, 8));
            }
        }
    }

    @SubscribeEvent
    public void onPlayerLeave(PlayerEvent.PlayerLoggedOutEvent event) {
        if (event.getEntity() instanceof ServerPlayer player) {
            LOGGER.info("[SpiderMinecraft] Player left: {}", player.getUUID().toString().substring(0, 8));
        }
    }

    // ===== 协议处理 =====

    private void handleDirectMessage(String connId, JsonObject obj) {
        String type = obj.has("type") ? obj.get("type").getAsString() : "";
        SessionManager sm = mod.getSessionManager();

        switch (type) {
            case Protocol.AUTH_OK -> { if (sm != null) sm.onAuthOk(obj); }
            case Protocol.AUTH_FAIL -> { if (sm != null) sm.onAuthFail(obj); }
            case Protocol.RECV_MSG -> handleRecvMsg(obj);
            case Protocol.DELIVERY_RECEIPT -> handleReceipt(obj, "delivered");
            case Protocol.READ_RECEIPT -> handleReceipt(obj, "read");
            case Protocol.OFFLINE_QUEUE -> handleOfflineQueue(obj);
            case Protocol.COMPROMISED -> handleCompromised(obj);
            case Protocol.FILE_SEND -> handleFileReceive(obj);
            default -> LOGGER.debug("[SpiderMinecraft] Unknown direct message type: {}", type);
        }
    }

    private void handleSendMsg(SpiderPacket packet, IPayloadContext ctx) {
        // 中继消息到目标
        try {
            JsonObject obj = JsonUtil.parse(packet.getPayload());
            String toUuid = obj.get("to_uuid").getAsString();
            // 检查目标是否在线
            if (server != null) {
                for (ServerPlayer player : server.getPlayerList().getAllPlayers()) {
                    if (player.getUUID().toString().equals(toUuid)) {
                        SpiderNetwork.sendToPlayer(player,
                                new SpiderPacket(Protocol.RECV_MSG, packet.getPayload()));
                        // 发送送达回执
                        sendDeliveryReceipt(obj);
                        return;
                    }
                }
            }
            // 不在线 — 存入离线队列
            OfflineStore os = mod.getOfflineStore();
            if (os != null) {
                os.enqueue(toUuid, Protocol.RECV_MSG, packet.getPayload());
                LOGGER.info("[SpiderMinecraft] Message queued offline for {}", toUuid.substring(0, 8));
            }
        } catch (Exception e) {
            LOGGER.error("[SpiderMinecraft] handleSendMsg error: {}", e.getMessage());
        }
    }

    private void handleRegister(SpiderPacket packet, IPayloadContext ctx) {
        // 简化：直接返回 AUTH_OK
        try {
            JsonObject response = new JsonObject();
            response.addProperty("type", Protocol.AUTH_OK);
            response.addProperty("session_id", java.util.UUID.randomUUID().toString());
            if (ctx.player() instanceof ServerPlayer player) {
                SpiderNetwork.sendToPlayer(player, new SpiderPacket(Protocol.AUTH_OK, JsonUtil.toJson(response)));
            }
        } catch (Exception e) {
            LOGGER.error("[SpiderMinecraft] handleRegister error: {}", e.getMessage());
        }
    }

    private void handleLogin(SpiderPacket packet, IPayloadContext ctx) {
        handleRegister(packet, ctx); // 简化处理
    }

    private void handleRecvMsg(JsonObject obj) {
        // 客户端收到消息 — 解密并显示
        LOGGER.info("[SpiderMinecraft] Received message from {}",
                obj.has("from_uuid") ? obj.get("from_uuid").getAsString().substring(0, 8) : "unknown");
    }

    private void handleReceipt(JsonObject obj, String status) {
        String msgId = obj.has("msg_id") ? obj.get("msg_id").getAsString() : "";
        if (mod.getMessageStore() != null && !msgId.isEmpty()) {
            mod.getMessageStore().updateDeliveryStatus(msgId, status);
        }
    }

    private void handleOfflineQueue(JsonObject obj) {
        LOGGER.info("[SpiderMinecraft] Received offline queue");
    }

    private void handleCompromised(JsonObject obj) {
        String uuid = obj.has("uuid") ? obj.get("uuid").getAsString() : "unknown";
        LOGGER.warn("[SpiderMinecraft] COMPROMISED signal from {}", uuid.substring(0, 8));
        // 通知所有在线玩家
        if (server != null) {
            SpiderNetwork.broadcast(new SpiderPacket(Protocol.COMPROMISED, JsonUtil.toJson(obj)));
        }
    }

    private void handleFileReceive(JsonObject obj) {
        LOGGER.info("[SpiderMinecraft] File received from {}",
                obj.has("from_uuid") ? obj.get("from_uuid").getAsString().substring(0, 8) : "unknown");
    }

    private void sendDeliveryReceipt(JsonObject originalMsg) {
        try {
            String fromUuid = originalMsg.get("from_uuid").getAsString();
            String msgId = originalMsg.get("msg_id").getAsString();
            JsonObject receipt = new JsonObject();
            receipt.addProperty("type", Protocol.DELIVERY_RECEIPT);
            receipt.addProperty("msg_id", msgId);
            receipt.addProperty("to_uuid", fromUuid);
            receipt.addProperty("timestamp", System.currentTimeMillis() / 1000);

            // 通过直连发送回执
            String connId = mod.getSessionManager() != null ? mod.getSessionManager().getCurrentConnectionId() : null;
            if (connId != null) {
                mod.getDirectConnector().sendMessage(connId, JsonUtil.toJson(receipt));
            }
        } catch (Exception ignored) {}
    }
}
