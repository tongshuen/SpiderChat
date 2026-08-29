package com.spider.minecraft.network;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.util.NetUtil;
import com.google.gson.JsonObject;
import com.spider.minecraft.util.JsonUtil;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 服务发现服务 — UDP 多播，同时检测局域网 Spider 服务端和 Minecraft 服务端。
 *
 * <p>对齐 Spider 的 UDPDiscovery，并扩展：除了检测 Spider 服务端外，
 * 还检测局域网内的 Minecraft 服务端（通过 SpiderMinecraft 模组的广播）。
 *
 * <p>首次登录时，用户可从检测到的服务端列表中选择，也可手动输入地址。
 */
public class DiscoveryService {

    private final SpiderMinecraftMod mod;
    private Thread broadcastThread;
    private Thread listenerThread;
    private final AtomicBoolean broadcasting = new AtomicBoolean(false);
    private final AtomicBoolean listening = new AtomicBoolean(false);
    private MulticastSocket multicastSocket;

    private final ConcurrentHashMap<String, DiscoveredServer> discoveredServers = new ConcurrentHashMap<>();

    public DiscoveryService(SpiderMinecraftMod mod) {
        this.mod = mod;
    }

    public void startServer() {
        if (broadcasting.get()) return;
        broadcasting.set(true);
        broadcastThread = new Thread(this::broadcastLoop, "SpiderMC-Discovery-Broadcast");
        broadcastThread.setDaemon(true);
        broadcastThread.start();
    }

    public void stopServer() {
        broadcasting.set(false);
        if (broadcastThread != null) { broadcastThread.interrupt(); broadcastThread = null; }
    }

    public void startClient() {
        if (listening.get()) return;
        listening.set(true);
        listenerThread = new Thread(this::listenLoop, "SpiderMC-Discovery-Listener");
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    public void stopClient() {
        listening.set(false);
        if (multicastSocket != null) { multicastSocket.close(); multicastSocket = null; }
        if (listenerThread != null) { listenerThread.interrupt(); listenerThread = null; }
    }

    private void broadcastLoop() {
        try (MulticastSocket socket = new MulticastSocket()) {
            socket.setTimeToLive(32);
            InetAddress group = InetAddress.getByName(SpiderMinecraft.DISCOVERY_MULTICAST_ADDR);
            while (broadcasting.get()) {
                try {
                    JsonObject obj = new JsonObject();
                    obj.addProperty("type", "DISCOVERY");
                    obj.addProperty("server_uuid", mod.getKeyManager().getIdentityUuid());
                    obj.addProperty("server_name", "SpiderMinecraft Server");
                    obj.addProperty("address", NetUtil.getPrimaryLocalIPv4());
                    obj.addProperty("minecraft_port", 25565);
                    obj.addProperty("spider_tcp_port", SpiderMinecraft.DIRECT_TCP_PORT);
                    obj.addProperty("node_type", SpiderMinecraft.NODE_MC_SERVER);
                    obj.addProperty("protocol", SpiderMinecraft.PROTOCOL_VERSION);
                    obj.addProperty("x25519_pub", mod.getKeyManager().getX25519PublicB64());
                    obj.addProperty("ed25519_pub", mod.getKeyManager().getEd25519PublicB64());
                    obj.addProperty("timestamp", System.currentTimeMillis() / 1000);

                    byte[] data = JsonUtil.toJson(obj).getBytes("UTF-8");
                    socket.send(new DatagramPacket(data, data.length, group, SpiderMinecraft.DISCOVERY_PORT));
                } catch (IOException ignored) {}
                try { Thread.sleep(SpiderMinecraft.DISCOVERY_BROADCAST_INTERVAL_MS); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); break; }
            }
        } catch (IOException e) {
            SpiderMinecraftMod.LOGGER.error("[SpiderMinecraft] Broadcast error: {}", e.getMessage());
        }
    }

    private void listenLoop() {
        try {
            multicastSocket = new MulticastSocket(SpiderMinecraft.DISCOVERY_PORT);
            InetAddress group = InetAddress.getByName(SpiderMinecraft.DISCOVERY_MULTICAST_ADDR);
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface iface = ifaces.nextElement();
                if (iface.isUp() && !iface.isLoopback()) {
                    try { multicastSocket.joinGroup(new java.net.InetSocketAddress(group, 0), iface); }
                    catch (IOException ignored) {}
                }
            }
            byte[] buf = new byte[65536];
            while (listening.get()) {
                DatagramPacket dg = new DatagramPacket(buf, buf.length);
                try {
                    multicastSocket.receive(dg);
                    String json = new String(dg.getData(), dg.getOffset(), dg.getLength(), "UTF-8");
                    JsonObject obj = JsonUtil.parse(json);
                    String uuid = obj.get("server_uuid").getAsString();
                    discoveredServers.put(uuid, new DiscoveredServer(obj, dg.getAddress().getHostAddress(),
                            System.currentTimeMillis()));
                } catch (IOException e) {
                    if (!listening.get()) break;
                }
            }
        } catch (IOException e) {
            SpiderMinecraftMod.LOGGER.error("[SpiderMinecraft] Listener error: {}", e.getMessage());
        }
    }

    public void cleanupExpired() {
        long now = System.currentTimeMillis();
        discoveredServers.entrySet().removeIf(e ->
                now - e.getValue().lastSeen > SpiderMinecraft.DISCOVERY_ENTRY_TTL_MS);
    }

    public ConcurrentHashMap<String, DiscoveredServer> getDiscoveredServers() {
        return discoveredServers;
    }

    public boolean isBroadcasting() { return broadcasting.get(); }
    public boolean isListening() { return listening.get(); }

    public static class DiscoveredServer {
        public final JsonObject info;
        public final String sourceAddress;
        public volatile long lastSeen;

        public DiscoveredServer(JsonObject info, String sourceAddress, long lastSeen) {
            this.info = info;
            this.sourceAddress = sourceAddress;
            this.lastSeen = lastSeen;
        }
    }
}
