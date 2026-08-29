package com.spider.minecraft.network;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.crypto.TransportEncryptor;
import com.spider.minecraft.protocol.Protocol;
import com.google.gson.JsonObject;
import com.spider.minecraft.util.JsonUtil;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 直连连接器 — TCP 直连，使用 TransportEncryptor 全包加密 + 密钥轮换。
 *
 * <p>对齐 Spider 的 TCPClient/TCPServer：
 * <ul>
 *   <li>服务端模式：监听 TCP 端口，接受 Spider 客户端连接</li>
 *   <li>客户端模式：主动连接 Spider 服务端</li>
 *   <li>传输加密：握手后所有数据经 AES-256-GCM 全包加密，定期轮换密钥（PFS）</li>
 *   <li>协议：line-delimited JSON，完全兼容 Spider 标准信令</li>
 * </ul>
 */
public class DirectConnector {

    private final SpiderMinecraftMod mod;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private final AtomicBoolean accepting = new AtomicBoolean(false);
    private final ConcurrentHashMap<String, Connection> connections = new ConcurrentHashMap<>();
    private volatile java.util.function.BiConsumer<String, JsonObject> onMessageReceived;

    public DirectConnector(SpiderMinecraftMod mod) {
        this.mod = mod;
    }

    public void startServer() {
        if (accepting.get()) return;
        try {
            serverSocket = new ServerSocket(SpiderMinecraft.DIRECT_TCP_PORT);
            accepting.set(true);
            acceptThread = new Thread(this::acceptLoop, "SpiderMC-Direct-Accept");
            acceptThread.setDaemon(true);
            acceptThread.start();
            SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Direct TCP server on port {}", SpiderMinecraft.DIRECT_TCP_PORT);
        } catch (IOException e) {
            SpiderMinecraftMod.LOGGER.error("[SpiderMinecraft] Failed to start TCP server: {}", e.getMessage());
        }
    }

    public void stopServer() {
        accepting.set(false);
        connections.values().forEach(Connection::close);
        connections.clear();
        if (serverSocket != null) { try { serverSocket.close(); } catch (IOException ignored) {} }
        if (acceptThread != null) { acceptThread.interrupt(); acceptThread = null; }
    }

    private void acceptLoop() {
        while (accepting.get()) {
            try {
                Socket socket = serverSocket.accept();
                socket.setSoTimeout(SpiderMinecraft.DIRECT_READ_TIMEOUT_MS);
                String connId = com.spider.minecraft.util.NetUtil.generateShortId();
                Connection conn = new Connection(connId, socket, this, false);
                connections.put(connId, conn);
                conn.start();
            } catch (IOException e) {
                if (accepting.get()) SpiderMinecraftMod.LOGGER.debug("[SpiderMinecraft] Accept error: {}", e.getMessage());
            }
        }
    }

    public String connect(String host, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), SpiderMinecraft.DIRECT_CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(SpiderMinecraft.DIRECT_READ_TIMEOUT_MS);
            String connId = com.spider.minecraft.util.NetUtil.generateShortId();
            Connection conn = new Connection(connId, socket, this, true);
            connections.put(connId, conn);
            conn.start();
            return connId;
        } catch (IOException e) {
            SpiderMinecraftMod.LOGGER.error("[SpiderMinecraft] Connect failed: {}", e.getMessage());
            return null;
        }
    }

    public void disconnect(String connId) {
        Connection conn = connections.remove(connId);
        if (conn != null) conn.close();
    }

    public void sendMessage(String connId, String json) {
        Connection conn = connections.get(connId);
        if (conn != null) conn.sendMessage(json);
    }

    public void broadcast(String json) {
        connections.values().forEach(c -> c.sendMessage(json));
    }

    void onConnectionClosed(String connId) {
        connections.remove(connId);
    }

    void onMessage(String connId, String json) {
        try {
            JsonObject obj = JsonUtil.parse(json);
            if (onMessageReceived != null) onMessageReceived.accept(connId, obj);
        } catch (Exception e) {
            SpiderMinecraftMod.LOGGER.debug("[SpiderMinecraft] Parse error: {}", e.getMessage());
        }
    }

    public void setOnMessageReceived(java.util.function.BiConsumer<String, JsonObject> handler) {
        this.onMessageReceived = handler;
    }

    public ConcurrentHashMap<String, Connection> getConnections() { return connections; }
    public boolean isServerRunning() { return accepting.get(); }

    /**
     * TCP 连接封装 — 含 TransportEncryptor 全包加密。
     */
    public static class Connection {
        public final String id;
        private final Socket socket;
        private final DirectConnector connector;
        private final boolean isInitiator;
        private TransportEncryptor transport;
        private DataOutputStream rawOut;
        private DataInputStream rawIn;
        private Thread readThread;
        private final AtomicBoolean running = new AtomicBoolean(true);
        public volatile String peerUuid;
        private long lastKeyCheck = System.currentTimeMillis() / 1000;

        Connection(String id, Socket socket, DirectConnector connector, boolean isInitiator) {
            this.id = id;
            this.socket = socket;
            this.connector = connector;
            this.isInitiator = isInitiator;
        }

        void start() {
            try {
                rawOut = new DataOutputStream(socket.getOutputStream());
                rawIn = new DataInputStream(socket.getInputStream());

                // 传输加密握手
                transport = new TransportEncryptor(isInitiator);
                if (isInitiator) {
                    transport.handshakeInitiator(socket);
                } else {
                    transport.handshakeResponder(socket);
                }

                readThread = new Thread(this::readLoop, "SpiderMC-Conn-" + id);
                readThread.setDaemon(true);
                readThread.start();
                SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Connection {} established (encrypted)", id);
            } catch (IOException e) {
                SpiderMinecraftMod.LOGGER.error("[SpiderMinecraft] Connection {} init failed: {}", id, e.getMessage());
                close();
            }
        }

        private void readLoop() {
            while (running.get()) {
                try {
                    // 检查密钥轮换
                    long now = System.currentTimeMillis() / 1000;
                    if (transport != null && transport.isEstablished() &&
                            now - lastKeyCheck > 60 && transport.shouldRotate(SpiderMinecraft.TRANSPORT_KEY_ROTATION_SEC)) {
                        transport.rotateKey(rawOut, rawIn);
                        lastKeyCheck = now;
                    }

                    // 读取加密帧
                    byte[] plaintext = transport.recvEncrypted(rawIn);
                    String json = new String(plaintext, StandardCharsets.UTF_8);
                    if (!json.isEmpty()) connector.onMessage(id, json);
                } catch (IOException e) {
                    if (running.get()) SpiderMinecraftMod.LOGGER.debug("[SpiderMinecraft] Conn {} read error: {}", id, e.getMessage());
                    break;
                }
            }
            close();
        }

        public void sendMessage(String json) {
            if (transport != null && transport.isEstablished() && running.get()) {
                try {
                    transport.sendEncrypted(rawOut, json.getBytes(StandardCharsets.UTF_8));
                } catch (IOException e) {
                    SpiderMinecraftMod.LOGGER.debug("[SpiderMinecraft] Conn {} send error: {}", id, e.getMessage());
                }
            }
        }

        public void close() {
            running.set(false);
            if (transport != null) transport.close();
            try { socket.close(); } catch (IOException ignored) {}
            connector.onConnectionClosed(id);
        }

        public String getRemoteAddress() {
            return socket.getInetAddress().getHostAddress();
        }
    }
}
