package com.spider.minecraft.network;

import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.crypto.KeyManager;
import com.spider.minecraft.protocol.Protocol;
import com.google.gson.JsonObject;
import com.spider.minecraft.util.JsonUtil;

/**
 * 会话管理器 — 处理 REGISTER/LOGIN 流程，对齐 Spider 的认证流程。
 *
 * <p>首次登录流程：
 * <ol>
 *   <li>检测局域网 Spider 服务端和 Minecraft 服务端（UDP 发现）</li>
 *   <li>用户从列表选择或手动输入服务器地址</li>
 *   <li>用户在聊天框输入密码和胁迫密码</li>
 *   <li>如果 identity.json 不存在 → REGISTER（生成 UUIDv1+MAC、密钥对，用密码加密存储）</li>
 *   <li>如果 identity.json 存在 → LOGIN（用密码解密私钥，发送登录信令）</li>
 * </ol>
 *
 * <p>认证信令格式（Spider 标准）：
 * <pre>
 * REGISTER: { "type":"REGISTER", "uuid":"...", "x25519_pub":"...", "ed25519_pub":"...", "signature":"..." }
 * LOGIN:    { "type":"LOGIN", "uuid":"...", "timestamp":..., "signature":"..." }
 * AUTH_OK:  { "type":"AUTH_OK", "session_id":"..." }
 * AUTH_FAIL:{ "type":"AUTH_FAIL", "reason":"..." }
 * </pre>
 */
public class SessionManager {

    private final SpiderMinecraftMod mod;
    private final KeyManager keyManager;
    private volatile boolean authenticated = false;
    private volatile String sessionId;
    private volatile String currentServerHost;
    private volatile int currentServerPort;
    private volatile String currentConnectionId;

    // 登录流程状态
    private volatile LoginState loginState = LoginState.IDLE;
    private volatile String pendingServerHost;
    private volatile int pendingServerPort;

    public enum LoginState {
        IDLE, SELECTING_SERVER, ENTERING_PASSWORD, ENTERING_DURESS_PIN, REGISTERING, LOGGING_IN, AUTHENTICATED
    }

    public SessionManager(SpiderMinecraftMod mod, KeyManager keyManager) {
        this.mod = mod;
        this.keyManager = keyManager;
    }

    /**
     * 开始登录流程 — 检测服务器。
     */
    public void beginLogin() {
        loginState = LoginState.SELECTING_SERVER;
        // 启动发现监听
        if (!mod.getDiscovery().isListening()) {
            mod.getDiscovery().startClient();
        }
        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Login flow started — discovering servers");
    }

    /**
     * 用户选择服务器。
     */
    public void selectServer(String host, int port) {
        this.pendingServerHost = host;
        this.pendingServerPort = port;
        this.loginState = LoginState.ENTERING_PASSWORD;
        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Server selected: {}:{}", host, port);
    }

    /**
     * 用户输入密码 — 执行 REGISTER 或 LOGIN。
     */
    public boolean submitPassword(String password) {
        if (loginState != LoginState.ENTERING_PASSWORD) return false;

        currentServerHost = pendingServerHost;
        currentServerPort = pendingServerPort;

        if (!keyManager.identityExists()) {
            // 首次注册
            loginState = LoginState.ENTERING_DURESS_PIN;
            SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] New identity — need duress PIN");
            return true; // 需要继续输入胁迫 PIN
        } else {
            // 已有身份 — 登录
            loginState = LoginState.LOGGING_IN;
            boolean ok = keyManager.login(password);
            if (ok) {
                performLogin();
            } else {
                // 登录失败 — 检查是否为胁迫触发（胁迫 PIN 或解锁 PIN 的倒序）
                if (KeyManager.isValidPinFormat(password) && keyManager.isDuressTrigger(password)) {
                    SpiderMinecraftMod.LOGGER.warn("[SpiderMinecraft] Duress trigger detected at login — initiating wipe");
                    if (isAuthenticated()) {
                        sendCompromised();
                        try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                    }
                    keyManager.wipeAllData();
                    logout();
                    return false;
                }
                loginState = LoginState.ENTERING_PASSWORD;
                SpiderMinecraftMod.LOGGER.warn("[SpiderMinecraft] Login failed — wrong password");
            }
            return ok;
        }
    }

    /**
     * 用户输入胁迫 PIN（仅首次注册时）。
     */
    public boolean submitDuressPin(String duressPin, String password) {
        if (loginState != LoginState.ENTERING_DURESS_PIN) return false;

        loginState = LoginState.REGISTERING;
        keyManager.register(password, duressPin);
        performRegister();
        return true;
    }

    /**
     * 执行 REGISTER 信令。
     */
    private void performRegister() {
        currentConnectionId = mod.getDirectConnector().connect(currentServerHost, currentServerPort);
        if (currentConnectionId == null) {
            loginState = LoginState.SELECTING_SERVER;
            return;
        }

        // 构建 REGISTER 信令
        JsonObject msg = new JsonObject();
        msg.addProperty("type", Protocol.REGISTER);
        msg.addProperty("uuid", keyManager.getIdentityUuid());
        msg.addProperty("x25519_pub", keyManager.getX25519PublicB64());
        msg.addProperty("ed25519_pub", keyManager.getEd25519PublicB64());
        msg.addProperty("node_type", SpiderMinecraft.NODE_MC_CLIENT);
        msg.addProperty("protocol", SpiderMinecraft.PROTOCOL_VERSION);

        // 签名
        byte[] toSign = (keyManager.getIdentityUuid() + keyManager.getX25519PublicB64() +
                keyManager.getEd25519PublicB64()).getBytes();
        msg.addProperty("signature", JsonUtil.b64Encode(KeyManager.ed25519Sign(keyManager.getEd25519Private(), toSign)));

        mod.getDirectConnector().sendMessage(currentConnectionId, JsonUtil.toJson(msg));
        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] REGISTER sent to {}:{}", currentServerHost, currentServerPort);
    }

    /**
     * 执行 LOGIN 信令。
     */
    private void performLogin() {
        currentConnectionId = mod.getDirectConnector().connect(currentServerHost, currentServerPort);
        if (currentConnectionId == null) {
            loginState = LoginState.SELECTING_SERVER;
            return;
        }

        long timestamp = System.currentTimeMillis() / 1000;
        JsonObject msg = new JsonObject();
        msg.addProperty("type", Protocol.LOGIN);
        msg.addProperty("uuid", keyManager.getIdentityUuid());
        msg.addProperty("timestamp", timestamp);
        msg.addProperty("node_type", SpiderMinecraft.NODE_MC_CLIENT);

        byte[] toSign = (keyManager.getIdentityUuid() + timestamp).getBytes();
        msg.addProperty("signature", JsonUtil.b64Encode(KeyManager.ed25519Sign(keyManager.getEd25519Private(), toSign)));

        mod.getDirectConnector().sendMessage(currentConnectionId, JsonUtil.toJson(msg));
        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] LOGIN sent to {}:{}", currentServerHost, currentServerPort);
    }

    /**
     * 处理 AUTH_OK 响应。
     */
    public void onAuthOk(JsonObject response) {
        sessionId = response.has("session_id") ? response.get("session_id").getAsString() : "";
        authenticated = true;
        loginState = LoginState.AUTHENTICATED;
        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Authenticated! session_id={}", sessionId);

        // 请求离线消息
        JsonObject req = new JsonObject();
        req.addProperty("type", Protocol.REQUEST_OFFLINE);
        req.addProperty("uuid", keyManager.getIdentityUuid());
        mod.getDirectConnector().sendMessage(currentConnectionId, JsonUtil.toJson(req));
    }

    /**
     * 处理 AUTH_FAIL 响应。
     */
    public void onAuthFail(JsonObject response) {
        authenticated = false;
        loginState = LoginState.ENTERING_PASSWORD;
        String reason = response.has("reason") ? response.get("reason").getAsString() : "unknown";
        SpiderMinecraftMod.LOGGER.warn("[SpiderMinecraft] Auth failed: {}", reason);
    }

    /**
     * 发送 COMPROMISED 信令（胁迫 PIN 触发）。
     */
    public void sendCompromised() {
        if (currentConnectionId != null && authenticated) {
            JsonObject msg = new JsonObject();
            msg.addProperty("type", Protocol.COMPROMISED);
            msg.addProperty("uuid", keyManager.getIdentityUuid());
            msg.addProperty("timestamp", System.currentTimeMillis() / 1000);

            byte[] toSign = (keyManager.getIdentityUuid() + "COMPROMISED").getBytes();
            msg.addProperty("signature", JsonUtil.b64Encode(KeyManager.ed25519Sign(keyManager.getEd25519Private(), toSign)));

            mod.getDirectConnector().sendMessage(currentConnectionId, JsonUtil.toJson(msg));
            SpiderMinecraftMod.LOGGER.warn("[SpiderMinecraft] COMPROMISED signal sent");
        }
    }

    public void logout() {
        if (currentConnectionId != null) {
            JsonObject msg = new JsonObject();
            msg.addProperty("type", Protocol.BYE);
            msg.addProperty("uuid", keyManager.getIdentityUuid());
            mod.getDirectConnector().sendMessage(currentConnectionId, JsonUtil.toJson(msg));
            mod.getDirectConnector().disconnect(currentConnectionId);
        }
        authenticated = false;
        sessionId = null;
        currentConnectionId = null;
        loginState = LoginState.IDLE;
    }

    public boolean isAuthenticated() { return authenticated; }
    public LoginState getLoginState() { return loginState; }
    public String getSessionId() { return sessionId; }
    public String getCurrentServerHost() { return currentServerHost; }
    public int getCurrentServerPort() { return currentServerPort; }
    public String getCurrentConnectionId() { return currentConnectionId; }
}
