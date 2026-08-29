package com.spider.minecraft;

import com.spider.minecraft.command.SpiderCommand;
import com.spider.minecraft.config.SpiderConfig;
import com.spider.minecraft.crypto.CryptoManager;
import com.spider.minecraft.crypto.KeyManager;
import com.spider.minecraft.crypto.TransportEncryptor;
import com.spider.minecraft.event.ClientEventHandler;
import com.spider.minecraft.event.ServerEventHandler;
import com.spider.minecraft.file.FileTransfer;
import com.spider.minecraft.group.GroupManager;
import com.spider.minecraft.network.DirectConnector;
import com.spider.minecraft.network.DiscoveryService;
import com.spider.minecraft.network.SessionManager;
import com.spider.minecraft.network.SpiderNetwork;
import com.spider.minecraft.security.DuressManager;
import com.spider.minecraft.security.EphemeralEngine;
import com.spider.minecraft.server.SpiderServerCore;
import com.spider.minecraft.storage.DatabaseManager;
import com.spider.minecraft.storage.MessageStore;
import com.spider.minecraft.storage.OfflineStore;
import net.neoforged.bus.api.IEventBus;
import net.neoforged.fml.ModContainer;
import net.neoforged.fml.common.Mod;
import net.neoforged.fml.config.ModConfig;
import net.neoforged.fml.event.lifecycle.FMLClientSetupEvent;
import net.neoforged.fml.event.lifecycle.FMLCommonSetupEvent;
import net.neoforged.fml.event.lifecycle.FMLDedicatedServerSetupEvent;
import net.neoforged.neoforge.common.NeoForge;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * SpiderMinecraft 模组主入口。
 *
 * <p>Spider 官方通信网络在 Minecraft 世界中的投射。
 * 纯新增模组，不修改任何 Minecraft 已有代码。所有交互通过聊天框命令。
 *
 * <p>核心子系统：
 * <ul>
 *   <li>{@link KeyManager} — UUIDv1+MAC 身份、密钥对、胁迫 PIN、wipe_all_data</li>
 *   <li>{@link CryptoManager} — 消息 E2EE（X25519+AES-256-GCM+Ed25519）</li>
 *   <li>{@link TransportEncryptor} — TCP 全包加密 + 密钥轮换（PFS）</li>
 *   <li>{@link DatabaseManager} — SQLite 持久化（消息/用户/离线队列/群组）</li>
 *   <li>{@link SessionManager} — REGISTER/LOGIN 认证流程</li>
 *   <li>{@link DirectConnector} — TCP 直连（含传输加密）</li>
 *   <li>{@link DiscoveryService} — UDP 多播服务发现（LAN + MC 服务器）</li>
 *   <li>{@link GroupManager} — 群组（替代房间，持久化）</li>
 *   <li>{@link DuressManager} — 胁迫 PIN 触发擦除</li>
 *   <li>{@link EphemeralEngine} — 阅后即焚（每人开关）</li>
 *   <li>{@link FileTransfer} — 加密文件传输（saves/SpiderFiles/）</li>
 * </ul>
 */
@Mod(SpiderMinecraft.MOD_ID)
public class SpiderMinecraftMod {

    public static final Logger LOGGER = LogManager.getLogger(SpiderMinecraft.MOD_NAME);
    private static SpiderMinecraftMod instance;

    private final IEventBus modEventBus;
    private final ModContainer modContainer;

    // 子系统
    private SpiderNetwork network;
    private KeyManager keyManager;
    private CryptoManager cryptoManager;
    private DatabaseManager databaseManager;
    private MessageStore messageStore;
    private OfflineStore offlineStore;
    private DiscoveryService discovery;
    private DirectConnector directConnector;
    private SessionManager sessionManager;
    private GroupManager groupManager;
    private DuressManager duressManager;
    private EphemeralEngine ephemeralEngine;
    private FileTransfer fileTransfer;
    private SpiderServerCore serverCore;
    private ClientEventHandler clientHandler;
    private ServerEventHandler serverHandler;

    public SpiderMinecraftMod(IEventBus modEventBus, ModContainer modContainer) {
        instance = this;
        this.modEventBus = modEventBus;
        this.modContainer = modContainer;

        LOGGER.info("[SpiderMinecraft] Initializing {} v{} for MC 26.2 + NeoForge",
                SpiderMinecraft.MOD_NAME, SpiderMinecraft.MOD_VERSION);

        modContainer.registerConfig(ModConfig.Type.COMMON, SpiderConfig.COMMON_SPEC);
        modContainer.registerConfig(ModConfig.Type.CLIENT, SpiderConfig.CLIENT_SPEC);

        // 网络通道必须在构造函数中注册（RegisterPayloadHandlersEvent 时序）
        network = new SpiderNetwork();
        network.register();

        modEventBus.addListener(this::onCommonSetup);
        modEventBus.addListener(this::onClientSetup);
        modEventBus.addListener(this::onDedicatedServerSetup);

        LOGGER.info("[SpiderMinecraft] Mod construction complete.");
    }

    private void onCommonSetup(final FMLCommonSetupEvent event) {
        event.enqueueWork(() -> {
            LOGGER.info("[SpiderMinecraft] Common setup...");

            // 身份密钥
            keyManager = new KeyManager();
            keyManager.initialize();

            // 加密
            cryptoManager = new CryptoManager(keyManager);

            // 数据库（持久化）
            String configDir = System.getProperty("neoforge.configDir", "config");
            Path dataDir = Paths.get(configDir, SpiderMinecraft.IDENTITY_DIR, SpiderMinecraft.DATA_DIR);
            try { java.nio.file.Files.createDirectories(dataDir); } catch (Exception ignored) {}
            databaseManager = new DatabaseManager(dataDir);
            databaseManager.initialize();
            messageStore = new MessageStore(databaseManager);
            offlineStore = new OfflineStore(databaseManager);

            // 群组
            groupManager = new GroupManager(databaseManager);

            // 网络
            discovery = new DiscoveryService(this);
            directConnector = new DirectConnector(this);

            // 会话
            sessionManager = new SessionManager(this, keyManager);

            // 安全
            duressManager = new DuressManager(keyManager, sessionManager);
            ephemeralEngine = new EphemeralEngine(messageStore);

            // 文件传输
            fileTransfer = new FileTransfer(this, cryptoManager, keyManager);

            // 服务端事件处理器（客户端也注册，用于内置服务端）
            serverHandler = new ServerEventHandler(this);
            NeoForge.EVENT_BUS.register(serverHandler);

            LOGGER.info("[SpiderMinecraft] Common setup complete.");
        });
    }

    private void onClientSetup(final FMLClientSetupEvent event) {
        event.enqueueWork(() -> {
            LOGGER.info("[SpiderMinecraft] Client setup...");
            clientHandler = new ClientEventHandler(this);
            NeoForge.EVENT_BUS.register(clientHandler);

            if (SpiderConfig.CLIENT.autoDiscovery.get()) {
                getDiscovery().startClient();
            }
            LOGGER.info("[SpiderMinecraft] Client setup complete.");
        });
    }

    private void onDedicatedServerSetup(final FMLDedicatedServerSetupEvent event) {
        event.enqueueWork(() -> {
            LOGGER.info("[SpiderMinecraft] Dedicated server setup...");
            // 初始化服务端核心（用户管理、限速、管理员控制台、联邦等）
            serverCore = new SpiderServerCore(this);
            serverCore.setServerName(SpiderConfig.COMMON.nodeLabel.get().isEmpty() ?
                    "Spider-MC-Server" : SpiderConfig.COMMON.nodeLabel.get());
            serverCore.setSpiderTcpPort(SpiderConfig.COMMON.directTcpPort.get());
            serverCore.start();
            if (SpiderConfig.COMMON.announceServer.get()) {
                getDiscovery().startServer();
            }
            if (directConnector != null) {
                directConnector.startServer();
            }
            LOGGER.info("[SpiderMinecraft] Dedicated server setup complete.");
        });
    }

    // ===== 访问器 =====
    public IEventBus getModEventBus() { return modEventBus; }
    public SpiderNetwork getNetwork() { return network; }
    public KeyManager getKeyManager() { return keyManager; }
    public CryptoManager getCryptoManager() { return cryptoManager; }
    public DatabaseManager getDatabaseManager() { return databaseManager; }
    public MessageStore getMessageStore() { return messageStore; }
    public OfflineStore getOfflineStore() { return offlineStore; }
    public DiscoveryService getDiscovery() { return discovery; }
    public DirectConnector getDirectConnector() { return directConnector; }
    public SessionManager getSessionManager() { return sessionManager; }
    public GroupManager getGroupManager() { return groupManager; }
    public DuressManager getDuressManager() { return duressManager; }
    public EphemeralEngine getEphemeralEngine() { return ephemeralEngine; }
    public FileTransfer getFileTransfer() { return fileTransfer; }
    public SpiderServerCore getServerCore() { return serverCore; }

    public static SpiderMinecraftMod get() { return instance; }
    public static Logger logger() { return LOGGER; }
}
