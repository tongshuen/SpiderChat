package com.spider.minecraft.config;

import net.neoforged.neoforge.common.ModConfigSpec;

/**
 * SpiderMinecraft 配置。
 */
public final class SpiderConfig {

    private SpiderConfig() {}

    public static final Common COMMON;
    public static final ModConfigSpec COMMON_SPEC;

    static {
        ModConfigSpec.Builder builder = new ModConfigSpec.Builder();
        COMMON = new Common(builder);
        COMMON_SPEC = builder.build();
    }

    public static class Common {
        public final ModConfigSpec.BooleanValue announceServer;
        public final ModConfigSpec.BooleanValue enableCrypto;
        public final ModConfigSpec.BooleanValue enableTransportEncryption;
        public final ModConfigSpec.IntValue discoveryPort;
        public final ModConfigSpec.IntValue directTcpPort;
        public final ModConfigSpec.IntValue transportKeyRotationSec;
        public final ModConfigSpec.StringValue defaultGroupName;
        public final ModConfigSpec.BooleanValue allowVanillaConnections;
        public final ModConfigSpec.StringValue nodeLabel;

        Common(ModConfigSpec.Builder builder) {
            builder.push("network");
            announceServer = builder.comment("是否向局域网广播本服务端存在").define("announceServer", true);
            enableCrypto = builder.comment("是否启用端到端加密").define("enableCrypto", true);
            enableTransportEncryption = builder.comment("是否启用 TCP 传输全包加密（PFS）").define("enableTransportEncryption", true);
            discoveryPort = builder.comment("UDP 服务发现端口").defineInRange("discoveryPort", 42999, 1, 65535);
            directTcpPort = builder.comment("Spider TCP 直连端口").defineInRange("directTcpPort", 42998, 1, 65535);
            transportKeyRotationSec = builder.comment("传输密钥轮换间隔（秒）").defineInRange("transportKeyRotationSec", 3600, 60, 86400);
            builder.pop();

            builder.push("group");
            defaultGroupName = builder.comment("默认群组名称").define("defaultGroupName", "SpiderMinecraft");
            builder.pop();

            builder.push("interop");
            allowVanillaConnections = builder.comment("是否允许原版客户端连接").define("allowVanillaConnections", true);
            nodeLabel = builder.comment("本节点显示名称").define("nodeLabel", "");
            builder.pop();
        }
    }

    public static final Client CLIENT;
    public static final ModConfigSpec CLIENT_SPEC;

    static {
        ModConfigSpec.Builder builder = new ModConfigSpec.Builder();
        CLIENT = new Client(builder);
        CLIENT_SPEC = builder.build();
    }

    public static class Client {
        public final ModConfigSpec.BooleanValue autoDiscovery;
        public final ModConfigSpec.BooleanValue showDiscoveryNotifications;
        public final ModConfigSpec.BooleanValue readReceiptsEnabled;
        public final ModConfigSpec.BooleanValue readReceipts;
        public final ModConfigSpec.BooleanValue autoDownload;
        public final ModConfigSpec.BooleanValue showHudButton;
        public final ModConfigSpec.IntValue discoveryTimeoutSec;

        Client(ModConfigSpec.Builder builder) {
            builder.push("discovery");
            autoDiscovery = builder.comment("启动时自动开始服务发现").define("autoDiscovery", true);
            showDiscoveryNotifications = builder.comment("发现新服务端时在聊天框提示").define("showDiscoveryNotifications", true);
            discoveryTimeoutSec = builder.comment("服务发现超时（秒）").defineInRange("discoveryTimeoutSec", 5, 1, 60);
            builder.pop();

            builder.push("privacy");
            readReceiptsEnabled = builder.comment("是否发送已读回执").define("readReceiptsEnabled", true);
            readReceipts = builder.comment("已读回执（GUI设置用）").define("readReceipts", true);
            builder.pop();
            builder.push("gui");
            autoDownload = builder.comment("是否自动下载接收到的文件").define("autoDownload", true);
            showHudButton = builder.comment("是否在游戏界面显示Spider按钮").define("showHudButton", true);
            builder.pop();
        }
    }
}
