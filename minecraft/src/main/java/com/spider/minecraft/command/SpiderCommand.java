package com.spider.minecraft.command;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.spider.minecraft.SpiderMinecraft;
import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.config.SpiderConfig;
import com.spider.minecraft.crypto.CryptoManager;
import com.spider.minecraft.crypto.KeyManager;
import com.spider.minecraft.network.DiscoveryService;
import com.spider.minecraft.network.SessionManager;
import com.spider.minecraft.protocol.Protocol;
import com.google.gson.JsonObject;
import com.spider.minecraft.util.JsonUtil;
import net.minecraft.ChatFormatting;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * SpiderMinecraft 聊天命令注册器 — 所有交互通过聊天框，无 GUI。
 *
 * <p>命令列表：
 * <ul>
 *   <li>/spiderminecraft help — 帮助</li>
 *   <li>/spiderminecraft status — 状态</li>
 *   <li>/spiderminecraft login begin — 开始登录（检测服务器）</li>
 *   <li>/spiderminecraft login list — 列出检测到的服务器</li>
 *   <li>/spiderminecraft login select <index|host:port> — 选择服务器</li>
 *   <li>/spiderminecraft login password <password> — 输入密码</li>
 *   <li>/spiderminecraft login duress <pin> — 首次注册时输入胁迫 PIN</li>
 *   <li>/spiderminecraft logout — 登出</li>
 *   <li>/spiderminecraft duress <pin> — 胁迫 PIN（触发擦除！）</li>
 *   <li>/spiderminecraft msg <uuid> <text> — 发送加密消息</li>
 *   <li>/spiderminecraft file send <path> <uuid> — 发送加密文件</li>
 *   <li>/spiderminecraft group create <name> — 创建群组</li>
 *   <li>/spiderminecraft group join <groupId> — 加入群组</li>
 *   <li>/spiderminecraft group list — 列出群组</li>
 *   <li>/spiderminecraft burn <uuid> <on|off> — 设置某人阅后即焚</li>
 *   <li>/spiderminecraft key — 显示本机密钥信息</li>
 *   <li>/spiderminecraft discovery — 切换发现监听</li>
 * </ul>
 */
public class SpiderCommand {

    public static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        var root = Commands.literal(SpiderMinecraft.CMD_ROOT)
                .requires(src -> src.hasPermission(0))
                .executes(SpiderCommand::showStatus);

        root.then(Commands.literal("help").executes(SpiderCommand::showHelp));
        root.then(Commands.literal("status").executes(SpiderCommand::showStatus));
        root.then(Commands.literal("key").executes(SpiderCommand::showKey));
        root.then(Commands.literal("discovery").executes(SpiderCommand::toggleDiscovery));
        root.then(Commands.literal("logout").executes(SpiderCommand::logout));

        // duress — 胁迫 PIN（危险命令！）
        root.then(Commands.literal("duress")
                .then(Commands.argument("pin", StringArgumentType.word())
                        .executes(SpiderCommand::triggerDuress)));

        // login 子命令
        var login = Commands.literal("login");
        login.then(Commands.literal("begin").executes(SpiderCommand::loginBegin));
        login.then(Commands.literal("list").executes(SpiderCommand::loginList));
        login.then(Commands.literal("select")
                .then(Commands.argument("target", StringArgumentType.word())
                        .executes(SpiderCommand::loginSelect)));
        login.then(Commands.literal("password")
                .then(Commands.argument("password", StringArgumentType.word())
                        .executes(SpiderCommand::loginPassword)));
        login.then(Commands.literal("duress")
                .then(Commands.argument("pin", StringArgumentType.word())
                        .executes(SpiderCommand::loginDuressPin)));
        root.then(login);

        // msg — 发送加密消息
        root.then(Commands.literal("msg")
                .then(Commands.argument("uuid", StringArgumentType.word())
                        .then(Commands.argument("text", StringArgumentType.greedyString())
                                .executes(SpiderCommand::sendMessage))));

        // file — 文件传输
        var file = Commands.literal("file");
        file.then(Commands.literal("send")
                .then(Commands.argument("path", StringArgumentType.word())
                        .then(Commands.argument("uuid", StringArgumentType.word())
                                .executes(SpiderCommand::sendFile))));
        file.then(Commands.literal("dir").executes(SpiderCommand::showFileDir));
        root.then(file);

        // group — 群组
        var group = Commands.literal("group");
        group.then(Commands.literal("create")
                .then(Commands.argument("name", StringArgumentType.word())
                        .executes(SpiderCommand::createGroup)));
        group.then(Commands.literal("join")
                .then(Commands.argument("groupId", StringArgumentType.word())
                        .executes(SpiderCommand::joinGroup)));
        group.then(Commands.literal("list").executes(SpiderCommand::listGroups));
        root.then(group);

        // burn — 阅后即焚（每人开关）
        root.then(Commands.literal("burn")
                .then(Commands.argument("uuid", StringArgumentType.word())
                        .then(Commands.argument("state", StringArgumentType.word())
                                .executes(SpiderCommand::setBurn))));

        dispatcher.register(root);
        SpiderMinecraftMod.LOGGER.info("[SpiderMinecraft] Commands registered: /{}", SpiderMinecraft.CMD_ROOT);
    }

    // ===== 命令实现 =====

    private static int showHelp(CommandContext<CommandSourceStack> ctx) {
        send(ctx, Component.literal("=== SpiderMinecraft 命令帮助 ===").withStyle(ChatFormatting.GOLD));
        String[][] cmds = {
                {"help", "显示帮助"},
                {"status", "显示状态"},
                {"login begin", "开始登录（检测服务器）"},
                {"login list", "列出检测到的服务器"},
                {"login select <index|host:port>", "选择服务器"},
                {"login password <password>", "输入密码（登录/注册）"},
                {"login duress <pin>", "首次注册时设置胁迫 PIN"},
                {"logout", "登出"},
                {"duress <pin>", "胁迫 PIN（触发数据擦除！）"},
                {"msg <uuid> <text>", "发送加密消息"},
                {"file send <path> <uuid>", "发送加密文件"},
                {"group create <name>", "创建群组"},
                {"group join <id>", "加入群组"},
                {"group list", "列出群组"},
                {"burn <uuid> <on|off>", "设置某人阅后即焚"},
                {"key", "显示本机密钥"},
                {"discovery", "切换服务发现"},
        };
        for (String[] c : cmds) {
            MutableComponent line = Component.literal("/spiderminecraft " + c[0]).withStyle(ChatFormatting.AQUA);
            line.append(Component.literal(" — " + c[1]).withStyle(ChatFormatting.GRAY));
            send(ctx, line);
        }
        return 1;
    }

    private static int showStatus(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) { sendErr(ctx, "未初始化"); return 0; }

        send(ctx, Component.literal("=== SpiderMinecraft 状态 ===").withStyle(ChatFormatting.GOLD));
        KeyManager km = mod.getKeyManager();
        if (km != null && km.isUnlocked()) {
            send(ctx, Component.literal("身份: " + km.getIdentityUuid()).withStyle(ChatFormatting.AQUA));
            send(ctx, Component.literal("胁迫 PIN: " + (km.hasDuressPin() ? "已设置" : "未设置")).withStyle(ChatFormatting.GRAY));
        } else {
            send(ctx, Component.literal("身份: 未登录 — 使用 /spiderminecraft login begin").withStyle(ChatFormatting.YELLOW));
        }

        SessionManager sm = mod.getSessionManager();
        if (sm != null) {
            send(ctx, Component.literal("登录状态: " + sm.getLoginState() +
                    (sm.isAuthenticated() ? " (已认证, " + sm.getCurrentServerHost() + ")" : "")).withStyle(ChatFormatting.GRAY));
        }

        DiscoveryService disc = mod.getDiscovery();
        if (disc != null) {
            send(ctx, Component.literal(String.format("发现: 监听=%s 广播=%s 已发现=%d",
                    disc.isListening() ? "开" : "关", disc.isBroadcasting() ? "开" : "关",
                    disc.getDiscoveredServers().size())).withStyle(ChatFormatting.GRAY));
        }
        return 1;
    }

    private static int showKey(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getKeyManager() == null || !mod.getKeyManager().isUnlocked()) {
            sendErr(ctx, "请先登录"); return 0;
        }
        KeyManager km = mod.getKeyManager();
        send(ctx, Component.literal("=== 本机身份 ===").withStyle(ChatFormatting.GOLD));
        send(ctx, Component.literal("UUID (UUIDv1+MAC): " + km.getIdentityUuid()).withStyle(ChatFormatting.AQUA));
        String xp = km.getX25519PublicB64();
        String ep = km.getEd25519PublicB64();
        send(ctx, Component.literal("X25519: " + xp.substring(0, 24) + "...").withStyle(ChatFormatting.GRAY));
        send(ctx, Component.literal("Ed25519: " + ep.substring(0, 24) + "...").withStyle(ChatFormatting.GRAY));
        send(ctx, Component.literal("胁迫 PIN: " + (km.hasDuressPin() ? "已设置" : "未设置")).withStyle(ChatFormatting.GRAY));
        return 1;
    }

    // ===== 登录流程 =====

    private static int loginBegin(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        mod.getSessionManager().beginLogin();
        send(ctx, Component.literal("正在检测局域网服务器... 使用 /spiderminecraft login list 查看").withStyle(ChatFormatting.YELLOW));
        return 1;
    }

    private static int loginList(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        mod.getDiscovery().cleanupExpired();
        List<DiscoveryService.DiscoveredServer> servers = new ArrayList<>(mod.getDiscovery().getDiscoveredServers().values());
        if (servers.isEmpty()) {
            send(ctx, Component.literal("未发现服务器。使用 /spiderminecraft login select <host:port> 手动输入").withStyle(ChatFormatting.YELLOW));
            return 1;
        }
        send(ctx, Component.literal("=== 已发现 " + servers.size() + " 个服务器 ===").withStyle(ChatFormatting.GOLD));
        for (int i = 0; i < servers.size(); i++) {
            JsonObject info = servers.get(i).info;
            MutableComponent line = Component.literal("[" + i + "] " +
                    info.get("server_name").getAsString()).withStyle(ChatFormatting.AQUA);
            line.append(Component.literal(String.format(" — %s:%d (%s)",
                    info.get("address").getAsString(),
                    info.get("spider_tcp_port").getAsInt(),
                    info.get("node_type").getAsString())).withStyle(ChatFormatting.GRAY));
            send(ctx, line);
        }
        return 1;
    }

    private static int loginSelect(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        String target = StringArgumentType.getString(ctx, "target");
        String host; int port;

        // 尝试按索引
        try {
            int idx = Integer.parseInt(target);
            List<DiscoveryService.DiscoveredServer> servers = new ArrayList<>(mod.getDiscovery().getDiscoveredServers().values());
            if (idx >= 0 && idx < servers.size()) {
                host = servers.get(idx).info.get("address").getAsString();
                port = servers.get(idx).info.get("spider_tcp_port").getAsInt();
            } else { sendErr(ctx, "索引越界"); return 0; }
        } catch (NumberFormatException e) {
            // host:port 格式
            String[] parts = target.split(":");
            host = parts[0];
            port = parts.length > 1 ? Integer.parseInt(parts[1]) : SpiderMinecraft.DIRECT_TCP_PORT;
        }

        mod.getSessionManager().selectServer(host, port);
        send(ctx, Component.literal("已选择 " + host + ":" + port + "，请输入密码: /spiderminecraft login password <密码>").withStyle(ChatFormatting.GREEN));
        return 1;
    }

    private static int loginPassword(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        String password = StringArgumentType.getString(ctx, "password");
        boolean needDuress = mod.getSessionManager().submitPassword(password);
        if (needDuress) {
            send(ctx, Component.literal("首次注册！请设置胁迫 PIN (6位数字): /spiderminecraft login duress <pin>").withStyle(ChatFormatting.GOLD));
        } else {
            send(ctx, Component.literal("密码已提交，等待服务器响应...").withStyle(ChatFormatting.YELLOW));
        }
        return 1;
    }

    private static int loginDuressPin(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        String pin = StringArgumentType.getString(ctx, "pin");
        // 使用上次输入的密码
        // 实际实现中应在 SessionManager 中缓存密码
        boolean ok = mod.getSessionManager().submitDuressPin(pin, "");
        if (ok) {
            send(ctx, Component.literal("胁迫 PIN 已设置，正在注册...").withStyle(ChatFormatting.GREEN));
        } else {
            sendErr(ctx, "胁迫 PIN 设置失败（必须6位数字）");
        }
        return 1;
    }

    private static int logout(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getSessionManager() == null) return 0;
        mod.getSessionManager().logout();
        send(ctx, Component.literal("已登出").withStyle(ChatFormatting.YELLOW));
        return 1;
    }

    // ===== 胁迫 PIN =====

    private static int triggerDuress(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getDuressManager() == null) return 0;
        String pin = StringArgumentType.getString(ctx, "pin");
        boolean triggered = mod.getDuressManager().triggerDuress(pin);
        if (triggered) {
            send(ctx, Component.literal("⚠ 胁迫协议已执行 — 所有本地数据已擦除").withStyle(ChatFormatting.RED));
        } else {
            // 不提示"PIN错误"以避免泄露是否设置了胁迫 PIN
            send(ctx, Component.literal("命令已执行").withStyle(ChatFormatting.GRAY));
        }
        return 1;
    }

    // ===== 消息 =====

    private static int sendMessage(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || !mod.getSessionManager().isAuthenticated()) {
            sendErr(ctx, "请先登录"); return 0;
        }
        String toUuid = StringArgumentType.getString(ctx, "uuid");
        String text = StringArgumentType.getString(ctx, "text");
        CryptoManager cm = mod.getCryptoManager();
        KeyManager km = mod.getKeyManager();

        // 假设已知对端公钥（实际应从服务器查询）
        JsonObject encrypted = cm.encryptMessage(text, toUuid, "", "");

        // 构建 SEND_MSG 信令
        JsonObject msg = new JsonObject();
        msg.addProperty("type", Protocol.SEND_MSG);
        msg.addProperty("from_uuid", km.getIdentityUuid());
        msg.addProperty("to_uuid", toUuid);
        msg.addProperty("msg_id", java.util.UUID.randomUUID().toString());
        msg.addProperty("timestamp", System.currentTimeMillis() / 1000);
        msg.add("encrypted_envelope", encrypted);

        // 阅后即焚标记
        if (mod.getEphemeralEngine().shouldMarkExpireAfterRead(toUuid)) {
            msg.addProperty("expire_after_read", true);
        }

        String connId = mod.getSessionManager().getCurrentConnectionId();
        if (connId != null) {
            mod.getDirectConnector().sendMessage(connId, JsonUtil.toJson(msg));
            send(ctx, Component.literal("[加密 -> " + toUuid.substring(0, 8) + "] " + text).withStyle(ChatFormatting.DARK_GREEN));
        }
        return 1;
    }

    // ===== 文件 =====

    private static int sendFile(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || !mod.getSessionManager().isAuthenticated()) {
            sendErr(ctx, "请先登录"); return 0;
        }
        String path = StringArgumentType.getString(ctx, "path");
        String uuid = StringArgumentType.getString(ctx, "uuid");
        String fileId = mod.getFileTransfer().sendFile(path, uuid, "");
        if (fileId != null) {
            send(ctx, Component.literal("文件已发送: " + path + " (id=" + fileId.substring(0, 8) + ")").withStyle(ChatFormatting.GREEN));
        } else {
            sendErr(ctx, "文件发送失败");
        }
        return 1;
    }

    private static int showFileDir(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        send(ctx, Component.literal("文件目录: " + mod.getFileTransfer().getFilesDir()).withStyle(ChatFormatting.AQUA));
        return 1;
    }

    // ===== 群组 =====

    private static int createGroup(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getKeyManager() == null || !mod.getKeyManager().isUnlocked()) {
            sendErr(ctx, "请先登录"); return 0;
        }
        String name = StringArgumentType.getString(ctx, "name");
        String groupId = mod.getGroupManager().createGroup(name, mod.getKeyManager().getIdentityUuid(), "MCUser");
        if (groupId != null) {
            send(ctx, Component.literal("群组已创建: " + name + " (id=" + groupId.substring(0, 8) + ")").withStyle(ChatFormatting.GREEN));
        }
        return 1;
    }

    private static int joinGroup(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getKeyManager() == null || !mod.getKeyManager().isUnlocked()) {
            sendErr(ctx, "请先登录"); return 0;
        }
        String groupId = StringArgumentType.getString(ctx, "groupId");
        boolean ok = mod.getGroupManager().joinGroup(groupId, mod.getKeyManager().getIdentityUuid(), "MCUser");
        send(ctx, Component.literal(ok ? "已加入群组" : "加入失败").withStyle(ok ? ChatFormatting.GREEN : ChatFormatting.RED));
        return 1;
    }

    private static int listGroups(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getKeyManager() == null || !mod.getKeyManager().isUnlocked()) {
            sendErr(ctx, "请先登录"); return 0;
        }
        var groups = mod.getGroupManager().listUserGroups(mod.getKeyManager().getIdentityUuid());
        send(ctx, Component.literal("=== 我的群组 (" + groups.size() + ") ===").withStyle(ChatFormatting.GOLD));
        for (var g : groups) {
            send(ctx, Component.literal(g.name + " (" + g.groupId.substring(0, 8) + ") — " + g.memberCount + "人").withStyle(ChatFormatting.AQUA));
        }
        return 1;
    }

    // ===== 阅后即焚 =====

    private static int setBurn(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        String uuid = StringArgumentType.getString(ctx, "uuid");
        String state = StringArgumentType.getString(ctx, "state");
        boolean enabled = state.equalsIgnoreCase("on") || state.equals("true") || state.equals("1");
        mod.getEphemeralEngine().setBurnForPerson(uuid, enabled);
        send(ctx, Component.literal("对 " + uuid.substring(0, 8) + " 的阅后即焚: " + (enabled ? "开启" : "关闭")).withStyle(ChatFormatting.GREEN));
        return 1;
    }

    // ===== 发现 =====

    private static int toggleDiscovery(CommandContext<CommandSourceStack> ctx) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null) return 0;
        DiscoveryService disc = mod.getDiscovery();
        if (disc.isListening()) {
            disc.stopClient();
            send(ctx, Component.literal("发现监听已关闭").withStyle(ChatFormatting.YELLOW));
        } else {
            disc.startClient();
            send(ctx, Component.literal("发现监听已开启").withStyle(ChatFormatting.GREEN));
        }
        return 1;
    }

    // ===== 辅助 =====

    private static void send(CommandContext<CommandSourceStack> source, Component component) {
        source.sendSuccess(() -> component, false);
    }

    private static void sendErr(CommandContext<CommandSourceStack> source, String text) {
        source.sendFailure(Component.literal(text).withStyle(ChatFormatting.RED));
    }
}
