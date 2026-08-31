package com.spider.minecraft.gui.tabs;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.gui.SpiderMainScreen;
import com.spider.minecraft.network.DiscoveryService;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.Checkbox;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 登录标签页 — 服务器发现、登录/注册流程。
 * 模仿原版 Spider 客户端的注册/登录窗口。
 */
public class LoginTab {

    private final SpiderMainScreen parent;
    private final int x, y, width, height;
    private boolean visible = false;

    private EditBox serverHostBox;
    private EditBox passwordBox;
    private EditBox duressPinBox;
    private EditBox displayNameBox;
    private Button discoverButton;
    private Button connectButton;
    private Button registerButton;
    private Button logoutButton;
    private Checkbox stealthCheckBox;
    private List<String> serverList = new ArrayList<>();
    private List<String> logMessages = new ArrayList<>();
    private int scrollOffset = 0;
    private static final int MAX_VISIBLE = 8;

    public LoginTab(SpiderMainScreen parent, int x, int y, int width, int height) {
        this.parent = parent;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        initWidgets();
    }

    private void initWidgets() {
        int col1 = x + 4;
        int col2 = x + width / 2 + 4;
        int row1 = y + 4;
        int row2 = y + 28;
        int row3 = y + 52;
        int inputWidth = width / 2 - 12;

        displayNameBox = new EditBox(parent.getMinecraft().font, col1, row1, inputWidth, 18,
                Component.literal("显示名称"));
        displayNameBox.setMaxLength(32);
        displayNameBox.setHint("显示名称（注册时）");

        serverHostBox = new EditBox(parent.getMinecraft().font, col2, row1, inputWidth - 70, 18,
                Component.literal("服务器"));
        serverHostBox.setMaxLength(64);
        serverHostBox.setHint("host:port");

        discoverButton = Button.builder(Component.literal("发现"), btn -> discoverServers())
                .bounds(x + width - 65, row1 - 1, 60, 18)
                .build();

        passwordBox = new EditBox(parent.getMinecraft().font, col1, row2, inputWidth, 18,
                Component.literal("密码"));
        passwordBox.setMaxLength(64);
        passwordBox.setHint("解锁密码（8/10/12/16位PIN，不可为回文数）");

        duressPinBox = new EditBox(parent.getMinecraft().font, col2, row2, inputWidth, 18,
                Component.literal("胁迫PIN"));
        duressPinBox.setMaxLength(16);
        duressPinBox.setHint("胁迫PIN（注册时设置）");

        connectButton = Button.builder(Component.literal("连接/登录"), btn -> connect())
                .bounds(col1, row3, 100, 20)
                .build();

        registerButton = Button.builder(Component.literal("注册"), btn -> register())
                .bounds(col1 + 105, row3, 80, 20)
                .build();

        logoutButton = Button.builder(Component.literal("登出"), btn -> logout())
                .bounds(col1 + 190, row3, 80, 20)
                .build();

        stealthCheckBox = Checkbox.builder(Component.literal("隐匿模式（UUID 使用 MAC 哈希）"), parent.getMinecraft().font)
                .bounds(col1, row3 + 25, 200, 20)
                .build();

        parent.addRenderableWidget(displayNameBox);
        parent.addRenderableWidget(serverHostBox);
        parent.addRenderableWidget(discoverButton);
        parent.addRenderableWidget(passwordBox);
        parent.addRenderableWidget(duressPinBox);
        parent.addRenderableWidget(connectButton);
        parent.addRenderableWidget(registerButton);
        parent.addRenderableWidget(logoutButton);
        parent.addRenderableWidget(stealthCheckBox);
    }

    private void discoverServers() {
        logMessages.clear();
        logMessages.add("§e正在扫描局域网 Spider 服务器...");
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getDiscovery() != null) {
            mod.getDiscovery().startClient();
            mod.getDiscovery().cleanupExpired();
            var servers = new ArrayList<>(mod.getDiscovery().getDiscoveredServers().values());
            serverList.clear();
            if (servers.isEmpty()) {
                logMessages.add("§c未发现服务器，请手动输入 host:port");
            } else {
                logMessages.add("§a发现 " + servers.size() + " 个服务器:");
                for (int i = 0; i < servers.size(); i++) {
                    var info = servers.get(i).info;
                    String addr = info.get("address").getAsString() + ":" + info.get("spider_tcp_port").getAsInt();
                    String name = info.get("server_name").getAsString();
                    serverList.add(addr);
                    logMessages.add("§b[" + i + "] " + name + " §7(" + addr + ")");
                }
                if (!serverList.isEmpty()) {
                    serverHostBox.setValue(serverList.get(0));
                }
            }
        }
    }

    private void connect() {
        String host = serverHostBox.getValue().trim();
        String password = passwordBox.getValue().trim();
        if (host.isEmpty()) {
            logMessages.add("§c请输入服务器地址");
            return;
        }
        SpiderMinecraftMod mod = parent.getMod();
        if (mod == null || mod.getSessionManager() == null) return;

        String[] parts = host.split(":");
        String h = parts[0];
        int p = parts.length > 1 ? Integer.parseInt(parts[1]) : 25565;
        mod.getSessionManager().selectServer(h, p);
        logMessages.add("§e已选择服务器: " + host);

        if (!password.isEmpty()) {
            boolean needDuress = mod.getSessionManager().submitPassword(password);
            if (needDuress) {
                logMessages.add("§6首次注册！请设置胁迫PIN后点击注册");
            } else {
                logMessages.add("§e密码已提交，等待服务器响应...");
            }
        } else {
            logMessages.add("§e请输入密码后点击连接");
        }
    }

    private void register() {
        String duress = duressPinBox.getValue().trim();
        String displayName = displayNameBox.getValue().trim();
        if (duress.isEmpty()) {
            logMessages.add("§c请设置胁迫PIN（8/10/12/16位数字）");
            return;
        }
        SpiderMinecraftMod mod = parent.getMod();
        if (mod == null || mod.getSessionManager() == null) return;
        mod.getSessionManager().setStealthMode(stealthCheckBox.selected());
        boolean ok = mod.getSessionManager().submitDuressPin(duress, displayName);
        logMessages.add(ok ? "§a注册中..." : "§c胁迫PIN设置失败");
    }

    private void logout() {
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getSessionManager() != null) {
            mod.getSessionManager().logout();
            logMessages.add("§e已登出");
        }
    }

    public void refresh() {
        logMessages.clear();
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getSessionManager() != null) {
            var sm = mod.getSessionManager();
            if (sm.isAuthenticated()) {
                logMessages.add("§a已登录: " + sm.getCurrentServerHost());
                if (mod.getKeyManager() != null) {
                    logMessages.add("§aUUID: " + mod.getKeyManager().getIdentityUuid());
                }
            } else {
                logMessages.add("§e未登录 — 点击发现查找服务器，或手动输入地址");
                logMessages.add("§7提示: 也可使用 /spiderminecraft login begin 命令");
            }
        }
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!visible) return;
        int logY = y + 80;
        int logHeight = height - 85;
        graphics.fill(x, logY, x + width, logY + logHeight, 0xFF0F1923);
        graphics.fill(x + 1, logY + 1, x + width - 1, logY + logHeight - 1, 0xFF0A0A1A);

        int lineY = logY + 4;
        int start = Math.max(0, Math.min(scrollOffset, Math.max(0, logMessages.size() - MAX_VISIBLE)));
        int end = Math.min(logMessages.size(), start + MAX_VISIBLE);
        for (int i = start; i < end; i++) {
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(logMessages.get(i)),
                        x + 6, lineY, 0xFFFFFFFF, false);
            }
            lineY += 12;
        }
    }

    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (!visible) return false;
        scrollOffset -= (int) Math.signum(scrollY);
        scrollOffset = Math.max(0, Math.min(scrollOffset, Math.max(0, logMessages.size() - MAX_VISIBLE)));
        return true;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
        displayNameBox.setVisible(visible);
        serverHostBox.setVisible(visible);
        discoverButton.visible = visible;
        passwordBox.setVisible(visible);
        duressPinBox.setVisible(visible);
        connectButton.visible = visible;
        registerButton.visible = visible;
        logoutButton.visible = visible;
    }
}
