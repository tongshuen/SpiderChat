package com.spider.minecraft.gui.tabs;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.gui.SpiderMainScreen;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 联系人标签页 — 搜索、添加、管理联系人。
 */
public class ContactsTab {

    private final SpiderMainScreen parent;
    private final int x, y, width, height;
    private boolean visible = false;

    private EditBox searchBox;
    private Button searchButton;
    private Button addButton;
    private Button importButton;
    private List<String> contactList = new ArrayList<>();
    private int selectedIndex = -1;
    private int scrollOffset = 0;
    private static final int MAX_VISIBLE = 10;

    public ContactsTab(SpiderMainScreen parent, int x, int y, int width, int height) {
        this.parent = parent;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        initWidgets();
    }

    private void initWidgets() {
        searchBox = new EditBox(parent.getMinecraft().font, x + 4, y + 2, width - 200, 18,
                Component.literal("搜索"));
        searchBox.setMaxLength(64);
        searchBox.setHint("输入 UUID 或名称搜索...");

        searchButton = Button.builder(Component.literal("搜索"), btn -> doSearch())
                .bounds(x + width - 190, y + 1, 60, 18)
                .build();

        addButton = Button.builder(Component.literal("添加"), btn -> addContact())
                .bounds(x + width - 125, y + 1, 55, 18)
                .build();

        importButton = Button.builder(Component.literal("导入"), btn -> importContact())
                .bounds(x + width - 65, y + 1, 55, 18)
                .build();

        parent.addRenderableWidget(searchBox);
        parent.addRenderableWidget(searchButton);
        parent.addRenderableWidget(addButton);
        parent.addRenderableWidget(importButton);
    }

    private void doSearch() {
        String query = searchBox.getValue().trim();
        if (query.isEmpty()) {
            refresh();
            return;
        }
        contactList.clear();
        contactList.add("§7搜索: " + query);
        contactList.add("§e局域网搜索已启动...");
        contactList.add("§7提示: 可通过 /spiderminecraft discovery 开启发现");
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getDiscovery() != null) {
            var servers = mod.getDiscovery().getDiscoveredServers();
            contactList.add("§a已发现 " + servers.size() + " 个 Spider 节点");
        }
    }

    private void addContact() {
        String query = searchBox.getValue().trim();
        if (query.isEmpty()) {
            parent.sendClientMessage("§c请输入对方 UUID");
            return;
        }
        contactList.add("§a已添加联系人: " + query.substring(0, Math.min(16, query.length())));
        parent.sendClientMessage("§a联系人已添加");
    }

    private void importContact() {
        parent.sendClientMessage("§e请将联系人 JSON 文件放入 saves/SpiderFiles/ 目录");
    }

    public void refresh() {
        contactList.clear();
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getKeyManager() != null && mod.getKeyManager().isUnlocked()) {
            contactList.add("§a我的UUID: " + mod.getKeyManager().getIdentityUuid());
            contactList.add("§7=== 联系人列表 ===");
            contactList.add("§7暂无联系人，使用上方搜索添加");
        } else {
            contactList.add("§e请先登录以管理联系人");
        }
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!visible) return;

        int listY = y + 26;
        int listHeight = height - 30;
        graphics.fill(x, listY, x + width, listY + listHeight, 0xFF0F1923);
        graphics.fill(x + 1, listY + 1, x + width - 1, listY + listHeight - 1, 0xFF1A1A2E);

        int lineY = listY + 4;
        int start = Math.max(0, Math.min(scrollOffset, Math.max(0, contactList.size() - MAX_VISIBLE)));
        int end = Math.min(contactList.size(), start + MAX_VISIBLE);

        for (int i = start; i < end; i++) {
            if (i == selectedIndex) {
                graphics.fill(x + 2, lineY - 1, x + width - 2, lineY + 11, 0x404ECB71);
            }
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(contactList.get(i)),
                        x + 6, lineY, 0xFFFFFFFF, false);
            }
            lineY += 12;
        }
    }

    public boolean mouseClicked(double mouseX, double mouseY, int button) {
        if (!visible) return false;
        int listY = y + 26;
        if (mouseX >= x && mouseX <= x + width && mouseY >= listY) {
            int idx = scrollOffset + ((int) (mouseY - listY - 4) / 12);
            if (idx >= 0 && idx < contactList.size()) {
                selectedIndex = idx;
                return true;
            }
        }
        return false;
    }

    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (!visible) return false;
        scrollOffset -= (int) Math.signum(scrollY);
        scrollOffset = Math.max(0, Math.min(scrollOffset, Math.max(0, contactList.size() - MAX_VISIBLE)));
        return true;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
        searchBox.setVisible(visible);
        searchButton.visible = visible;
        addButton.visible = visible;
        importButton.visible = visible;
    }
}
