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
 * 群组标签页 — 创建、加入、管理群组。
 */
public class GroupsTab {

    private final SpiderMainScreen parent;
    private final int x, y, width, height;
    private boolean visible = false;

    private EditBox groupNameBox;
    private EditBox joinIdBox;
    private Button createButton;
    private Button joinButton;
    private Button refreshButton;
    private List<String> groupList = new ArrayList<>();
    private int scrollOffset = 0;
    private static final int MAX_VISIBLE = 10;

    public GroupsTab(SpiderMainScreen parent, int x, int y, int width, int height) {
        this.parent = parent;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        initWidgets();
    }

    private void initWidgets() {
        groupNameBox = new EditBox(parent.getMinecraft().font, x + 4, y + 2, 180, 18,
                Component.literal("群组名"));
        groupNameBox.setMaxLength(32);
        groupNameBox.setHint("新群组名称");

        createButton = Button.builder(Component.literal("创建"), btn -> createGroup())
                .bounds(x + 190, y + 1, 55, 18)
                .build();

        joinIdBox = new EditBox(parent.getMinecraft().font, x + 255, y + 2, 180, 18,
                Component.literal("群组ID"));
        joinIdBox.setMaxLength(64);
        joinIdBox.setHint("要加入的群组ID");

        joinButton = Button.builder(Component.literal("加入"), btn -> joinGroup())
                .bounds(x + 440, y + 1, 55, 18)
                .build();

        refreshButton = Button.builder(Component.literal("刷新"), btn -> refresh())
                .bounds(x + width - 60, y + 1, 55, 18)
                .build();

        parent.addRenderableWidget(groupNameBox);
        parent.addRenderableWidget(createButton);
        parent.addRenderableWidget(joinIdBox);
        parent.addRenderableWidget(joinButton);
        parent.addRenderableWidget(refreshButton);
    }

    private void createGroup() {
        String name = groupNameBox.getValue().trim();
        if (name.isEmpty()) {
            parent.sendClientMessage("§c请输入群组名称");
            return;
        }
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getGroupManager() != null && mod.getKeyManager() != null) {
            String gid = mod.getGroupManager().createGroup(name, mod.getKeyManager().getIdentityUuid(), "MCUser");
            if (gid != null) {
                parent.sendClientMessage("§a群组已创建: " + name + " (id=" + gid.substring(0, 8) + ")");
                groupNameBox.setValue("");
                refresh();
            }
        }
    }

    private void joinGroup() {
        String gid = joinIdBox.getValue().trim();
        if (gid.isEmpty()) {
            parent.sendClientMessage("§c请输入群组ID");
            return;
        }
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getGroupManager() != null && mod.getKeyManager() != null) {
            boolean ok = mod.getGroupManager().joinGroup(gid, mod.getKeyManager().getIdentityUuid(), "MCUser");
            parent.sendClientMessage(ok ? "§a已加入群组" : "§c加入失败");
            if (ok) {
                joinIdBox.setValue("");
                refresh();
            }
        }
    }

    public void refresh() {
        groupList.clear();
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getGroupManager() != null && mod.getKeyManager() != null && mod.getKeyManager().isUnlocked()) {
            var groups = mod.getGroupManager().listUserGroups(mod.getKeyManager().getIdentityUuid());
            groupList.add("§7=== 我的群组 (" + groups.size() + ") ===");
            for (var g : groups) {
                groupList.add("§a" + g.name + " §7(" + g.groupId.substring(0, Math.min(8, g.groupId.length())) + ") — " + g.memberCount + "人");
            }
            if (groups.isEmpty()) {
                groupList.add("§e暂无群组，创建或加入一个吧");
            }
        } else {
            groupList.add("§e请先登录以查看群组");
        }
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!visible) return;
        int listY = y + 26;
        int listHeight = height - 30;
        graphics.fill(x, listY, x + width, listY + listHeight, 0xFF0F1923);
        graphics.fill(x + 1, listY + 1, x + width - 1, listY + listHeight - 1, 0xFF1A1A2E);

        int lineY = listY + 4;
        int start = Math.max(0, Math.min(scrollOffset, Math.max(0, groupList.size() - MAX_VISIBLE)));
        int end = Math.min(groupList.size(), start + MAX_VISIBLE);
        for (int i = start; i < end; i++) {
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(groupList.get(i)),
                        x + 6, lineY, 0xFFFFFFFF, false);
            }
            lineY += 12;
        }
    }

    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (!visible) return false;
        scrollOffset -= (int) Math.signum(scrollY);
        scrollOffset = Math.max(0, Math.min(scrollOffset, Math.max(0, groupList.size() - MAX_VISIBLE)));
        return true;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
        groupNameBox.setVisible(visible);
        createButton.visible = visible;
        joinIdBox.setVisible(visible);
        joinButton.visible = visible;
        refreshButton.visible = visible;
    }
}
