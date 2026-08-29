package com.spider.minecraft.gui;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.gui.tabs.*;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/**
 * Spider 主 GUI 界面 — 模仿原版 Spider 客户端的图形界面。
 *
 * <p>包含以下标签页：
 * <ul>
 *   <li>聊天 — 查看和发送加密消息</li>
 *   <li>联系人 — 搜索、添加、管理联系人</li>
 *   <li>群组 — 创建、加入、管理群组</li>
 *   <li>登录 — 服务器发现、登录/注册</li>
 *   <li>文件 — 文件传输管理</li>
 *   <li>设置 — 颜色、自动下载、已读回执等</li>
 * </ul>
 *
 * <p>CLI 命令仍然完全可用，此 GUI 是额外的图形交互入口。
 */
public class SpiderMainScreen extends Screen {

    private static final int TAB_COUNT = 6;
    private static final String[] TAB_NAMES = {"聊天", "联系人", "群组", "登录", "文件", "设置"};

    private int selectedTab = 0;
    private Button[] tabButtons;
    private ChatTab chatTab;
    private ContactsTab contactsTab;
    private GroupsTab groupsTab;
    private LoginTab loginTab;
    private FileTab fileTab;
    private SettingsTab settingsTab;

    // 布局参数
    private int guiWidth;
    private int guiHeight;
    private int guiLeft;
    private int guiTop;
    private static final int TAB_HEIGHT = 24;
    private static final int CONTENT_PADDING = 8;

    public SpiderMainScreen() {
        super(Component.literal("Spider 加密聊天"));
    }

    @Override
    protected void init() {
        this.guiWidth = Math.min(600, this.width - 40);
        this.guiHeight = Math.min(400, this.height - 60);
        this.guiLeft = (this.width - this.guiWidth) / 2;
        this.guiTop = (this.height - this.guiHeight) / 2;

        // 创建标签页按钮
        tabButtons = new Button[TAB_COUNT];
        int tabWidth = this.guiWidth / TAB_COUNT;
        for (int i = 0; i < TAB_COUNT; i++) {
            final int tabIndex = i;
            int x = this.guiLeft + i * tabWidth;
            int y = this.guiTop;
            tabButtons[i] = Button.builder(Component.literal(TAB_NAMES[i]),
                    btn -> selectTab(tabIndex))
                    .bounds(x, y, tabWidth - 1, TAB_HEIGHT)
                    .build();
            this.addRenderableWidget(tabButtons[i]);
        }

        // 初始化各标签页
        int contentY = this.guiTop + TAB_HEIGHT + CONTENT_PADDING;
        int contentHeight = this.guiHeight - TAB_HEIGHT - CONTENT_PADDING * 2;

        chatTab = new ChatTab(this, this.guiLeft + CONTENT_PADDING, contentY,
                this.guiWidth - CONTENT_PADDING * 2, contentHeight);
        contactsTab = new ContactsTab(this, this.guiLeft + CONTENT_PADDING, contentY,
                this.guiWidth - CONTENT_PADDING * 2, contentHeight);
        groupsTab = new GroupsTab(this, this.guiLeft + CONTENT_PADDING, contentY,
                this.guiWidth - CONTENT_PADDING * 2, contentHeight);
        loginTab = new LoginTab(this, this.guiLeft + CONTENT_PADDING, contentY,
                this.guiWidth - CONTENT_PADDING * 2, contentHeight);
        fileTab = new FileTab(this, this.guiLeft + CONTENT_PADDING, contentY,
                this.guiWidth - CONTENT_PADDING * 2, contentHeight);
        settingsTab = new SettingsTab(this, this.guiLeft + CONTENT_PADDING, contentY,
                this.guiWidth - CONTENT_PADDING * 2, contentHeight);

        selectTab(0);
    }

    private void selectTab(int index) {
        this.selectedTab = index;
        // 更新按钮样式（选中的按钮高亮）
        for (int i = 0; i < TAB_COUNT; i++) {
            tabButtons[i].active = (i != index);
        }
        // 隐藏/显示各标签页组件
        chatTab.setVisible(index == 0);
        contactsTab.setVisible(index == 1);
        groupsTab.setVisible(index == 2);
        loginTab.setVisible(index == 3);
        fileTab.setVisible(index == 4);
        settingsTab.setVisible(index == 5);

        // 选中时刷新数据
        if (index == 0) chatTab.refresh();
        if (index == 1) contactsTab.refresh();
        if (index == 2) groupsTab.refresh();
        if (index == 3) loginTab.refresh();
        if (index == 4) fileTab.refresh();
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        // 渲染背景
        this.renderBackground(graphics, mouseX, mouseY, partialTick);

        // 渲染 GUI 外框
        graphics.fill(this.guiLeft - 2, this.guiTop - 2,
                this.guiLeft + this.guiWidth + 2, this.guiTop + this.guiHeight + 2, 0xFF333333);
        graphics.fill(this.guiLeft, this.guiTop,
                this.guiLeft + this.guiWidth, this.guiTop + this.guiHeight, 0xFF1A1A2E);

        // 渲染内容区域背景
        int contentY = this.guiTop + TAB_HEIGHT;
        graphics.fill(this.guiLeft, contentY,
                this.guiLeft + this.guiWidth, this.guiTop + this.guiHeight, 0xFF16213E);

        // 渲染标题栏状态
        renderStatusBar(graphics);

        // 渲染当前标签页
        switch (selectedTab) {
            case 0 -> chatTab.render(graphics, mouseX, mouseY, partialTick);
            case 1 -> contactsTab.render(graphics, mouseX, mouseY, partialTick);
            case 2 -> groupsTab.render(graphics, mouseX, mouseY, partialTick);
            case 3 -> loginTab.render(graphics, mouseX, mouseY, partialTick);
            case 4 -> fileTab.render(graphics, mouseX, mouseY, partialTick);
            case 5 -> settingsTab.render(graphics, mouseX, mouseY, partialTick);
        }

        super.render(graphics, mouseX, mouseY, partialTick);
    }

    private void renderStatusBar(GuiGraphics graphics) {
        int y = this.guiTop + this.guiHeight - 16;
        graphics.fill(this.guiLeft, y, this.guiLeft + this.guiWidth, y + 16, 0xFF0F3460);

        String status = "未连接";
        int color = 0xFFFF6B6B;
        if (SpiderMinecraftMod.get() != null && SpiderMinecraftMod.get().getSessionManager() != null) {
            var sm = SpiderMinecraftMod.get().getSessionManager();
            if (sm.isAuthenticated()) {
                status = "已连接: " + sm.getCurrentServerHost();
                color = 0xFF4ECB71;
            } else if (sm.getLoginState() != null && !sm.getLoginState().isEmpty()) {
                status = "登录中: " + sm.getLoginState();
                color = 0xFFFFD93D;
            }
        }

        if (this.font != null) {
            graphics.drawString(this.font, Component.literal(status),
                    this.guiLeft + 6, y + 4, color, false);
        }
    }

    @Override
    public boolean isPauseScreen() {
        return false; // 不暂停游戏
    }

    // ===== 供各标签页调用的辅助方法 =====

    public SpiderMinecraftMod getMod() {
        return SpiderMinecraftMod.get();
    }

    public void sendClientMessage(String text) {
        if (this.minecraft != null && this.minecraft.player != null) {
            this.minecraft.player.displayClientMessage(Component.literal(text), false);
        }
    }

    public void switchToTab(int tabIndex) {
        if (tabIndex >= 0 && tabIndex < TAB_COUNT) {
            selectTab(tabIndex);
        }
    }
}
