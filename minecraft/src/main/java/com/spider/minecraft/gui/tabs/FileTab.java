package com.spider.minecraft.gui.tabs;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.gui.SpiderMainScreen;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.network.chat.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 文件标签页 — 加密文件传输管理。
 */
public class FileTab {

    private final SpiderMainScreen parent;
    private final int x, y, width, height;
    private boolean visible = false;

    private EditBox filePathBox;
    private EditBox targetUuidBox;
    private Button sendButton;
    private Button refreshButton;
    private Button openDirButton;
    private List<String> fileList = new ArrayList<>();
    private int scrollOffset = 0;
    private static final int MAX_VISIBLE = 10;

    public FileTab(SpiderMainScreen parent, int x, int y, int width, int height) {
        this.parent = parent;
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
        initWidgets();
    }

    private void initWidgets() {
        filePathBox = new EditBox(parent.getMinecraft().font, x + 4, y + 2, width - 280, 18,
                Component.literal("文件路径"));
        filePathBox.setMaxLength(256);
        filePathBox.setHint("文件路径（相对 saves/SpiderFiles/）");

        targetUuidBox = new EditBox(parent.getMinecraft().font, x + width - 270, y + 2, 150, 18,
                Component.literal("目标UUID"));
        targetUuidBox.setMaxLength(64);
        targetUuidBox.setHint("对方UUID");

        sendButton = Button.builder(Component.literal("发送"), btn -> sendFile())
                .bounds(x + width - 115, y + 1, 50, 18)
                .build();

        refreshButton = Button.builder(Component.literal("刷新"), btn -> refresh())
                .bounds(x + width - 60, y + 1, 55, 18)
                .build();

        openDirButton = Button.builder(Component.literal("打开文件目录"), btn -> openDir())
                .bounds(x + 4, y + 24, 120, 16)
                .build();

        parent.addRenderableWidget(filePathBox);
        parent.addRenderableWidget(targetUuidBox);
        parent.addRenderableWidget(sendButton);
        parent.addRenderableWidget(refreshButton);
        parent.addRenderableWidget(openDirButton);
    }

    private void sendFile() {
        String path = filePathBox.getValue().trim();
        String uuid = targetUuidBox.getValue().trim();
        if (path.isEmpty() || uuid.isEmpty()) {
            parent.sendClientMessage("§c请填写文件路径和目标UUID");
            return;
        }
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getFileTransfer() != null) {
            String fileId = mod.getFileTransfer().sendFile(path, uuid, "");
            if (fileId != null) {
                parent.sendClientMessage("§a文件已加密发送: " + path);
                fileList.add("§a[发送] " + path + " -> " + uuid.substring(0, Math.min(8, uuid.length())) + " (id=" + fileId.substring(0, 8) + ")");
                filePathBox.setValue("");
            } else {
                parent.sendClientMessage("§c文件发送失败");
            }
        }
    }

    private void openDir() {
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getFileTransfer() != null) {
            String dir = mod.getFileTransfer().getFilesDir();
            parent.sendClientMessage("§b文件目录: " + dir);
            fileList.add("§7目录: " + dir);
        }
    }

    public void refresh() {
        fileList.clear();
        SpiderMinecraftMod mod = parent.getMod();
        if (mod != null && mod.getFileTransfer() != null) {
            String dir = mod.getFileTransfer().getFilesDir();
            File dirFile = new File(dir);
            fileList.add("§7=== 文件目录: " + dir + " ===");
            if (dirFile.exists() && dirFile.isDirectory()) {
                File[] files = dirFile.listFiles();
                if (files != null) {
                    for (File f : files) {
                        String size = f.length() > 1024 * 1024 ?
                                String.format("%.1fMB", f.length() / 1024.0 / 1024.0) :
                                String.format("%.1fKB", f.length() / 1024.0);
                        fileList.add("§f" + f.getName() + " §7(" + size + ")");
                    }
                    if (files.length == 0) {
                        fileList.add("§e目录为空");
                    }
                }
            } else {
                fileList.add("§e目录不存在，发送文件时自动创建");
            }
        } else {
            fileList.add("§e文件传输未初始化");
        }
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        if (!visible) return;
        int listY = y + 46;
        int listHeight = height - 50;
        graphics.fill(x, listY, x + width, listY + listHeight, 0xFF0F1923);
        graphics.fill(x + 1, listY + 1, x + width - 1, listY + listHeight - 1, 0xFF1A1A2E);

        int lineY = listY + 4;
        int start = Math.max(0, Math.min(scrollOffset, Math.max(0, fileList.size() - MAX_VISIBLE)));
        int end = Math.min(fileList.size(), start + MAX_VISIBLE);
        for (int i = start; i < end; i++) {
            if (parent.getMinecraft().font != null) {
                graphics.drawString(parent.getMinecraft().font, Component.literal(fileList.get(i)),
                        x + 6, lineY, 0xFFFFFFFF, false);
            }
            lineY += 12;
        }
    }

    public boolean mouseScrolled(double mouseX, double mouseY, double scrollX, double scrollY) {
        if (!visible) return false;
        scrollOffset -= (int) Math.signum(scrollY);
        scrollOffset = Math.max(0, Math.min(scrollOffset, Math.max(0, fileList.size() - MAX_VISIBLE)));
        return true;
    }

    public void setVisible(boolean visible) {
        this.visible = visible;
        filePathBox.setVisible(visible);
        targetUuidBox.setVisible(visible);
        sendButton.visible = visible;
        refreshButton.visible = visible;
        openDirButton.visible = visible;
    }
}
