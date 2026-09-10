package com.spider.minecraft.forum;

import com.spider.minecraft.SpiderMinecraftMod;
import com.spider.minecraft.gui.SpiderMainScreen;
import com.spider.minecraft.util.JsonUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.network.chat.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * 论坛标签页 — 帖子列表、帖子详情、发帖、评论、投票。
 *
 * <p>发帖页顶部醒目警示：帖子评论明文存储，管理员可查看删除导出，
 * 等同于公开发布，不可否认，敏感信息请移步私聊。
 */
public class ForumTab {

    private final SpiderMainScreen parent;
    private int guiLeft, guiTop, guiWidth, guiHeight;

    // 视图状态
    private enum View { LIST, DETAIL, CREATE }
    private View currentView = View.LIST;

    // 帖子列表
    private List<JsonObject> posts = new ArrayList<>();
    private int selectedPostIndex = -1;
    private JsonObject currentPost = null;

    // 评论
    private List<JsonObject> commentRoots = new ArrayList<>();
    private java.util.Map<String, List<JsonObject>> commentReplies = new java.util.HashMap<>();

    // UI 组件
    private EditBox searchBox;
    private EditBox titleBox;
    private EditBox tagsBox;
    private EditBox contentBox;
    private EditBox commentBox;
    private Button createBtn;
    private Button backBtn;
    private Button upvoteBtn;
    private Button downvoteBtn;
    private Button submitCommentBtn;
    private Button submitPostBtn;

    // 排序
    private String currentSort = "hot";
    private boolean searchMode = false;

    public ForumTab(SpiderMainScreen parent) {
        this.parent = parent;
    }

    public void init(int guiLeft, int guiTop, int guiWidth, int guiHeight) {
        this.guiLeft = guiLeft;
        this.guiTop = guiTop;
        this.guiWidth = guiWidth;
        this.guiHeight = guiHeight;

        int contentTop = guiTop + 32;
        int contentHeight = guiHeight - 40;

        // 搜索框
        searchBox = new EditBox(parent.getFontRenderer(), guiLeft + 8, contentTop, 150, 18,
                Component.literal("搜索帖子"));
        searchBox.setMaxLength(100);

        // 发帖按钮
        createBtn = Button.builder(Component.literal("+ 发帖"), b -> openCreate())
                .bounds(guiLeft + guiWidth - 70, contentTop, 60, 18).build();

        // 排序按钮
        Button sortHot = Button.builder(Component.literal("热"), b -> changeSort("hot"))
                .bounds(guiLeft + 170, contentTop, 30, 18).build();
        Button sortNew = Button.builder(Component.literal("新"), b -> changeSort("new"))
                .bounds(guiLeft + 205, contentTop, 30, 18).build();

        // 详情页按钮
        backBtn = Button.builder(Component.literal("← 返回"), b -> backToList())
                .bounds(guiLeft + 8, contentTop, 60, 18).build();
        upvoteBtn = Button.builder(Component.literal("👍"), b -> vote(1))
                .bounds(guiLeft + guiWidth - 140, contentTop, 40, 18).build();
        downvoteBtn = Button.builder(Component.literal("👎"), b -> vote(-1))
                .bounds(guiLeft + guiWidth - 95, contentTop, 40, 18).build();

        // 发帖表单
        titleBox = new EditBox(parent.getFontRenderer(), guiLeft + 8, contentTop + 30, guiWidth - 16, 18,
                Component.literal("标题"));
        titleBox.setMaxLength(128);
        tagsBox = new EditBox(parent.getFontRenderer(), guiLeft + 8, contentTop + 55, guiWidth - 16, 18,
                Component.literal("标签（逗号分隔）"));
        tagsBox.setMaxLength(50);
        contentBox = new EditBox(parent.getFontRenderer(), guiLeft + 8, contentTop + 80, guiWidth - 16, contentHeight - 120,
                Component.literal("正文"));
        contentBox.setMaxLength(65536);
        submitPostBtn = Button.builder(Component.literal("发布"), b -> submitPost())
                .bounds(guiLeft + guiWidth - 70, guiTop + guiHeight - 25, 60, 18).build();

        // 评论输入
        commentBox = new EditBox(parent.getFontRenderer(), guiLeft + 8, guiTop + guiHeight - 50, guiWidth - 90, 18,
                Component.literal("发表评论..."));
        commentBox.setMaxLength(4096);
        submitCommentBtn = Button.builder(Component.literal("发送"), b -> submitComment())
                .bounds(guiLeft + guiWidth - 75, guiTop + guiHeight - 50, 60, 18).build();

        // 初始加载帖子
        loadPosts();
    }

    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        int contentTop = guiTop + 32;
        int contentHeight = guiHeight - 40;

        // 标题
        graphics.drawString(parent.getFontRenderer(), "Spider 论坛", guiLeft + 8, guiTop + 10, 0xFFFFFF, false);

        if (currentView == View.LIST) {
            renderListView(graphics, contentTop, contentHeight, mouseX, mouseY);
        } else if (currentView == View.DETAIL) {
            renderDetailView(graphics, contentTop, contentHeight, mouseX, mouseY);
        } else if (currentView == View.CREATE) {
            renderCreateView(graphics, contentTop, contentHeight);
        }
    }

    private void renderListView(GuiGraphics graphics, int contentTop, int contentHeight, int mouseX, int mouseY) {
        // 搜索和发帖按钮
        searchBox.render(graphics, mouseX, mouseY, 0);

        // 帖子列表
        int y = contentTop + 25;
        int listHeight = contentHeight - 30;

        if (posts.isEmpty()) {
            graphics.drawString(parent.getFontRenderer(), "暂无帖子", guiLeft + guiWidth / 2 - 20,
                    contentTop + contentHeight / 2, 0x888888, false);
        } else {
            for (int i = 0; i < posts.size() && y < contentTop + listHeight; i++) {
                JsonObject post = posts.get(i);
                int itemHeight = 36;
                boolean selected = (i == selectedPostIndex);

                // 背景
                graphics.fill(guiLeft + 4, y, guiLeft + guiWidth - 4, y + itemHeight,
                        selected ? 0x334488 : 0x222222);

                // 标题
                String title = JsonUtil.getString(post, "title", "");
                if (title.length() > 40) title = title.substring(0, 40) + "...";
                graphics.drawString(parent.getFontRenderer(), title, guiLeft + 8, y + 4, 0xFFFFFF, false);

                // 元信息
                String meta = String.format("↑%d ↓%d | 💬%d",
                        JsonUtil.getInt(post, "upvotes", 0),
                        JsonUtil.getInt(post, "downvotes", 0),
                        JsonUtil.getInt(post, "comment_count", 0));
                graphics.drawString(parent.getFontRenderer(), meta, guiLeft + 8, y + 18, 0x888888, false);

                // 标签
                String tags = JsonUtil.getString(post, "tags", "");
                if (!tags.isEmpty()) {
                    graphics.drawString(parent.getFontRenderer(), "#" + tags.replace(",", " #"),
                            guiLeft + 120, y + 18, 0x5588FF, false);
                }

                y += itemHeight + 2;
            }
        }
    }

    private void renderDetailView(GuiGraphics graphics, int contentTop, int contentHeight, int mouseX, int mouseY) {
        if (currentPost == null) return;

        int y = contentTop + 25;

        // 标题
        String title = JsonUtil.getString(currentPost, "title", "");
        graphics.drawString(parent.getFontRenderer(), title, guiLeft + 8, y, 0xFFFFFF, false);
        y += 12;

        // 作者和时间
        String author = JsonUtil.getString(currentPost, "author_uuid", "").substring(0, Math.min(12, JsonUtil.getString(currentPost, "author_uuid", "").length())) + "...";
        graphics.drawString(parent.getFontRenderer(), "作者: " + author, guiLeft + 8, y, 0x888888, false);
        y += 14;

        // 正文（简单换行）
        String content = JsonUtil.getString(currentPost, "content", "");
        int maxCharsPerLine = (guiWidth - 20) / 6;
        for (int i = 0; i < content.length() && y < contentTop + contentHeight - 80; i += maxCharsPerLine) {
            int end = Math.min(i + maxCharsPerLine, content.length());
            graphics.drawString(parent.getFontRenderer(), content.substring(i, end),
                    guiLeft + 8, y, 0xDDDDDD, false);
            y += 10;
        }

        y += 8;
        // 投票信息
        graphics.drawString(parent.getFontRenderer(),
                String.format("净投票: %d (↑%d ↓%d)",
                        JsonUtil.getInt(currentPost, "net_votes", 0),
                        JsonUtil.getInt(currentPost, "upvotes", 0),
                        JsonUtil.getInt(currentPost, "downvotes", 0)),
                guiLeft + 8, y, 0xFFAA00, false);

        // 评论区
        y += 16;
        graphics.drawString(parent.getFontRenderer(), "评论:", guiLeft + 8, y, 0xFFFFFF, false);
        y += 12;

        for (JsonObject root : commentRoots) {
            if (y > contentTop + contentHeight - 60) break;
            String cAuthor = JsonUtil.getString(root, "author_uuid", "").substring(0, Math.min(10, JsonUtil.getString(root, "author_uuid", "").length()));
            String cContent = JsonUtil.getString(root, "content", "");
            if (cContent.length() > 50) cContent = cContent.substring(0, 50) + "...";
            graphics.drawString(parent.getFontRenderer(), cAuthor + ": " + cContent,
                    guiLeft + 12, y, 0xCCCCCC, false);
            y += 10;

            // 回复
            List<JsonObject> replies = commentReplies.getOrDefault(JsonUtil.getString(root, "id", ""), new ArrayList<>());
            for (JsonObject reply : replies) {
                if (y > contentTop + contentHeight - 60) break;
                String rAuthor = JsonUtil.getString(reply, "author_uuid", "").substring(0, Math.min(10, JsonUtil.getString(reply, "author_uuid", "").length()));
                String rContent = JsonUtil.getString(reply, "content", "");
                if (rContent.length() > 45) rContent = rContent.substring(0, 45) + "...";
                graphics.drawString(parent.getFontRenderer(), "  └ " + rAuthor + ": " + rContent,
                        guiLeft + 20, y, 0x999999, false);
                y += 10;
            }
            y += 2;
        }
    }

    private void renderCreateView(GuiGraphics graphics, int contentTop, int contentHeight) {
        // 醒目警示
        graphics.fill(guiLeft + 4, contentTop + 5, guiLeft + guiWidth - 4, contentTop + 50, 0x662222);
        graphics.drawString(parent.getFontRenderer(), "⚠ 重要警示", guiLeft + 8, contentTop + 10, 0xFF4444, false);
        graphics.drawString(parent.getFontRenderer(), "帖子和评论明文存储，管理员可查看删除导出。", guiLeft + 8, contentTop + 24, 0xFF8888, false);
        graphics.drawString(parent.getFontRenderer(), "等同于公开发布，不可否认。敏感信息请移步私聊。", guiLeft + 8, contentTop + 36, 0xFF8888, false);

        titleBox.render(graphics, 0, 0, 0);
        tagsBox.render(graphics, 0, 0, 0);
        contentBox.render(graphics, 0, 0, 0);
    }

    // ===== 操作 =====

    /** 发送论坛消息到服务器（通过 DirectConnector） */
    private boolean sendForumMessage(JsonObject msg) {
        SpiderMinecraftMod mod = SpiderMinecraftMod.get();
        if (mod == null || mod.getSessionManager() == null || !mod.getSessionManager().isAuthenticated()) {
            return false;
        }
        String connId = mod.getSessionManager().getCurrentConnectionId();
        if (connId == null || mod.getDirectConnector() == null) return false;
        mod.getDirectConnector().sendMessage(connId, JsonUtil.toJson(msg));
        return true;
    }

    private void loadPosts() {
        JsonObject req = new JsonObject();
        req.addProperty("type", "POST_LIST");
        req.addProperty("sort", currentSort);
        req.addProperty("limit", 50);
        sendForumMessage(req);
    }

    private void changeSort(String sort) {
        this.currentSort = sort;
        this.searchMode = false;
        loadPosts();
    }

    private void openCreate() {
        currentView = View.CREATE;
        titleBox.setValue("");
        tagsBox.setValue("");
        contentBox.setValue("");
    }

    private void backToList() {
        currentView = View.LIST;
        currentPost = null;
        loadPosts();
    }

    private void submitPost() {
        String title = titleBox.getValue();
        String content = contentBox.getValue();
        if (title.isEmpty() || content.isEmpty()) return;

        JsonObject req = new JsonObject();
        req.addProperty("type", "POST_CREATE");
        req.addProperty("title", title);
        req.addProperty("content", content);
        JsonArray tagsArr = new JsonArray();
        for (String t : tagsBox.getValue().split(",")) {
            if (!t.trim().isEmpty()) tagsArr.add(t.trim());
        }
        req.add("tags", tagsArr);
        sendForumMessage(req);

        currentView = View.LIST;
        loadPosts();
    }

    private void submitComment() {
        if (currentPost == null) return;
        String content = commentBox.getValue();
        if (content.isEmpty()) return;

        JsonObject req = new JsonObject();
        req.addProperty("type", "COMMENT_CREATE");
        req.addProperty("post_id", JsonUtil.getString(currentPost, "id", ""));
        req.addProperty("content", content);
        sendForumMessage(req);

        commentBox.setValue("");
        // 刷新评论
        JsonObject listReq = new JsonObject();
        listReq.addProperty("type", "COMMENT_LIST");
        listReq.addProperty("post_id", JsonUtil.getString(currentPost, "id", ""));
        sendForumMessage(listReq);
    }

    private void vote(int value) {
        if (currentPost == null) return;
        JsonObject req = new JsonObject();
        req.addProperty("type", "VOTE_CAST");
        req.addProperty("target_type", "post");
        req.addProperty("target_id", JsonUtil.getString(currentPost, "id", ""));
        req.addProperty("value", value);
        sendForumMessage(req);
    }

    // ===== 消息处理 =====

    public void handleMessage(JsonObject msg) {
        String type = JsonUtil.getString(msg, "type", "");
        switch (type) {
            case "POST_LIST_RESULT":
            case "POST_SEARCH_RESULT":
            case "POST_HOT_RANKING_RESULT":
                posts.clear();
                JsonArray arr = msg.getAsJsonArray("posts");
                for (int i = 0; i < arr.size(); i++) {
                    posts.add(arr.get(i).getAsJsonObject());
                }
                break;
            case "POST_GET_RESULT":
                currentPost = msg.getAsJsonObject("post");
                currentView = View.DETAIL;
                break;
            case "COMMENT_LIST_RESULT":
                commentRoots.clear();
                commentReplies.clear();
                if (msg.has("roots")) {
                    JsonArray roots = msg.getAsJsonArray("roots");
                    for (int i = 0; i < roots.size(); i++) {
                        commentRoots.add(roots.get(i).getAsJsonObject());
                    }
                }
                if (msg.has("replies") && msg.get("replies").isJsonObject()) {
                    JsonObject repliesObj = msg.getAsJsonObject("replies");
                    for (String key : repliesObj.keySet()) {
                        List<JsonObject> replyList = new ArrayList<>();
                        JsonArray replyArr = repliesObj.getAsJsonArray(key);
                        for (int i = 0; i < replyArr.size(); i++) {
                            replyList.add(replyArr.get(i).getAsJsonObject());
                        }
                        commentReplies.put(key, replyList);
                    }
                }
                break;
            case "POST_CREATE_RESULT":
                loadPosts();
                break;
            case "VOTE_CAST_RESULT":
                if (currentPost != null) {
                    JsonObject getReq = new JsonObject();
                    getReq.addProperty("type", "POST_GET");
                    getReq.addProperty("id", JsonUtil.getString(currentPost, "id", ""));
                    sendForumMessage(getReq);
                }
                break;
        }
    }

    // ===== 鼠标点击 =====

    public boolean mouseClicked(double mouseX, double mouseY, int button) {
        if (currentView == View.LIST) {
            // 检测帖子点击
            int contentTop = guiTop + 32;
            int y = contentTop + 25;
            for (int i = 0; i < posts.size(); i++) {
                int itemHeight = 36;
                if (mouseX >= guiLeft + 4 && mouseX <= guiLeft + guiWidth - 4 &&
                    mouseY >= y && mouseY <= y + itemHeight) {
                    selectedPostIndex = i;
                    JsonObject post = posts.get(i);
                    JsonObject req = new JsonObject();
                    req.addProperty("type", "POST_GET");
                    req.addProperty("id", JsonUtil.getString(post, "id", ""));
                    sendForumMessage(req);

                    JsonObject cReq = new JsonObject();
                    cReq.addProperty("type", "COMMENT_LIST");
                    cReq.addProperty("post_id", JsonUtil.getString(post, "id", ""));
                    sendForumMessage(cReq);
                    return true;
                }
                y += itemHeight + 2;
            }
        }
        return false;
    }

    public void tick() {
        if (searchBox != null) searchBox.tick();
        if (titleBox != null) titleBox.tick();
        if (tagsBox != null) tagsBox.tick();
        if (contentBox != null) contentBox.tick();
        if (commentBox != null) commentBox.tick();
    }

    public List<Button> getButtons() {
        List<Button> btns = new ArrayList<>();
        if (currentView == View.LIST) {
            btns.add(createBtn);
        } else if (currentView == View.DETAIL) {
            btns.add(backBtn);
            btns.add(upvoteBtn);
            btns.add(downvoteBtn);
            btns.add(submitCommentBtn);
        } else if (currentView == View.CREATE) {
            btns.add(backBtn);
            btns.add(submitPostBtn);
        }
        return btns;
    }

    public List<EditBox> getEditBoxes() {
        List<EditBox> boxes = new ArrayList<>();
        if (currentView == View.LIST) {
            boxes.add(searchBox);
        } else if (currentView == View.DETAIL) {
            boxes.add(commentBox);
        } else if (currentView == View.CREATE) {
            boxes.add(titleBox);
            boxes.add(tagsBox);
            boxes.add(contentBox);
        }
        return boxes;
    }
}
