# Spider 论坛子系统设计文档

## 一、概述

Spider 论坛子系统为 Spider 端到端加密通信系统新增公开论坛功能，覆盖服务端、Python 客户端、Minecraft 模组、Android 客户端四端。论坛帖子不端到端加密，明文存储于服务器，传输走现有 TransportEncryptor。

## 二、硬约束

- 不修改 `shared/protocol.py` 已有常量，只新增
- 不修改 `crypto_utils.py` 已有函数签名
- 不改 TransportEncryptor 线格式
- 不改 identity.json 结构
- 论坛数据独立 `forum.db`，通过 UUID 关联 users.db
- 数据库迁移用 `CREATE TABLE IF NOT EXISTS`
- 所有改动向后兼容，新客户端连旧服务器不崩溃

## 三、核心设计

### 3.1 帖子

- 帖子 ID 格式：`{node_id}:{64hex}`
- 帖子附作者和服务器双层 Ed25519 签名
- 发帖页顶部醒目警示：帖子评论明文存储，管理员可查看删除导出，等同于公开发布，不可否认，敏感信息请移步私聊
- 帖子不联邦，只联邦服务器目录
- 每服为本服帖子唯一权威，跨服按 ID 直达

### 3.2 跨服寻址

寻址顺序：
1. 解析前缀 → 本服前缀本地查
2. 本地 known_servers 查
3. DHT 查 `server:` 键
4. 失败返回明确错误

**禁止广播整个联邦作为回退。** 跨服超时 5 秒。

### 3.3 热度公式

```
hot_score = log10(max(|net_votes|, 1)) * sign(net_votes)
          + w * log10(max(distinct_commenters, 1))
          + post_timestamp / 45000
```

- `sign(0) = 0` 显式处理
- `w` 默认 0.8
- `distinct_commenters` = 去重评论者数（不用"只有第一条评论生效"）
- `post_timestamp` = 发帖时间（Unix 秒）
- 后台每 5-10 分钟重算，查询直接排序
- 提供"为什么这个排名"分解

### 3.4 投票

- 投票值 -1/0/1
- 每用户每对象一票，改票正确回滚旧票
- 乐观更新失败回滚
- 新用户 24 小时内投票不计入热度

### 3.5 评论

- 两层结构：根评论按 hot_score(net_votes) 降序，回复按时间升序
- 删除为墓碑不级联
- 编辑显示已编辑标记

### 3.6 搜索

- 按名称只搜本服（FTS5 全文搜索，降级为 LIKE）
- 按 ID 走寻址
- 按标签搜服务器目录
- 搜索框旁显示当前范围

## 四、服务器卡片

卡片 JSON 字段：

| 字段 | 说明 |
|------|------|
| node_id | 服务器节点 ID |
| name | 名称（≤32 字符） |
| avatar_b64 | 头像 Base64（≤128×128、64KB） |
| tags | 标签（≤5 个、每个 ≤8 字符） |
| host | 主机地址 |
| tcp_port | TCP 端口 |
| dht_port | DHT 端口 |
| online_count | 在线人数 |
| max_online | 最大在线 |
| heat_level | 热度等级 |
| heat_reference | 热度参考值 |
| protocol_version | 协议版本 |
| software_version | 软件版本 |
| public_key | 服务器 Ed25519 公钥 |
| signature | 签名（覆盖除 signature 外所有字段） |
| updated_at | 更新时间 |
| hidden | 是否隐藏 |
| status | 状态 |

- 首次连接记 known_hosts，后续公钥变更拒绝并报警
- 注册页输入 host:port 后立即发 SERVER_INFO_REQUEST（无需认证），验证签名后显示卡片
- 默认名称 "Spider"，默认标签 ["安全的通信"]
- 服务器列表分"最近连接"和"局域网发现"两组
- 离线卡片灰显，超 30 天归档

## 五、在线人数与限流

### 5.1 在线人数

- 在线 = TCP 活跃 + 60 秒内心跳，UUID 去重
- 管理员不计入
- `load_ratio = online / max_online` 用于限流
- `heat = online / heat_reference` 用于显示

### 5.2 热度等级

| 等级 | 范围 | UI 文字 |
|------|------|---------|
| 绿 | [0, 0.25] | 活跃 |
| 黄 | (0.25, 0.5] | 中等 |
| 橙 | (0.5, 0.75] | 繁忙 |
| 红 | (0.75, 1.0] | 拥挤 |

- UI 只显示等级文字，默认显示精确数字
- 管理员可手动关闭精确数字显示以避免马太效应

### 5.3 限流阈值

| 级别 | 阈值 | 动作 |
|------|------|------|
| slow_messages | 0.5 | 消息减速 |
| slow_posting | 0.6 | 发帖减速 |
| block_search | 0.7 | 禁止搜索 |
| block_register | 0.75 | 禁止注册 |
| block_dht | 0.8 | 禁止 DHT |
| block_login | 0.9 | 禁止登录 |
| logout_users | 0.95 | 踢人 |
| block_all | 1.0 | 全部禁止 |

- hysteresis 0.05 防抖
- 优雅降级按序执行：先限流后禁功能最后踢人
- 管理员豁免
- 状态切换广播通知

## 六、身份跨服

- 身份本地生成不绑服务器
- 跨服登录时目标服通过 DHT 查 `user:` 键找到原服
- 原服用私钥签"UUID 存在"证明
- 作者资料页聚合多服数据

## 七、数据与协议

### 7.1 数据库表（forum.db）

- `posts` — 帖子
- `comments` — 评论
- `votes` — 投票
- `posts_fts` — FTS5 全文搜索
- `known_servers` — 已知服务器（目录联邦）
- `audit_log` — 审计日志
- `reports` — 举报
- `notifications` — 通知
- `drafts` — 草稿
- `user_preferences` — 用户偏好

所有时间用 Unix 秒。

### 7.2 协议常量分类

- `POST_` — 帖子相关
- `COMMENT_` — 评论相关
- `VOTE_` — 投票相关
- `SERVER_` — 服务器卡片/目录
- `LOAD_` — 负载与限流
- `CROSS_SERVER_` — 跨服寻址
- `NOTIFICATION_` — 通知
- `REPORT_` — 举报
- `DRAFT_` — 草稿
- `FORUM_PROFILE_` — 论坛用户资料

所有请求带 nonce+timestamp，服务端重放保护。
错误响应格式：`{"type":"ERROR","code":"...","message":"...","request_id":"..."}`

## 八、必要补充

### 8.1 管理员面板

- 审核队列
- 举报处理
- 目录管理
- 限流配置
- 审计日志
- 显示精确在线人数开关

### 8.2 用户侧

- 举报
- 屏蔽
- 草稿箱
- 个人资料页

### 8.3 反滥用

- 新用户冷却（24 小时内投票不计入热度）
- 重复检测
- 链接限制
- @ 提及限制

### 8.4 性能

- 游标分页
- 批量重算热度
- 跨服 5 秒超时
- 目录缓存 5 分钟

### 8.5 日志与审计

- 日志不记录帖子正文
- 审计日志滚动更新，默认 30 天
- 每日备份默认保留 30 天
- 所有管理员操作必须有审计

## 九、禁止事项

- 禁止帖子 E2EE
- 禁止"只有第一条评论生效"
- 禁止管理员不可开关"显示精确在线人数"
- 禁止无签名卡片
- 禁止跨服帖子无签名转发
- 禁止 ID 搜索失败广播
- 禁止一开始就踢人
- 禁止无迟滞抖动
- 禁止改已有协议常量
- 禁止省略警示语
- 禁止论坛阅后即焚
- 禁止日志记录正文
- 禁止无审计的管理员操作
- 禁止论坛流程要求 E2EE 密钥
- 禁止联邦同步帖子内容
- 禁止 ID 暴露服务器 IP
- 禁止错误响应含正文
- 禁止未验签显示跨服帖子
- 禁止未确认写 known_hosts

## 十、代码结构

```
server/forum/
├── __init__.py
├── database.py       # forum.db 初始化与连接
├── posts.py          # 帖子 CRUD、热度公式、搜索
├── comments.py       # 评论 CRUD、两层结构
├── votes.py          # 投票、改票回滚、新用户冷却
├── server_card.py    # 服务器卡片构建/验签/缓存
├── online.py         # 在线人数管理
├── rate_limit.py     # 分级限流、hysteresis
├── cross_server.py   # 跨服寻址、目录联邦
└── handler.py        # ForumHandler 消息处理器

client/gui/forum/
├── __init__.py
├── forum_client.py   # 论坛消息发送封装
└── forum_window.py   # 论坛主窗口 UI

minecraft/.../forum/
└── ForumTab.java     # Minecraft 论坛标签页

android/.../forum/
├── ForumFragment.kt  # Android 论坛 Fragment
└── PostAdapter.kt    # 帖子列表适配器
```

## 十一、测试

测试文件：`test_forum_integration.py`

覆盖：
- 单元测试：热度公式、投票回滚、评论两层结构、签名验证
- 集成测试：发帖→评论→投票→搜索全流程
- 回归测试：现有 E2EE、群组、文件、死人开关、胁迫 PIN 不受影响
- 协议兼容测试：新客户端连旧服务器不崩溃
- 压力测试：高并发发帖/评论/投票
- 安全测试：未认证访问、越权操作、签名伪造、重放攻击
