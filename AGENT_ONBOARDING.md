# SpiderChat / SpiderWallet — AI Agent 接手说明书

> 本文档供下一个 AI Agent 快速接手项目，无需向用户提问、无需翻找文件。
> 最后更新：2026-09-29。当前 SpiderChat HEAD = `4d3a6ef`（feat: 新增服务器随机数据包（诱饵包）对抗时序分析攻击），SpiderWallet HEAD = `caecf21`。

---

## 0. 30 秒速览

这是一个**端到端加密通信系统**，跨 4 个端：
- **Python 客户端**（GUI，customtkinter/tkinter）
- **Python 服务端**（TCP 中继 + DHT + 管理员）
- **Minecraft 模组**（Java，Forge 1.20.1）
- **Android 客户端**（Kotlin）
- 独立项目 **SpiderWallet**（Python，CTK/TK GUI，加密货币钱包）

加密底座：**Ed25519**（签名）+ **X25519**（ECDH）+ **AES-256-GCM**（加密）+ **HKDF/PBKDF2**（派生）。
消息走 JSON 行协议（TCP），传输层额外整包 AES-256-GCM 加密。

---

## 1. 仓库位置与 Git 信息

### SpiderChat（主仓库）
- **本地路径**：`/home/user/.super_doubao/super-doubao-runtime/workspace/spider_commit/repo`
- **GitHub**：https://github.com/tongshuen/SpiderChat
- **分支**：`main`
- **最新 commit**：`4d3a6ef` — "feat: 新增服务器随机数据包（诱饵包）对抗时序分析攻击"
- **Git remote URL（含 token，已配置在 origin）**：
  `https://github.com/tongshuen/SpiderChat.git`

### SpiderWallet（独立仓库）
- **本地路径**：`/home/user/.super_doubao/super-doubao-runtime/workspace/SpiderWallet`
- **GitHub**：https://github.com/tongshuen/SpiderWallet
- **分支**：`main`
- **最新 commit**：`caecf21` — "新增: 3 PIN系统 + 死人开关(只清数据) + /api/supported_chains"
- **协议**：MIT

### GitHub Token
- **Token**：仅存于本地 .git/config 与 shell 环境变量（GITHUB_TOKEN），不写入仓库，避免触发 GitHub secret scanning push protection
- **账号**：`tongshuen`，邮箱 `15730642468@163.com`
- **Scope**：`repo`（可读写）
- 推送前先 `cd` 到对应仓库目录，`git add` → `git commit` → `git push origin main`

---

## 2. 硬约束（违反会被用户打回，务必遵守）

1. **不修改 `shared/protocol.py` 已有常量**，只新增。
2. **不改 `shared/crypto_utils.py` 已有函数签名**，只能新增函数。
3. **不改 `TransportEncryptor` 线格式**（传输层包结构）。
4. **不改 `identity.json` 结构**（本地身份文件）。
5. **论坛数据独立 `forum.db`**，通过 UUID 关联 `users.db`。
6. **数据库迁移用 `CREATE TABLE IF NOT EXISTS`**，写独立回滚脚本。
7. **所有改动向后兼容**：新客户端连旧服务端不崩溃；旧客户端连新服务端不作要求。
8. **所有用户文案用中文**。
9. **不提交无关文件**：`PackUp.py`、`packed_archive.txt`、`__pycache__/`、`*.pyc`、`.idea/`、`.vscode/`、`build/` 临时文件都不提交 git。
10. **`releases/` 目录要提交 git**（编译成品独立目录，与源码分离）。
11. **打包交付用纯文本链接**，不要用卡片形式。
12. **Minecraft 论坛功能已移除**，不要恢复。服务端论坛模块保留。

---

## 3. 目录结构与每个文件的作用

### 3.1 根目录

| 文件 | 作用 |
|------|------|
| `README.md` | 项目主 README，功能介绍、架构、构建说明 |
| `CRYPTOGRAPHY_WHITEPAPER.md` | 密码学白皮书（算法选型、协议、安全模型） |
| `FORUM_DESIGN.md` | 论坛子系统完整设计文档（11节） |
| `LICENSE` | 开源协议 |
| `DISCLAIMERandEULA.txt` | 免责声明与最终用户许可协议 |
| `requirements.txt` | Python 依赖（核心仅标准库，customtkinter/SoapySDR 可选） |
| `PackUp.py` | 打包脚本（本地运行，不提交 git）。运行后生成 `packed_archive.txt` |
| `packed_archive.txt` | 打包产物（不提交 git） |
| `.gitignore` | Git 忽略规则 |
| `AGENT_ONBOARDING.md` | **本文档** |

### 3.2 `shared/` — 跨端共享层

| 文件 | 作用 |
|------|------|
| `__init__.py` | 包标识 |
| `protocol.py` (334行) | **所有协议常量**。消息类型字符串（REGISTER/LOGIN/SEND_MSG/...）、论坛常量（POST_/COMMENT_/VOTE_/SERVER_/LOAD_/CROSS_SERVER_/NOTIFICATION_/REPORT_/DRAFT_）、错误码。**只增不改已有**。 |
| `crypto_utils.py` (553行) | **核心加密工具库 v3**。Ed25519 签名/验签、X25519 ECDH（含临时密钥 PFS）、AES-256-GCM 加解密（强制 AAD）、HKDF 派生、PBKDF2 PIN 派生（20万次迭代）、传输层整包加解密、密钥轮换、重放保护、secure nonce。常量：`PBKDF2_ITERATIONS=200000`、`REPLAY_WINDOW_SEC=300`、AAD 域分隔符 `spider-msg-v1`/`spider-transport-v1` 等。 |
| `packet_obfuscation.py` | 包混淆（HTTP/1.1、DNS、TLS ClientHello、WebSocket 帧伪装） |

### 3.3 `server/` — Python 服务端

| 文件/目录 | 作用 |
|-----------|------|
| `main.py` (309行) | **服务端入口**。启动 DHT 节点、聊天 TCP 服务端、跨服中继、UDP 广播、P2P 节点。支持 headless 模式。 |
| `__init__.py` | 包标识 |
| `chat/server.py` | 核心聊天服务端：连接管理、消息路由、REGISTER/LOGIN/SEND_MSG 处理、在线/离线投递、回执分发 |
| `chat/group.py` | 群组管理：创建/加入/离开/成员管理、**group_key（AES-256-GCM）生成与密封分发**、群消息存储与分发 |
| `chat/offline.py` | 离线消息队列：存储、投递、清理 |
| `chat/relay.py` | 消息中继 |
| `chat/cross_server.py` | 跨服中继：服务器间 TCP 连接、RELAY_MSG、跨服 PKI Ed25519 握手、TOFU 公钥固定；另含随机数据包（诱饵包）：`_build_decoy_message` 构造与 RELAY_MSG 同构的外层信封、用对端 transport_key AES-256-GCM 密封内容层（dummy 标记在密文内）、`_decoy_loop` 按随机间隔选一台已认证 peer 发送；接收侧 `_is_decoy_relay` 用 transport_key 试解密、命中 dummy 即静默丢弃；`get_stats()` 含 decoy_sent/decoy_received 计数（详见 6.9） |
| `forum/` | **论坛子系统（10个文件）**，见 3.4 |
| `admin/auth.py` | 管理员认证（PIN 验证、会话管理） |
| `admin/commands.py` | 管理员命令处理（LIST_ONLINE/BAN/KICK/CREATE_USER/... 共40+命令） |
| `admin/stats.py` | 服务端统计信息 |
| `dht/node.py` | Kademlia DHT 节点：UDP PING/FIND_NODE/STORE/GET |
| `dht/routing.py` | DHT K-桶路由表，XOR 距离查找最近节点 |
| `dht/rpc.py` | DHT RPC 消息处理 |
| `dht/bootstrap.py` | DHT 引导节点加载（guide.txt）、初始 ping |
| `discovery/broadcast.py` | UDP 局域网广播发现服务器 |
| `file_manager/store.py` | 文件存储：大小限制、保留期清理、按用户检索 |
| `keyring_store/backend.py` | 密钥存储后端 |
| `keyring_store/credentials.py` | 管理员凭据加载 |
| `logs/logger.py` | 日志（不记录帖子正文/消息正文） |
| `p2p/node.py` | P2P 节点：入站/出站连接、消息中继 |
| `p2p/transport.py` | P2P 全包传输加密 |
| `rate_limit/token_bucket.py` | 全局限速令牌桶 |
| `storage/store.py` | 通用 SQLite 存储 |
| `user/manager.py` | 用户管理：注册/登录/创建（admin 创建用 uuid4，不用 MAC）、封禁/禁言 |
| `user/banlist.py` | 封禁列表 |
| `config/loader.py` | 配置加载（server_config.json、环境变量、数据目录）；DEFAULT_CONFIG 含 `decoy_enabled`(默认 false) / `decoy_min_interval_sec`(默认 30) / `decoy_max_interval_sec`(默认 300) 随机数据包字段（详见 6.9） |

### 3.4 `server/forum/` — 论坛子系统（10文件）

| 文件 | 作用 |
|------|------|
| `database.py` | forum.db 独立 SQLite，11张表（posts/votes/comments/posts_fts/known_servers/audit_log/reports/notifications/drafts/user_preferences），CREATE TABLE IF NOT EXISTS |
| `posts.py` | 帖子 CRUD、**热度公式** `log10(max(|net_votes|,1))*sign(net_votes) + 0.8*log10(max(distinct_commenters,1)) + post_ts/45000`、FTS5 搜索（不可用时降级 LIKE）、"为什么这个排名"分解、后台每5-10分钟重算 |
| `comments.py` | 评论：**任意深度树状存储**（parent_id）、扁平列表按热度排序返回、reply_to_username 显示、墓碑删除不级联、编辑标记、拒绝跨帖回复/悬挂回复 |
| `votes.py` | 投票 -1/0/1、每用户每对象一票、改票回滚旧票、新用户24小时冷却不计入热度 |
| `server_card.py` | 服务器卡片构建/验签、热度四级（绿黄橙红）、known_hosts TOFU、目录缓存5分钟 |
| `online.py` | 在线人数：TCP活跃+60秒心跳、UUID去重、管理员不计入 |
| `rate_limit.py` | 8级负载限流：slow_messages(0.5)→slow_posting(0.6)→block_search(0.7)→block_register(0.75)→block_dht(0.8)→block_login(0.9)→logout_users(0.95)→block_all(1.0)，hysteresis 0.05 |
| `cross_server.py` | 跨服寻址：本服前缀→known_servers缓存→DHT `server:` 键→失败明确错误（**禁止广播联邦回退**），5秒超时 |
| `handler.py` | ForumHandler：约40种论坛消息类型路由分发 |

### 3.5 `client/` — Python 客户端

| 文件/目录 | 作用 |
|-----------|------|
| `main.py` (18行) | 客户端入口 → 启动注册/解锁窗口 |
| `gui/register.py` | 注册/解锁窗口：首次注册 PIN/胁迫PIN/隐匿模式/P2P开关，已有身份 PIN 解锁 |
| `gui/main_window.py` | 主窗口：联系人列表、聊天区、输入框、发送/文件/Collection/设置/论坛按钮 |
| `gui/chat_panel.py` | 聊天面板：消息渲染、发送、已读回执（头尾曾出现即触发）、元数据悬停显示 |
| `gui/contact_list.py` | 联系人列表：搜索/备注/拉黑/删除/分享 |
| `gui/settings.py` | 设置窗口：颜色/自动下载/已读回执/死人开关/头像/昵称/群组/管理员/实验功能/HTTP API |
| `gui/admin_panel.py` | 管理员面板：40+管理员命令 |
| `gui/api_dialog.py` | HTTP API 管理：创建/删除 API Key、权限选择、有效期设置 |
| `gui/experimental_dialog.py` | 实验性功能开关：PIN验证+输入"打开实验性功能"+5秒冷却滑块 |
| `gui/outband_sign_window.py` | **带外签名工具**（实验性功能内）：账号所有权挑战签名/消息内容签名/校验 |
| `gui/forum/` | 论坛客户端：`forum_client.py`（消息发送封装）、`forum_window.py`（帖子列表/详情/发帖/评论/投票/搜索/服务器卡片） |
| `crypto/encrypt.py` | 消息加解密：临时X25519 ECDH→HKDF→AES-256-GCM，Ed25519签名，AAD绑定，±300秒时间窗口 |
| `crypto/exchange.py` | 密钥交换：ECDH会话密钥生成与缓存 |
| `crypto/keys.py` | 密钥管理：身份密钥加载/持久化 |
| `crypto/outband_sign.py` | **带外签名**：`sign_outband()`/`verify_outband()`，格式 `spider-sig:v1;uuid=...;timestamp=...;data_hash=...;sig=...`，域分离 `spider-outband-ownership`/`spider-outband-content` |
| `crypto_collection.py` | 加密货币卡片解析/渲染：Collection 格式，**冒号 `\:` 转义**，货币/网络/地址 Tab 补全 |
| `network/tcp_client.py` | TCP 客户端连接服务端 |
| `network/protocol.py` | 客户端协议消息构造 |
| `network/link.py` | 链路抽象：公网/直连/无线电三种传输回调注入，`_send_public`/`_send_direct` 真实传输 |
| `network/discovery.py` | UDP 局域网发现服务器/P2P对端 |
| `network/direct_connect.py` | P2P 直连 TCP 监听/连接 |
| `network/cross_server.py` | 客户端跨服寻址 |
| `network/radio/` | **无线电/SDR 模块**：见 3.6 |
| `security/deadman.py` | 死人开关：警告消息/收件人/宽限期，登录/编辑时同步到服务端，过期前推送警告再执行胁迫 |
| `security/ephemeral.py` | 前向保密临时密钥管理 |
| `security/vault.py` | 聊天记录加密保险库：PIN派生主密钥，每条消息独立AES-256-GCM加密 |
| `storage/identity.py` | 身份文件读写（identity.json） |
| `storage/messages.py` | 消息本地存储 |
| `storage/api_keys.py` | API Key 管理：128位hex key，哈希存储，掩码显示前8后4，权限累计警告（>1.5即15项权限时警告攻击面过宽） |
| `integration/spiderwallet.py` | SpiderWallet 联动：跳转前调用 `/api/supported_chains` 检查链支持 |
| `api/server.py` | HTTP API 服务：Flask/aiohttp，端口用户自定，细粒度权限，`/api/sign/outband` 和 `/api/sign/verify` |
| `experimental/manager.py` | 实验性功能管理器：总开关、无线电链路、SpiderWallet集成、HTTP API、带外签名 |
| `utils/uuidgen.py` | UUIDv1 生成：真实MAC绑定，**隐匿模式用 SHA-256(MAC)** 而非原始MAC，拒绝虚拟网卡/全零/广播MAC |
| `utils/config.py` | 客户端配置管理 |

### 3.6 `client/network/radio/` — 无线电/SDR

| 文件 | 作用 |
|------|------|
| `phy.py` | 物理层 Python 接口 |
| `phy_wrapper.py` | C 库 `libphy.so` 封装 |
| `sdr_interface.py` | SDR 后端抽象：V4L2/SoapySDR/DummyBackend |
| `fec.py` | FEC 纠错：Hamming(7,4)、比特重复编码、块交织 |
| `dht.py` | 无线电 DHT：频点路由表、gossip、网关管理 |
| `signature.py` | 无线电协议签名：前导码/导频音/同步字/相关检测 |
| `phy_lib.c` / `phy_lib.h` | C 物理层源码 |
| `Makefile` | 编译 `libphy.so`：`cd client/network/radio && make` |
| `libphy.so` | 预编译 C 库（已提交 releases/native/） |
| `HAMbandlist.json` | 业余频段表 |

### 3.7 `minecraft/` — Minecraft 模组（Java，Forge 1.20.1）

| 文件/目录 | 作用 |
|-----------|------|
| `build.gradle` / `settings.gradle` | Gradle 构建 |
| `README.md` / `WARNING.txt` | 模组说明 |
| `src/main/java/com/spider/minecraft/SpiderMinecraftMod.java` | Forge 模组主入口 |
| `SpiderMinecraft.java` | Spider 客户端核心初始化 |
| `crypto/CryptoManager.java` | 加密管理器 |
| `crypto/KeyManager.java` | 密钥管理 |
| `crypto/TransportEncryptor.java` | 传输层加密 |
| `protocol/Protocol.java` | 协议常量（镜像 shared/protocol.py） |
| `network/SpiderNetwork.java` | 网络层 |
| `network/SpiderPacket.java` | 网络包 |
| `network/SessionManager.java` | 会话管理 |
| `network/DirectConnector.java` | P2P 直连 |
| `network/DiscoveryService.java` | 局域网发现 |
| `gui/SpiderHudOverlay.java` | HUD 按钮（绿/黄/红状态灯） |
| `gui/SpiderMainScreen.java` | 主 GUI，6个Tab：聊天/联系人/群组/登录/文件/设置（**论坛Tab已移除**） |
| `gui/tabs/*.java` | 6个Tab实现 |
| `command/SpiderCommand.java` | CLI 命令 `/spiderminecraft ...` |
| `config/SpiderConfig.java` | 配置 |
| `event/ClientEventHandler.java` | 客户端事件处理 |
| `event/ServerEventHandler.java` | 服务端事件处理 |
| `group/GroupManager.java` | 群组管理 |
| `file/FileTransfer.java` | 文件传输 |
| `security/DuressManager.java` | 胁迫 PIN |
| `security/EphemeralEngine.java` | 临时密钥 |
| `server/SpiderServerCore.java` | 服务端核心 |
| `server/AdminConsole.java` | 管理员控制台 |
| `server/RateLimiter.java` | 限速 |
| `server/ServerUserManager.java` | 用户管理 |
| `storage/DatabaseManager.java` | SQLite 数据库 |
| `storage/MessageStore.java` | 消息存储 |
| `storage/OfflineStore.java` | 离线存储 |
| `util/JsonUtil.java` | JSON 工具（getString/getInt 安全取值） |
| `util/NetUtil.java` | 网络工具 |
| `uuid/UuidGenerator.java` | UUID 生成 |
| `resources/` | mod 元数据、语言文件、pack.mcmeta |

### 3.8 `android/` — Android 客户端（Kotlin）

| 文件/目录 | 作用 |
|-----------|------|
| `build.gradle.kts` / `settings.gradle.kts` | Gradle 构建 |
| `app/build.gradle.kts` | App 模块配置 |
| `app/proguard-rules.pro` | ProGuard 混淆规则 |
| `app/src/main/AndroidManifest.xml` | 清单文件 |
| `SpiderApp.kt` | Application 入口，初始化 BouncyCastle 和全局单例 |
| `crypto/CryptoManager.kt` | 加密管理器（BouncyCastle Ed25519/X25519/AES-GCM） |
| `crypto/KeyManager.kt` | 密钥管理 |
| `crypto/OutbandSign.kt` | **带外签名**（与 Python 互通） |
| `network/Protocol.kt` | 协议常量 |
| `network/SpiderClient.kt` | TCP 客户端 |
| `storage/DatabaseHelper.kt` | SQLite 帮助类 |
| `storage/IdentityStore.kt` | 身份存储 |
| `storage/MessageStore.kt` | 消息存储 |
| `storage/ContactStore.kt` | 联系人存储 |
| `session/SessionManager.kt` | 会话管理 |
| `security/DuressManager.kt` | 胁迫 PIN |
| `security/DeadmanManager.kt` | 死人开关 |
| `file/FileTransferManager.kt` | 文件传输 |
| `location/LocationHelper.kt` | 定位：经纬度 DMS、不确定度 r=xxx′/″、定位时间 |
| `model/Contact.kt` / `Message.kt` | 数据模型 |
| `ui/login/LoginActivity.kt` | 登录/注册界面，PIN 输入（maxLength=16，digits=0123456789） |
| `ui/main/MainActivity.kt` | 主界面，底部导航：聊天/联系人/论坛/设置 |
| `ui/main/ChatFragment.kt` | 聊天界面 |
| `ui/main/ContactsFragment.kt` | 联系人界面 |
| `ui/main/MessageAdapter.kt` / `ContactAdapter.kt` | 列表适配器 |
| `ui/settings/SettingsActivity.kt` | 设置界面（含签名工具入口） |
| `ui/sign/OutbandSignActivity.kt` | **带外签名页面** |
| `forum/ForumFragment.kt` | 论坛界面 |
| `forum/PostAdapter.kt` | 帖子列表适配器 |
| `res/layout/` | 所有 XML 布局 |
| `res/values/` | 颜色/字符串/主题 |
| `res/drawable/` | 图标和背景 |
| `res/menu/bottom_nav.xml` | 底部导航菜单 |
| `res/mipmap-*/ic_launcher.png` | 应用图标（蜘蛛网） |

### 3.9 `assets/`
- `default_avatar.png` — 默认蜘蛛网头像
- `logo.png` — 项目 logo

### 3.10 `data/`（运行时数据，不提交 git 或 .gitignore）
- `users.db` — 用户数据库
- `groups.db` — 群组数据库
- `offline_messages.db` — 离线消息
- `guide.txt` — DHT 引导节点
- `server_config.json` — 服务端配置
- `icon.png` — 图标

### 3.11 `releases/`（编译成品，**提交 git**）
- `native/libphy.so` — C 物理层库
- `android/` — Android APK（环境限制暂未构建，见 README）
- `minecraft/` — Minecraft JAR（环境限制暂未构建，见 README）
- `README.md` — 构建说明

### 3.12 测试文件（根目录）

| 文件 | 作用 |
|------|------|
| `test_integration.py` | 整合测试：加密/传输/链路/文件群组等全链路 |
| `test_forum_integration.py` | 论坛集成测试（36个用例）：热度公式/投票回滚/评论树/服务器卡片/限流/跨服寻址/协议常量/数据库迁移/回归/安全 |
| `test_outband_sign.py` | 带外签名测试（24个用例）：生成/校验/篡改/跨端/域分离 |
| `test_client_features.py` | 客户端功能测试（358个用例）：身份/PIN/加密/GUI/网络/安全/API |
| `test_server_features.py` | 服务端功能测试（20个用例）：核心/管理员/DHT |
| `test_radio_features.py` | 无线电功能测试：FEC/物理层/SDR/频段/DHT |
| `test_crypto_collection.py` | 加密货币卡片解析测试（冒号转义） |
| `test_decoy.py` | 随机数据包（诱饵包）功能测试：开关/发送上下限/对端静默丢弃/向后兼容/decoy_sent 与 decoy_received 统计计数 |

---

## 4. SpiderWallet 仓库结构

路径：`/home/user/.super_doubao/super-doubao-runtime/workspace/SpiderWallet`

| 文件 | 作用 |
|------|------|
| `main.py` | 钱包入口 |
| `wallet/core.py` | 钱包核心：地址生成、余额查询、交易构造 |
| `wallet/chains.py` | 内置链实现（BTC/ETH/LTC等），用户可自定义配置 |
| `wallet/pin.py` | **3 PIN 系统**：解锁PIN/胁迫PIN/反向PIN，PBKDF2-HMAC-SHA256+独立salt，8/10/12/16位，禁回文，胁迫PIN位置约束 |
| `wallet/deadman.py` | **死人开关**：只清空本地数据（随机覆写后删除），**不发警告消息** |
| `wallet/storage.py` | 钱包存储（加密 SQLite） |
| `wallet/api_server.py` | 本地 HTTP API：`/api/supported_chains` 返回已支持链列表 |
| `wallet/api_client.py` | 与 SpiderChat 联动的 API 客户端 |
| `gui/main_window.py` | CTK GUI |
| `gui/tk_fallback.py` | tkinter 降级 |
| `README.md` | 钱包说明 |
| `LICENSE` | MIT |
| `DISCLAIMER.md` / `EULA.md` | 免责/许可 |
| `PackUp.py` | 打包脚本（不提交 git） |

---

## 5. 如何运行 / 测试 / 构建 / 打包

### 5.1 运行 Python 客户端
```bash
cd /home/user/.super_doubao/super-doubao-runtime/workspace/spider_commit/repo
pip install cryptography customtkinter  # 可选依赖
python -m client.main
```

### 5.2 运行 Python 服务端
```bash
cd /home/user/.super_doubao/super-doubao-runtime/workspace/spider_commit/repo
python -m server.main
# headless: 无显示器时自动用 stdin/环境变量
```

### 5.3 运行全部测试
```bash
cd /home/user/.super_doubao/super-doubao-runtime/workspace/spider_commit/repo
python test_integration.py
python test_forum_integration.py
python test_outband_sign.py
python test_client_features.py
python test_server_features.py
python test_radio_features.py
python test_crypto_collection.py
python test_decoy.py
# 编译检查
python -m py_compile $(find . -name "*.py" -not -path "./.git/*")
```

### 5.4 编译 C 库
```bash
cd client/network/radio && make
# 产物: libphy.so → 复制到 releases/native/
```

### 5.5 构建 Android APK（需要 JDK 17 + Android SDK）
```bash
cd android
./gradlew assembleDebug
# 产物: app/build/outputs/apk/debug/app-debug.apk → 复制到 releases/android/
```

### 5.6 构建 Minecraft JAR（需要 JDK 17）
```bash
cd minecraft
./gradlew build
# 产物: build/libs/spiderminecraft-2.0.0.jar → 复制到 releases/minecraft/
```

### 5.7 打包交付
```bash
cd /home/user/.super_doubao/super-doubao-runtime/workspace/spider_commit/repo
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null
find . -name "*.pyc" -delete 2>/dev/null
python3 PackUp.py
# 产物: packed_archive.txt
# 用 FileBatchUpload 上传后把链接给用户（纯文本链接，不要卡片）
```

### 5.8 提交 Git
```bash
cd /home/user/.super_doubao/super-doubao-runtime/workspace/spider_commit/repo
git add -A
git status --short  # 确认没有 PackUp.py / packed_archive.txt / __pycache__
git commit -m "描述改动"
git push origin main
```

---

## 6. 核心架构要点

### 6.1 加密体系
- **身份密钥**：Ed25519 签名密钥对 + X25519 密钥交换密钥对，存在 `identity.json`，AES-256-GCM 加密存储，PIN 通过 PBKDF2(20万次) 派生密钥
- **消息加密**：每条消息临时 X25519 密钥对 → ECDH → HKDF → AES-256-GCM，AAD 绑定 UUID+时间戳+协议版本，Ed25519 签名
- **传输加密**：TransportEncryptor 整包 AES-256-GCM，临时 X25519 握手，每小时或每1000包轮换
- **群消息**：群组共享 group_key（AES-256-GCM），成员加入时 ECDH+HKDF 分发
- **带外签名**：`spider-sig:v1;uuid=...;timestamp=...;data_hash=...;sig=...`，域分离防重放

### 6.2 消息协议
- JSON 行协议（每条消息一行 JSON，TCP）
- 所有请求带 nonce + timestamp，服务端重放保护（±300秒窗口）
- 错误响应：`{"type":"ERROR","code":"...","message":"...","request_id":"..."}`
- 回执系统：SEND_OK → DELIVERY_RECEIPT → READ_RECEIPT（或 READ_RECEIPT_DISABLED）

### 6.3 PIN 系统
- 解锁 PIN / 胁迫 PIN / 反向 PIN（倒序输入解锁PIN触发胁迫）
- 8/10/12/16 位纯数字
- 拒绝回文 PIN
- 胁迫 PIN 不能等于解锁 PIN 或其倒序
- 解锁PIN倒序 < 解锁PIN → 胁迫PIN > 解锁PIN；反之亦然
- PBKDF2-HMAC-SHA256 + 独立 salt，恒定时间比对

### 6.4 死人开关
- 客户端每次编辑警告消息/收件人/登录时，把最新警告消息发给服务端
- 服务端作为特殊离线消息存储，替换旧的
- 到期用户未登录 → 先推送警告消息给预定收件人 → 再执行胁迫密码同款操作
- 警告消息附加位置元数据（DMS 经纬度 + r=不确定度 + 时间戳）

### 6.5 论坛热度公式
```
hot_score = log10(max(|net_votes|, 1)) * sign(net_votes)
          + 0.8 * log10(max(distinct_commenters, 1))
          + post_timestamp / 45000
```
sign(0)=0 显式处理。后台每5-10分钟重算。新用户24小时内投票不计入。

### 6.6 评论系统
- 任意深度树状（parent_id 级联）
- 扁平显示，按热度排序
- 每条显示"回复 @xxx"标识
- 删除为墓碑不级联
- 编辑显示"已编辑"标记

### 6.7 分级限流
- load_ratio = online / max_online
- 8级：0.5→0.6→0.7→0.75→0.8→0.9→0.95→1.0
- hysteresis 0.05 防抖
- 管理员豁免
- 状态切换广播通知

### 6.8 跨服寻址
- 帖子 ID 格式：`{node_id}:{64hex}`
- 解析：本服前缀本地查 → known_servers 缓存 → DHT `server:` 键 → 失败返回明确错误
- **禁止广播整个联邦作为回退**
- 超时 5 秒

### 6.9 随机数据包（诱饵包）功能

- **用途**：对抗洋葱网络的时序分析攻击。服务器管理员可选启用；启用后，服务器每隔随机时间间隔从已认证跨服 peer 集合中随机选**一台**发送一个诱饵包（非广播），使无密钥观察者无法从包时序/形状上区分真实聊天包与噪声包。
- **涉及文件**：
  - `shared/protocol.py`：常量 `DECOY_MSG`（保留的旧消息类型，仍有静默丢弃处理器用于混版本兼容）、管理员命令常量 `CMD_SET_DECOY`（旧）/ `CMD_DECOY_ON` / `CMD_DECOY_OFF` / `CMD_DECOY_STATUS`。
  - `server/config/loader.py`：`DEFAULT_CONFIG` 新增 `decoy_enabled` / `decoy_min_interval_sec` / `decoy_max_interval_sec`。
  - `server/chat/cross_server.py`：`_build_decoy_message()` 构造与 `RELAY_MSG` 逐字段同构的外层信封；`_decoy_loop()` 按随机间隔选一台已认证 peer 发送；`_is_decoy_relay()` + `_decrypt_with_transport_key()` 在接收侧识别并静默丢弃；`decoy_status()` 供管理员查询；`get_stats()` 输出 decoy_sent/decoy_received 等。
  - `server/admin/commands.py`：管理员命令 `DECOY_ON` / `DECOY_OFF` / `DECOY_STATUS`（另保留旧 `SET_DECOY`）。
  - `server/main.py`：服务端启动时按 `decoy_enabled` 配置拉起诱饵发送定时器。
  - `test_decoy.py`：功能测试（见 3.12）。
- **配置字段**（`server_config.json` / `DEFAULT_CONFIG`，均可选）：`decoy_enabled`（bool，默认 `false`）、`decoy_min_interval_sec`（默认 30 秒）、`decoy_max_interval_sec`（默认 300 秒），需满足 `0 < min < max`。
- **管理员命令**：
  - `DECOY_ON`：开启；可选参数 `interval_min` / `interval_max`（秒，缺省取配置值）。返回当前 `decoy_status()`。
  - `DECOY_OFF`：关闭，停止发送线程。
  - `DECOY_STATUS`：返回 `{enabled, interval_min, interval_max, last_sent_time, sent_count, received_count, known_peers}`。
  - 旧 `SET_DECOY (enabled) [min_interval] [max_interval]` 仍可用，行为等价。
- **安全设计要点**：
  - **外层信封同构**：诱饵包直接使用 `type=RELAY_MSG`，外层 `from_uuid`/`to_uuid`/`signature`/`source_server`/`timestamp` 与内层 `encrypted_payload` 字典的键集（version/from_uuid/to_uuid/timestamp/nonce/ciphertext/tag/aad/signature/ephemeral_pub/fs_used）与真实中继消息完全对齐；UUID、签名、ephemeral_pub 取等长随机值消除长度侧信道。
  - **内容层 transport_key AES-256-GCM 密封**：诱饵明文（`{"dummy": true, "nonce", "payload"(随机 16~1024 字节), "ts"}`）用对端握手派生的 interserver transport_key（HKDF info=`spider-interserver-transport`）密封；dummy 标记只在 GCM 密文内部。AAD 与真实消息同形（`{from,to,ts,proto:"spider/2.0"}` 排序 JSON），域分隔标签 `spider-random-packet-v1`。
  - **接收侧静默丢弃**：新对端收到 `RELAY_MSG` 后先用 transport_key 试解密；真实中继内容是客户端 E2EE 密封、不经 transport_key，GCM 认证必失败走正常流程。解密成功且带 `dummy` 即计数后直接 return——不落库、不转发、不投递、不触发限速/业务、不回执、不打日志（避免日志侧信道）。
  - **随机时间 + 随机对端**：发送间隔在 `[min, max]` 上均匀随机，对端从已认证 peer 集合中 `random.choice` 单选；集合为空则跳过本轮。
  - **无密钥不可区分**：观察者没有 interserver transport_key，无法区分真实中继包与诱饵包（同构信封 + 密文外形 + 随机 nonce/载荷 + 随机间隔/对端）。

---

## 7. 当前状态（2026-09-29）

### 已完成
- [x] 四端 E2EE 通信（Python/Android/Minecraft/服务端）
- [x] 群组 E2EE（group_key）
- [x] 文件传输（分块加密）
- [x] 死人开关（服务端定时检测+警告推送+胁迫执行）
- [x] 胁迫 PIN / 反向 PIN / 3 PIN 系统
- [x] 隐匿模式（MAC→SHA-256→UUID node）
- [x] 经纬度 DMS 格式 + r=不确定度
- [x] HTTP API（细粒度权限、API Key 管理）
- [x] 实验性功能开关（PIN验证+滑块冷却）
- [x] SpiderWallet 集成（/api/supported_chains 链支持检查）
- [x] 无线电 SDR 链路（FEC/物理层/DHT mesh）
- [x] 论坛子系统（帖子/评论/投票/服务器卡片/限流/跨服寻址）
- [x] 带外签名（Python + Android，跨端互通）
- [x] 加密货币卡片（Collection 格式 + 冒号转义 + SW 跳转）
- [x] 服务器随机数据包（诱饵包）：RELAY_MSG 同构信封 + transport_key AES-256-GCM 密封 + dummy 密文标记 + 随机间隔/随机对端 + 接收侧静默丢弃；管理员命令 DECOY_ON/OFF/STATUS；配置 decoy_enabled（默认关）/decoy_min/max_interval_sec（默认 30/300）
- [x] 全量测试 0 失败 0 错误

### 已知环境限制
- **Android APK 未编译**：当前环境无 JDK 17 / Android SDK / Gradle，代码已就绪但未产出 APK。构建命令见 `releases/README.md`。
- **Minecraft JAR 未编译**：同上，无 JDK 17。
- **C 库 libphy.so 已预编译**，在 `releases/native/` 和 `client/network/radio/` 中。

### 待办/可扩展方向
- 多语言（目前全中文）
- Android/Minecraft 编译环境搭建
- 更多内置链支持（SpiderWallet）
- 预言机法币估值（SpiderWallet）

---

## 8. 功能清单测试基线

完整功能清单（约990项）在：
`/home/user/.doubao/agent_mode/workspace/.sessions/38439386987206402/attachments/Spider 功能列表.txt`

14大类：身份密钥PIN / 加密消息传输 / 客户端GUI / 网络DHT P2P / 安全隐私 / HTTP API / 服务端核心 / 管理员命令 / DHT跨服P2P / 论坛子系统 / Android / Minecraft / 无线电SDR / 测试构建。

上次全量验证结果：**全部通过，0失败0错误**（2026-09-29，含 test_decoy.py）。

---

## 9. 其他 Agent 接手时的操作清单

1. **确认当前状态**：`cd` 到仓库，`git log --oneline -5` 看最新 commit，`git status` 看是否有未提交改动。
2. **不要重新探索**：本文档已说明所有文件用途，直接改代码即可。
3. **改完先测试**：运行相关测试文件（`python test_xxx.py`），必须 0 失败。
4. **提交前清理**：`find . -name "__pycache__" -type d -exec rm -rf {} +`，确认 `git status` 无无关文件。
5. **推送**：`git push origin main`（token 已在 remote URL 中）。
6. **打包**：`python3 PackUp.py` → 上传 `packed_archive.txt` → 给用户纯文本链接。
7. **遇到问题**：先看本文档第6节架构要点和第2节硬约束，不要违反。
8. **SpiderWallet**：独立仓库，路径见第4节，改动后单独提交和打包。
