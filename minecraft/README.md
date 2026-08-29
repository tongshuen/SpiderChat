# SpiderMinecraft

Spider 官方通信网络在 Minecraft 世界中的投射。为 Minecraft 26.2 (混沌立方) + NeoForge 设计。

## 核心特性

### 客户端

- **游戏内 GUI** — 右上角 Spider 按钮一键打开图形界面，包含聊天、联系人、群组、登录、文件、设置六个标签页
- **CLI 命令保留** — `/spiderminecraft` 全套命令仍然完全可用，GUI 与 CLI 双入口
- **UUIDv1 + 真实 MAC 身份** — 永久固定身份，对齐 Spider 客户端，接入用户数据库和权限系统
- **Spider 标准协议信令** — REGISTER/LOGIN/SEND_MSG/RECV_MSG/DELIVERY_RECEIPT/READ_RECEIPT/COMPROMISED/OFFLINE_QUEUE，直连端口与 Spider 客户端结构完全一致
- **SQLite 持久化** — 消息/用户/离线队列/群组全部持久化，服务器重启不丢失
- **端到端加密 + 传输加密** — X25519 ECDH + AES-256-GCM + Ed25519 签名；TCP 全包加密 + 定期密钥轮换（PFS）
- **胁迫 PIN** — `/spiderminecraft duress <pin>` 触发 wipe_all_data() + COMPROMISED 信令
- **阅后即焚** — 按每个人单独开关（裁剪自 Spider 的三规则）
- **加密文件传输** — 存储在 saves/SpiderFiles/，对齐 Spider 的 encrypt_file_data
- **群组系统** — 替代原"房间"，持久化到 SQLite
- **纯新增代码** — 不修改任何 Minecraft 已有类

### 服务端

- **用户管理** — 注册/登录/在线追踪/封禁/解封/踢下线/删除用户
- **限速系统** — 令牌桶全局限速 + 用户级限速 + 突发容量 + 禁言（临时/永久）
- **管理员控制台** — 20+ 条管理员命令（LIST_ONLINE/BAN_USER/MUTE_USER/SET_RATE_LIMIT/BROADCAST_MSG/SHUTDOWN 等）
- **消息中继与离线存储** — 在线用户直接转发，离线用户存入离线队列
- **文件传输管理** — 最大文件大小限制、传输统计
- **跨服务器联邦** — 联邦服务器节点管理（基础）
- **DHT 节点发现** — 引导节点管理（基础）
- **隐藏模式与白名单** — 仅白名单节点可查询
- **运行统计** — 在线人数、总用户、中继消息数、传输文件数、运行时间

## GUI 使用说明

### 打开 GUI

进入游戏后，点击屏幕右上角的 **Spider** 按钮（带状态指示灯）即可打开图形界面。

- 🟢 绿色 = 已连接服务器
- 🟡 黄色 = 未登录
- 🔴 红色 = 未初始化

### GUI 标签页

| 标签页 | 功能 |
|--------|------|
| 聊天 | 查看和发送加密消息，支持滚动 |
| 联系人 | 搜索、添加、导入联系人 |
| 群组 | 创建、加入、查看群组 |
| 登录 | 服务器发现、连接/登录/注册 |
| 文件 | 发送文件、查看文件目录 |
| 设置 | 自动下载、已读回执、HUD按钮、数据管理 |

## 登录流程

### GUI 方式

1. 打开 Spider GUI → 切换到「登录」标签页
2. 点击「发现」按钮扫描局域网服务器
3. 从列表中选择服务器（或手动输入 host:port）
4. 输入密码，点击「连接/登录」
5. 首次注册时设置胁迫 PIN，点击「注册」

### CLI 方式

1. `/spiderminecraft login begin` — 检测局域网 Spider 服务端和 Minecraft 服务端
2. `/spiderminecraft login list` — 列出检测到的服务器
3. `/spiderminecraft login select <index|host:port>` — 选择服务器
4. `/spiderminecraft login password <password>` — 输入密码（首次注册时需设置胁迫 PIN）
5. `/spiderminecraft login duress <6位数字>` — 首次注册时设置胁迫 PIN

## 客户端命令

| 命令 | 说明 |
|------|------|
| `/spiderminecraft help` | 帮助 |
| `/spiderminecraft status` | 状态 |
| `/spiderminecraft login begin/list/select/password/duress` | 登录流程 |
| `/spiderminecraft logout` | 登出 |
| `/spiderminecraft duress <pin>` | 胁迫 PIN（触发擦除！） |
| `/spiderminecraft msg <uuid> <text>` | 发送加密消息 |
| `/spiderminecraft file send <path> <uuid>` | 发送加密文件 |
| `/spiderminecraft group create/join/list` | 群组管理 |
| `/spiderminecraft burn <uuid> <on\|off>` | 设置某人阅后即焚 |
| `/spiderminecraft key` | 显示本机密钥 |
| `/spiderminecraft discovery` | 切换服务发现 |

## 服务端管理员命令

在服务端控制台执行（需管理员权限）：

| 命令 | 说明 |
|------|------|
| `HELP` | 管理员命令帮助 |
| `LIST_ONLINE` | 在线用户列表 |
| `LIST_ALL_USERS` | 所有用户列表 |
| `LIST_BANNED` | 封禁用户列表 |
| `BAN_USER <uuid> [reason]` | 封禁用户 |
| `UNBAN_USER <uuid>` | 解封用户 |
| `KICK_USER <uuid>` | 踢用户下线 |
| `CREATE_USER <name>` | 创建用户 |
| `DELETE_USER <uuid>` | 删除用户 |
| `MUTE_USER <uuid> <seconds>` | 禁言（0=永久） |
| `UNMUTE_USER <uuid>` | 解除禁言 |
| `SET_RATE_LIMIT <rate>` | 全局限速（消息/秒） |
| `SET_USER_RATE <rate>` | 用户限速（消息/秒） |
| `SET_MAX_FILE_SIZE <mb>` | 最大文件大小（MB） |
| `BROADCAST_MSG <text>` | 广播通知 |
| `STATS` | 服务器统计 |
| `RELOAD_CONFIG` | 重载配置 |
| `SHUTDOWN` | 优雅关机 |
| `FORCE_SHUTDOWN` | 强制关机 |

## 构建

```bash
./gradlew build
```

产物：`build/libs/spiderminecraft-2.0.0.jar`

## 架构

```
SpiderMinecraftMod
├── 客户端
│   ├── gui/
│   │   ├── SpiderHudOverlay    — HUD 覆盖层（Spider按钮）
│   │   ├── SpiderMainScreen    — 主 GUI 界面（6标签页）
│   │   └── tabs/               — 聊天/联系人/群组/登录/文件/设置
│   ├── KeyManager              — UUIDv1+MAC, 密钥对, 胁迫PIN, wipe_all_data
│   ├── CryptoManager           — 消息 E2EE (X25519+AES-256-GCM+Ed25519)
│   ├── TransportEncryptor      — TCP 全包加密 + 密钥轮换 (PFS)
│   ├── DatabaseManager         — SQLite (messages/users/offline_queue/groups)
│   ├── SessionManager          — REGISTER/LOGIN 认证流程
│   ├── DirectConnector         — TCP 直连 (含传输加密)
│   ├── DiscoveryService        — UDP 多播服务发现 (LAN + MC 服务器)
│   ├── GroupManager            — 群组 (持久化)
│   ├── DuressManager           — 胁迫 PIN 触发擦除
│   ├── EphemeralEngine         — 阅后即焚 (每人开关)
│   └── FileTransfer            — 加密文件 (saves/SpiderFiles/)
└── 服务端
    └── server/
        ├── SpiderServerCore     — 服务端核心（中继/离线/联邦/统计）
        ├── AdminConsole         — 管理员命令控制台（20+命令）
        ├── ServerUserManager    — 用户管理（注册/封禁/踢人/在线追踪）
        └── RateLimiter          — 令牌桶限速（全局+用户级+禁言）
```

## 配置

客户端配置文件：`config/spiderminecraft-client.toml`

```toml
[discovery]
autoDiscovery = true
showDiscoveryNotifications = true
discoveryTimeoutSec = 5

[privacy]
readReceiptsEnabled = true
readReceipts = true

[gui]
autoDownload = true
showHudButton = true
```

服务端配置文件：`config/spiderminecraft-common.toml`

```toml
[network]
announceServer = true
enableCrypto = true
enableTransportEncryption = true
discoveryPort = 42999
directTcpPort = 42998
transportKeyRotationSec = 3600
```

## 许可

MIT License
