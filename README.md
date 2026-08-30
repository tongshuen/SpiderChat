# Spider

## 项目简介

Spider 是一个专注于安全与隐私的端到端加密通信系统，支持**互联网、局域网、P2P 直连、业余无线电（SDR）**以及 **Minecraft 游戏内**等多种通信渠道。它采用去中心化架构，结合去中心化服务器中继与点对点直连两种模式，为用户提供灵活、可靠且高度安全的通信体验。

Spider 的核心理念是"安全默认，隐私至上"。所有消息、文件传输、群聊内容均经过 **AES-256-GCM** 加密，身份验证采用 **Ed25519** 签名，密钥交换使用 **X25519** 椭圆曲线 Diffie-Hellman，并支持临时密钥（Ephemeral）以实现前向保密（PFS）。此外，Spider 集成了传输层包混淆（HTTP/DNS/TLS/WebSocket 伪装）、可选洋葱路由（多跳匿名中继）、胁迫 PIN 以及无线电链路 FEC 纠错等高级安全功能。

Spider 由以下部分组成，共享同一套加密协议与工具库：

- **Python 客户端** — 图形界面（基于 customtkinter，回退至 tkinter），支持 TCP/UDP/P2P/无线电多链路
- **Python 服务端** — 消息中继、离线存储、用户管理、DHT 网络节点、限速与管理员控制台
- **无线电模块** — 基于 SDR 的业余无线电通信链路，含 C 语言加速的物理层与 FEC 纠错
- **Minecraft 模组** — 游戏内 GUI + CLI 双入口，完整的客户端与服务端功能

## 主要特性

### 1. 端到端加密（E2EE）

- 每条消息使用独立的临时 X25519 密钥对进行 ECDH 协商，派生 AES-256-GCM 会话密钥。
- 加密信封包含 AAD（附加认证数据），绑定发送者、接收者、时间戳及协议版本，防止重放与篡改。
- Ed25519 签名确保消息来源真实性，防止身份冒充。

### 2. 前向保密与密钥轮换

- 每条消息或文件传输均可使用一次性临时密钥，即使长期身份密钥泄露，历史消息仍无法解密。
- 传输层密钥支持定期轮换（默认每小时），进一步降低长期密钥泄露风险。

### 3. 多模式通信

- **服务器中继模式**：客户端连接去中心化服务器，实现用户注册、登录、在线状态、离线消息存储、跨服务器转发。
- **P2P 直连模式**：支持蓝牙、WiFi Direct、局域网广播发现、公网 IP 直连，不依赖任何中心节点。
- **无线电模式**：通过 SDR 设备在业余无线电频段进行脱网通信，支持 FEC 纠错与自动频段检测。
- **混合模式**：可同时启用多种链路，根据网络条件自动选择最佳路径（公网 / 无线电 Mesh 桥接）。

### 4. 业余无线电通信（SDR）

- **多后端 SDR 抽象**：自动检测可用 SDR 硬件，无硬件时使用 DummyBackend 便于开发测试。
- **C 语言加速物理层**：`phy_lib.c` 实现调制/解调，编译为 `libphy.so`，Python 通过 `phy_wrapper.py` 调用。
- **前向纠错（FEC）**：Hamming 码 + 重复码 + 交织，提升弱信号下的通信可靠性。
- **协议签名**：每帧携带签名头，防止干扰与非法帧注入。
- **HAM 频段列表**：内置业余无线电频段表，自动校验频率合法性，越界时发出警告。
- **链路层整合**：`link.py` 提供 `public()`（公网）和 `radio_mesh()`（无线电 Mesh）两种链路模式，可在 GUI 设置中切换。
- **无线电 DHT**：`radio/dht.py` 实现无线电网络中的节点发现与路由。

### 5. 跨服务器联邦

- 通过 DHT（Kademlia）网络发现其他 Spider 服务器，自动建立跨服务器 TCP 中继通道。
- 用户可在不同服务器甚至在 Minecraft 客户端之间互发消息、创建联邦群组，实现全球分布式聊天网络。
- 跨服务器通信采用 PKI 认证（Ed25519）与 TOFU（首次信任）引脚机制，防止中间人攻击。

### 6. 群聊功能

- 支持创建本地群组和联邦群组（跨服务器成员）。
- 群消息加密后分发，每个成员使用自身密钥解密，服务器无法读取明文。
- 群主可管理成员、提升管理员、删除群组。

### 7. 文件传输

- 文件同样经过端到端加密（AES-256-GCM），支持断点续传（通过分片）。
- 服务器可配置最大文件大小（默认 100MB）和保留期限（默认 7 天），自动清理过期文件。
- 客户端支持自动下载（可配置）和手动保存。

### 8. 安全增强特性

- **胁迫 PIN（Duress PIN）**：当用户被胁迫时，输入胁迫 PIN 会触发本地数据自动销毁并通知服务器标记账户为已泄露。
- **死人开关（Dead Man's Switch）**：用户长期未登录时，服务器自动将预设警告消息发送给指定收件人，再执行胁迫操作。警告消息在登录、编辑时自动同步到服务器，哪怕客户端损坏也能按时发送。
- **重放攻击防护**：服务端和 DHT 节点均缓存近期 nonce，拒绝重复消息。
- **包混淆**：将加密流量伪装成 HTTP、DNS、TLS 或 WebSocket 流量，规避深度包检测。
- **洋葱路由**：可选多跳中继，隐藏通信双方真实 IP 地址。

### 9. 用户友好界面

- 主窗口包含联系人列表、聊天区域、消息输入框，支持颜色主题自定义。
- 消息状态实时显示（发送中、已送达、已读）。
- 联系人搜索、备注名编辑、拉黑/解拉黑、聊天记录检索与删除。
- 设置界面可调整颜色、自动下载、已读回执开关、个人资料（显示名称、头像）、无线电链路配置。
- Minecraft 客户端提供游戏内 GUI + CLI 双入口，支持加密聊天、群组、文件传输、胁迫 PIN、阅后即焚等核心功能。

### 10. 管理员功能

- 通过 6 位 PIN 认证，获得管理权限。
- 可查看在线用户、所有用户；封禁/解封/踢下线用户；创建/删除用户。
- 动态调整全局限速、用户限速、突发容量；禁言用户。
- 管理文件传输参数（大小、保留期、开关）。
- 控制 DHT 隐藏模式与白名单；查看路由表；添加引导节点。
- 查看日志、连接统计、广播通知、优雅关机/强制关机、重载配置。
- 修改管理员 PIN、重置 TOFU 引脚。

### 11. 跨平台支持

- **Python 客户端**：Windows（使用 customtkinter）、macOS、Linux（X11/Wayland）。
- **Python 服务端**：可运行于任意 Python 环境，包括无显示器（headless）服务器（通过环境变量配置）。
- **Minecraft 模组**：Minecraft 26.2 + NeoForge，客户端与服务端均支持。
- **Android 客户端**：Android 8.0+，Kotlin 编写，支持加密聊天、文件传输、胁迫 PIN、死人开关。
- **无线电模块**：Linux（推荐），需 SDR 硬件（如 RTL-SDR、HackRF 等）或使用 DummyBackend 开发。
- 核心功能仅需 `cryptography`、`keyring`；无线电需 `numpy`、SDR 驱动库；蓝牙需 `PyBluez`（可选）。

## 系统架构

### 1. 共享模块（`shared/`）

- `protocol.py`：定义所有消息类型常量、默认端口、安全参数。
- `crypto_utils.py`：提供 Ed25519/X25519 密钥生成、签名验证、ECDH、HKDF、AES-GCM 加解密、PBKDF2 PIN 派生、传输层加密（TransportEncryptor）、重放缓存等核心函数。
- `packet_obfuscation.py`：实现五种包混淆模式及洋葱路由（OnionRouter）类。

### 2. Python 客户端（`client/`）

- `gui/`：图形界面各窗口（主窗口、注册/解锁、设置、管理员面板等），使用 customtkinter，回退至 tkinter。设置界面集成无线电配置校验（`validate_radio_config`）与链路模式切换。
- `network/`：
  - `tcp_client.py`：TCP 客户端
  - `discovery.py`：UDP 局域网发现
  - `cross_server.py`：跨服务器辅助
  - `direct_connect.py`：P2P 直连管理（蓝牙 / WiFi Direct / 局域网 / 公网）
  - `link.py`：链路层抽象，支持 `public()`（公网）与 `radio_mesh()`（无线电 Mesh）两种模式，自动桥接
  - `protocol.py`：客户端协议常量
  - `HAMbandlist.json`：业余无线电频段表
  - `radio/`：无线电子模块（见下文）
- `crypto/`：消息加解密、会话密钥管理、密钥生成与存储。
- `storage/`：身份文件读写、SQLite 消息存储、联系人管理。
- `utils/`：配置管理、UUIDv1 生成（强制绑定真实 MAC 地址）。
- `main.py`：客户端入口，启动注册窗口。

#### 无线电子模块（`client/network/radio/`）

- `phy_lib.c` / `phy_lib.h`：C 语言物理层实现（调制/解调），通过 `Makefile` 编译
- `libphy.so` / `phy_lib.o`：编译产物（已预编译，便于直接使用）
- `phy_wrapper.py`：Python 对 C 物理层库的封装
- `phy.py`：Python 物理层（纯 Python 回退实现）
- `fec.py`：前向纠错（Hamming 码 + 重复码 + 交织）
- `signature.py`：协议帧签名与校验
- `sdr_interface.py`：SDR 硬件抽象层，自动检测后端，无硬件时使用 DummyBackend
- `dht.py`：无线电网络 DHT 节点发现与路由

### 3. Python 服务端（`server/`）

- `chat/`：TCP 服务端、消息中继、离线存储、群组管理、跨服务器中继。
- `dht/`：Kademlia DHT 节点、路由表、RPC 处理、引导加载。
- `user/`：用户管理、封禁列表。
- `admin/`：管理员认证、命令处理器、统计收集。
- `keyring_store/`：基于 keyring 的凭证存储（支持系统钥匙链与 cryptfile 后备）。
- `discovery/`：UDP 局域网广播。
- `p2p/`：P2P 节点与传输层封装。
- `rate_limit/`：令牌桶限速器。
- `file_manager/`：文件存储与清理。
- `config/`：配置加载器。
- `logs/`：日志工具。
- `main.py`：服务端入口，启动所有组件。

### 4. Minecraft 模组（`minecraft/`）

在 Minecraft 中使用完整功能的 Spider！为 Minecraft 26.2 + NeoForge 设计的模组。

**客户端特性：**
- 游戏内 GUI — 右上角 Spider 按钮一键打开图形界面（聊天/联系人/群组/登录/文件/设置六标签页）
- CLI 命令保留 — `/spiderminecraft` 全套命令仍然完全可用
- 端到端加密 + 传输加密（X25519 + AES-256-GCM + Ed25519）
- 胁迫 PIN、阅后即焚、加密文件传输、群组系统
- UUIDv1+MAC 身份，SQLite 持久化

**服务端特性：**
- 用户管理（注册/登录/封禁/踢人/在线追踪）
- 令牌桶限速（全局+用户级+禁言）
- 管理员控制台（20+ 条命令）
- 消息中继与离线存储
- 跨服务器联邦、DHT 节点发现（基础）
- 隐藏模式与白名单

详见 [`minecraft/README.md`](minecraft/README.md)。

## 安装与运行

### 1. 环境要求

- Python 3.8+，建议使用虚拟环境
- Minecraft 模组需 JDK 21+（用于构建）
- 无线电功能需 Linux + SDR 硬件（可选，无硬件时使用 DummyBackend）

### 2. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

可选依赖：
- 蓝牙支持（Linux/Windows）：`pip install PyBluez`
- 无显示器服务器：`pip install keyrings.cryptfile`
- 无线电功能：`pip install numpy`，并安装对应 SDR 驱动（如 `librtlsdr-dev`）

### 3. 编译无线电物理层（可选）

无线电模块已预编译 `libphy.so`，如需重新编译：

```bash
cd client/network/radio
make
```

要求：GCC + Python3 开发头文件。编译产物为 `libphy.so`，Python 会自动加载。

### 4. 首次运行服务端

- 编辑 `data/server_config.json` 配置端口、限速、文件参数等（若无，服务端会自动生成默认配置）。
- 若需加入 DHT 网络，编辑 `data/guide.txt`，每行填写一个引导节点（`host:port`）。
- 执行 `python -m server.main`。若无 keyring 后端，程序会提示设置管理员 PIN（有显示器则弹窗，无显示器则从环境变量 `SPIDER_ADMIN_PIN` 读取）。
- 管理员 PIN 为 6 位数字，用于登录管理面板。

### 5. 首次运行客户端

- 执行 `python -m client.main`。
- 若未发现身份文件，将进入注册界面，需输入服务器地址、端口、6 位解锁 PIN 和 6 位胁迫 PIN（可不同），以及显示名称。
- 注册成功后自动登录，进入主界面。
- 如需使用无线电通信，在设置中切换链路模式为 `radio_mesh`，并配置频率、调制方式等参数。

### 6. 构建 Minecraft 模组

```bash
cd minecraft
./gradlew build
```

产物：`build/libs/spiderminecraft-2.0.0.jar`，放入 Minecraft 模组目录即可。

### 7. 添加联系人

- 在主界面搜索框中输入对方 UUID 或显示名称，可选择局域网或全局搜索（通过服务器）。
- 或直接通过对方分享的联系人 JSON 文件导入。

### 8. 发送消息/文件

- 点击联系人，在底部输入框输入消息，按回车或点击"发送"。
- 点击"📁"按钮选择文件，发送后对方可下载（自动或手动）。

## 配置说明

- **客户端配置**：`~/.local/share/spider/settings.json`（Linux）或对应平台数据目录下的 `settings.json`。可调整颜色、自动下载、已读回执开关、默认搜索范围、无线电链路配置等。
- **服务端配置**：`data/server_config.json`，包括所有端口、限速、文件、DHT、日志、安全等参数。
- **引导节点**：`data/guide.txt`，每行一个 `host:port`，用于 DHT 引导。
- **Minecraft 客户端配置**：`config/spiderminecraft-client.toml`（HUD 按钮、自动下载、已读回执等）。
- **Minecraft 服务端配置**：`config/spiderminecraft-common.toml`（端口、加密、广播等）。
- 管理员 PIN 和服务器密钥存储在系统钥匙链（或 cryptfile 加密文件）中，不存于配置文件。

## 管理员命令（部分常用）

| 命令 | 说明 |
|------|------|
| `LIST_ONLINE` | 查看在线用户 |
| `LIST_ALL_USERS` | 查看所有用户 |
| `BAN_USER (uuid)` | 封禁用户 |
| `UNBAN_USER (uuid)` | 解封用户 |
| `KICK_USER (uuid)` | 踢用户下线 |
| `CREATE_USER (name)` | 创建用户 |
| `MUTE_USER (uuid) (seconds)` | 禁言用户（0=永久） |
| `SET_RATE_LIMIT (rate)` | 设置全局限速（消息/秒） |
| `SET_MAX_FILE_SIZE (mb)` | 设置最大文件大小 |
| `BROADCAST_MSG (text)` | 广播通知 |
| `SHUTDOWN` | 优雅关机 |
| `FORCE_SHUTDOWN` | 强制关机 |
| `RELOAD_CONFIG` | 重载配置 |
| `STATS` | 查看服务器统计 |
| `RESET_TOFU` | 重置 TOFU 引脚（清除所有跨服务器信任记录） |

详细命令列表请参考 `server/admin/commands.py` 中的 `ADMIN_COMMANDS`。Minecraft 服务端管理员命令详见 `minecraft/README.md`。

## 测试

运行整合测试套件（验证无线电模块 + 链路层 + GUI 钩子）：

```bash
python test_integration.py
```

测试覆盖：FEC 纠错、协议签名、SDR 抽象层、物理层、链路层互通、HAM 频段校验、GUI 无线电配置校验、链路模式切换。

## 安全注意事项

- 务必使用强 PIN（6 位数字），解锁 PIN 与胁迫 PIN 不可相同。
- 服务端可以启用隐藏模式（`hidden_mode`）并配置白名单，仅允许已知节点查询。
- 定期备份用户数据库（`users.db`）和消息数据库（`messages.db`），但加密密钥仅存于 keyring，备份不含私钥。
- 若怀疑服务器被入侵，可通过管理员命令 `RESET_TOFU` 清除所有引脚，并重新建立信任关系。
- 客户端私钥仅存在于本地，且经过 PIN 加密，切勿泄露 `identity.json` 文件。
- 无线电通信需遵守当地业余无线电法规，仅在合法频段内操作。

## 开发与贡献

Spider 采用模块化设计，各组件松耦合，便于扩展。欢迎开发者提交 PR 或报告 Issue。

- **代码风格**：Python 遵循 PEP 8，使用 f-string、类型注解；Minecraft 模组遵循 Java 标准编码规范。
- **测试**：整合测试位于 `test_integration.py`，覆盖无线电模块与链路层核心功能。
- **未来计划**：支持更多 SDR 硬件后端、优化无线电 Mesh 路由、语音通话、移动端适配等。
- 如果你要 fork 本仓库，建议不要修改通信协议相关部分，否则容易出现客户端与服务端、或服务端与服务端不兼容，无法加入网络。除非你能保证兼容性，或仅在内部使用。

## 许可证

Spider 采用 MIT 许可证，详情请参阅 `LICENSE` 文件。本项目仅供学习与合法用途，使用者需自行承担相关责任（详细免责声明请参阅 `DISCLAIMERandEULA.txt`）。
