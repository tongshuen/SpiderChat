SPIDER 端到端加密聊天系统

项目简介
--------
Spider 是一个专注于安全与隐私的端到端加密聊天系统。它采用去中心化架构，结合中心化服务器与点对点（P2P）直连两种模式，为用户提供灵活、可靠且高度安全的通信体验。无论是局域网内快速交谈，还是跨公网全球通信，Spider 都能在保护您隐私的前提下，提供清晰、即时、丰富的消息服务。

Spider 的核心理念是“安全默认，隐私至上”。所有消息、文件传输、群聊内容均经过 AES-256-GCM 加密，身份验证采用 Ed25519 签名，密钥交换使用 X25519 椭圆曲线 Diffie-Hellman，并支持临时密钥（Ephemeral）以实现前向保密（Perfect Forward Secrecy）。此外，Spider 集成了传输层包混淆（HTTP/DNS/TLS/WebSocket 伪装）、可选洋葱路由（多跳匿名中继）、以及胁迫 PIN 等高级安全功能，使其在对抗流量分析、中间人攻击、物理胁迫等场景下具备极强防护能力。

Spider 由客户端（Client）和服务端（Server）两部分组成，同时共享一套加密协议与工具库。客户端提供图形界面（基于 customtkinter，回退至 tkinter），服务端则作为消息中继、离线存储、用户管理与 DHT 网络节点运行。客户端之间也可通过 P2P 直连模块（Direct Connect）在无需服务器的情况下通信，支持蓝牙、WiFi Direct、局域网及公网 IP 直连。

主要特性
--------
1. 端到端加密（E2EE）
   - 每条消息使用独立的临时 X25519 密钥对进行 ECDH 协商，派生 AES-256-GCM 会话密钥。
   - 加密信封包含 AAD（附加认证数据），绑定发送者、接收者、时间戳及协议版本，防止重放与篡改。
   - Ed25519 签名确保消息来源真实性，防止身份冒充。

2. 前向保密与密钥轮换
   - 每条消息或文件传输均可使用一次性临时密钥，即使长期身份密钥泄露，历史消息仍无法解密。
   - 传输层密钥支持定期轮换（默认每小时），进一步降低长期密钥泄露风险。

3. 多模式通信
   - 服务器中继模式：客户端连接中央服务器，实现用户注册、登录、在线状态、离线消息存储、跨服务器转发。
   - P2P 直连模式：支持蓝牙、WiFi Direct、局域网广播发现、公网 IP 直连，不依赖任何中心节点。
   - 混合模式：可同时启用服务器与 P2P，根据网络条件自动选择最佳路径。

4. 跨服务器联邦
   - 通过 DHT（Kademlia）网络发现其他 Spider 服务器，自动建立跨服务器 TCP 中继通道。
   - 用户可在不同服务器之间互发消息、创建联邦群组，实现全球分布式聊天网络。
   - 跨服务器通信采用 PKI 认证（Ed25519）与 TOFU（首次信任）引脚机制，防止中间人攻击。

5. 群聊功能
   - 支持创建本地群组和联邦群组（跨服务器成员）。
   - 群消息加密后分发，每个成员使用自身密钥解密，服务器无法读取明文。
   - 群主可管理成员、提升管理员、删除群组。

6. 文件传输
   - 文件同样经过端到端加密（AES-256-GCM），支持断点续传（通过分片）。
   - 服务器可配置最大文件大小（默认 100MB）和保留期限（默认 7 天），自动清理过期文件。
   - 客户端支持自动下载（可配置）和手动保存。

7. 安全增强特性
   - 胁迫 PIN（Duress PIN）：当用户被胁迫时，输入胁迫 PIN 会触发本地数据自动销毁并通知服务器标记账户为已泄露。
   - 重放攻击防护：服务端和 DHT 节点均缓存近期 nonce，拒绝重复消息。
   - 包混淆：将加密流量伪装成 HTTP、DNS、TLS 或 WebSocket 流量，规避深度包检测。
   - 洋葱路由：可选多跳中继，隐藏通信双方真实 IP 地址。

8. 用户友好界面
   - 主窗口包含联系人列表、聊天区域、消息输入框，支持颜色主题自定义。
   - 消息状态实时显示（发送中、已送达、已读）。
   - 联系人搜索、备注名编辑、拉黑/解拉黑、聊天记录检索与删除。
   - 设置界面可调整颜色、自动下载、已读回执开关、个人资料（显示名称、头像）。

9. 管理员功能
   - 通过 6 位 PIN 认证，获得管理权限。
   - 可查看在线用户、所有用户；封禁/解封/踢下线用户；创建/删除用户。
   - 动态调整全局限速、用户限速、突发容量；禁言用户。
   - 管理文件传输参数（大小、保留期、开关）。
   - 控制 DHT 隐藏模式与白名单；查看路由表；添加引导节点。
   - 查看日志、连接统计、广播通知、优雅关机/强制关机、重载配置。
   - 修改管理员 PIN、重置 TOFU 引脚。

10. 跨平台支持
    - 客户端：Windows（使用 customtkinter）、macOS、Linux（X11/Wayland）。
    - 服务端：可运行于任意 Python 环境，包括无显示器（headless）服务器（通过环境变量配置）。
    - 依赖库精简，核心功能仅需 cryptography、keyring、PyBluez（可选蓝牙）。

系统架构
--------
Spider 整体分为三个主要部分：

1. 共享模块（shared/）
   - protocol.py：定义所有消息类型常量、默认端口、安全参数。
   - crypto_utils.py：提供 Ed25519/X25519 密钥生成、签名验证、ECDH、HKDF、AES-GCM 加解密、PBKDF2 PIN 派生、传输层加密（TransportEncryptor）、重放缓存等核心函数。
   - packet_obfuscation.py：实现五种包混淆模式及洋葱路由（OnionRouter）类。

2. 客户端（client/）
   - gui/：图形界面各窗口（主窗口、注册/解锁、设置、管理员面板等），使用 customtkinter，回退至 tkinter。
   - network/：TCP 客户端（tcp_client.py）、UDP 局域网发现（discovery.py）、跨服务器辅助（cross_server.py）、P2P 直连管理（direct_connect.py）。
   - crypto/：消息加解密（encrypt.py）、会话密钥管理（exchange.py）、密钥生成与存储（keys.py）。
   - storage/：身份文件读写（identity.py）、SQLite 消息存储（messages.py）、联系人管理。
   - utils/：配置管理（config.py）、UUIDv1 生成（强制绑定真实 MAC 地址）。
   - main.py：客户端入口，启动注册窗口。

3. 服务端（server/）
   - chat/：TCP 服务端（server.py）、消息中继（relay.py）、离线存储（offline.py）、群组管理（group.py）、跨服务器中继（cross_server.py）。
   - dht/：Kademlia DHT 节点（node.py）、路由表（routing.py）、RPC 处理（rpc.py）、引导加载（bootstrap.py）。
   - user/：用户管理（manager.py）、封禁列表（banlist.py）。
   - admin/：管理员认证（auth.py）、命令处理器（commands.py）、统计收集（stats.py）。
   - keyring_store/：基于 keyring 的凭证存储（支持系统钥匙链与 cryptfile 后备）。
   - discovery/：UDP 局域网广播（broadcast.py）。
   - p2p/：P2P 节点（node.py）与传输层封装（transport.py）。
   - rate_limit/：令牌桶限速器（token_bucket.py）。
   - file_manager/：文件存储与清理（store.py）。
   - config/：配置加载器（loader.py）。
   - logs/：日志工具（logger.py）。
   - main.py：服务端入口，启动所有组件。

安装与运行
----------
1. 环境要求：Python 3.8+，建议使用虚拟环境。
2. 安装依赖：
   pip install -r requirements.txt
   若需蓝牙支持（Linux/Windows），请安装 PyBluez；若在无显示器服务器运行，建议安装 keyrings.cryptfile。
3. 首次运行服务端：
   - 编辑 data/server_config.json 配置端口、限速、文件参数等（若无，服务端会自动生成默认配置）。
   - 若需加入 DHT 网络，编辑 data/guide.txt，每行填写一个引导节点（host:port）。
   - 执行 python -m server.main。若无 keyring 后端，程序会提示设置管理员 PIN（有显示器则弹窗，无显示器则从环境变量 SPIDER_ADMIN_PIN 读取）。
   - 管理员 PIN 为 6 位数字，用于登录管理面板。
4. 首次运行客户端：
   - 执行 python -m client.main。
   - 若未发现身份文件，将进入注册界面，需输入服务器地址、端口、6 位解锁 PIN 和 6 位胁迫 PIN（可不同），以及显示名称。
   - 注册成功后自动登录，进入主界面。
5. 添加联系人：
   - 在主界面搜索框中输入对方 UUID 或显示名称，可选择局域网或全局搜索（通过服务器）。
   - 或直接通过对方分享的联系人 JSON 文件导入。
6. 发送消息/文件：
   - 点击联系人，在底部输入框输入消息，按回车或点击“发送”。
   - 点击“📁”按钮选择文件，发送后对方可下载（自动或手动）。

配置说明
--------
- 客户端配置：~/.local/share/spider/settings.json（Linux）或对应平台数据目录下的 settings.json。
  可调整颜色、自动下载、已读回执开关、默认搜索范围等。
- 服务端配置：data/server_config.json，包括所有端口、限速、文件、DHT、日志、安全等参数。
- 引导节点：data/guide.txt，每行一个 host:port，用于 DHT 引导。
- 管理员 PIN 和服务器密钥存储在系统钥匙链（或 cryptfile 加密文件）中，不存于配置文件。

管理员命令（部分常用）
----------------------
- 查看在线用户：LIST_ONLINE
- 查看所有用户：LIST_ALL_USERS
- 封禁用户：BAN_USER (uuid)
- 解封用户：UNBAN_USER (uuid)
- 创建用户：CREATE_USER (name)
- 设置全局限速：SET_RATE_LIMIT (seconds)
- 设置最大文件：SET_MAX_FILE_SIZE (mb)
- 广播通知：BROADCAST_MSG (text)
- 优雅关机：SHUTDOWN
- 重置 TOFU 引脚：RESET_TOFU（清除所有跨服务器信任记录）

详细命令列表请参考 server/admin/commands.py 中的 ADMIN_COMMANDS。

安全注意事项
------------
- 务必使用强 PIN（6 位数字），解锁 PIN 与胁迫 PIN 不可相同。
- 服务端可以启用隐藏模式（hidden_mode）并配置白名单，仅允许已知节点查询。
- 定期备份用户数据库（users.db）和消息数据库（messages.db），但加密密钥仅存于 keyring，备份不含私钥。
- 若怀疑服务器被入侵，可通过管理员命令 RESET_TOFU 清除所有引脚，并重新建立信任关系。
- 客户端私钥仅存在于本地，且经过 PIN 加密，切勿泄露 identity.json 文件。

开发与贡献
----------
Spider 采用模块化设计，各组件松耦合，便于扩展。欢迎开发者提交 PR 或报告 Issue。
- 代码风格：遵循 PEP 8，使用 f-string、类型注解（部分）。
- 测试：目前无自动化测试套件，不过可以古法手动验证。
- 未来计划：支持更多混淆模式、优化 P2P NAT 穿透、增加语音/视频通话、移动端适配等，不过大概率泡汤。
- 如果你要fork我的仓库，建议不要动关于通信的部分，否则容易出现客户端与服务端，或者服务端与服务端不兼容，无法加入网络。除非你能保证兼容性，或者仅在内部使用。

许可证
------
Spider 采用 MIT 许可证，详情请参阅许可证文件。本项目仅供学习与合法用途，使用者需自行承担相关责任（详细免责声明请参阅免责声明文件）。
