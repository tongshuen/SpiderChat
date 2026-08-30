# Spider Android

Spider 端到端加密通信系统的 Android 客户端。

## 功能特性

### 核心通信
- **端到端加密** — X25519 ECDH 密钥协商 + AES-256-GCM 消息加密 + Ed25519 签名
- **TCP 客户端** — 连接 Spider Python 服务端，JSON 行协议
- **用户注册/登录** — UUIDv1 身份（Android ID 作为 MAC 替代），PIN 派生密钥加密存储
- **加密聊天** — 一对一加密消息，消息本地 SQLite 持久化
- **联系人管理** — 添加/搜索联系人，自动查询公钥
- **文件传输** — 加密文件传输（AES-256-GCM 加密，通过服务器中继，最大 10MB）

### 安全功能
- **胁迫 PIN（Duress PIN）** — 输入胁迫 PIN 触发本地数据擦除 + 发送 COMPROMISED 信令
- **死人开关（Dead Man's Switch）** — 长期未登录时自动发送警告消息给预定收件人
  - 登录时自动同步警告消息到服务器
  - 编辑警告消息/收件人时自动同步
  - 服务器端存储为特殊离线消息，到期先推送警告再执行胁迫操作
  - 哪怕客户端炸了，警告消息也能按时发送
- **私钥加密存储** — PIN 派生 AES-256-GCM 密钥加密私钥
- **前向保密** — 每条消息使用临时 X25519 密钥对

### UI
- **登录/注册界面** — 服务器配置、PIN、胁迫 PIN、显示名称
- **主界面** — 底部导航（聊天/联系人/设置）
- **聊天界面** — 消息列表、输入框、文件附件按钮、发送按钮
- **联系人界面** — 联系人列表、搜索、添加
- **设置界面** — 死人开关配置、胁迫 PIN 修改、通用设置

## 技术栈

- **语言**: Kotlin
- **最低 SDK**: Android 8.0 (API 26)
- **目标 SDK**: Android 14 (API 34)
- **加密**: BouncyCastle (X25519/Ed25519) + javax.crypto (AES-GCM/PBKDF2)
- **UI**: Material Components + ViewBinding
- **存储**: SQLite (SQLiteOpenHelper)
- **架构**: MVVM-ish，全局单例 (Application) 管理核心组件

## 项目结构

```
SpiderAndroid/
├── app/
│   ├── build.gradle.kts
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/spider/android/
│       │   ├── SpiderApp.kt              # Application 入口，全局单例
│       │   ├── crypto/
│       │   │   ├── KeyManager.kt         # X25519/Ed25519 密钥生成、PIN 派生
│       │   │   └── CryptoManager.kt      # 消息加密/解密/签名
│       │   ├── network/
│       │   │   ├── Protocol.kt            # 协议常量（与 Python 服务端对齐）
│       │   │   └── SpiderClient.kt       # TCP 客户端，消息收发
│       │   ├── storage/
│       │   │   ├── DatabaseHelper.kt      # SQLite 数据库
│       │   │   ├── MessageStore.kt        # 消息存储
│       │   │   ├── ContactStore.kt        # 联系人存储
│       │   │   └── IdentityStore.kt       # 身份存储（私钥加密）
│       │   ├── session/
│       │   │   └── SessionManager.kt      # 注册/登录/认证流程
│       │   ├── security/
│       │   │   ├── DuressManager.kt       # 胁迫 PIN 管理
│       │   │   └── DeadmanManager.kt      # 死人开关管理
│       │   ├── file/
│       │   │   └── FileTransferManager.kt # 加密文件传输（发送/接收/保存）
│       │   ├── model/
│       │   │   ├── Message.kt             # 消息数据模型
│       │   │   └── Contact.kt             # 联系人数据模型
│       │   └── ui/
│       │       ├── login/LoginActivity.kt
│       │       ├── main/
│       │       │   ├── MainActivity.kt
│       │       │   ├── ChatFragment.kt
│       │       │   ├── ContactsFragment.kt
│       │       │   ├── MessageAdapter.kt
│       │       │   └── ContactAdapter.kt
│       │       └── settings/SettingsActivity.kt
│       └── res/
│           ├── layout/                    # 布局文件
│           ├── values/                    # 字符串/颜色/主题
│           ├── drawable/                  # 图标资源
│           └── mipmap-*/                  # 启动图标（mdpi~xxxhdpi 五密度）
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
└── README.md
```

## 构建

```bash
# 使用 Gradle Wrapper（首次需生成）
gradle wrapper

# 构建 Debug APK
./gradlew assembleDebug

# 构建 Release APK
./gradlew assembleRelease
```

产物位于 `app/build/outputs/apk/`。

## 死人开关工作流程

1. **配置**: 在设置界面启用死人开关，填写警告消息、收件人 UUID、宽限期（天）
2. **同步**: 保存设置时自动将警告消息发送到服务器（`STORE_DEADMAN_MSG`）
3. **登录同步**: 每次登录成功后自动同步最新警告消息到服务器
4. **服务器存储**: 服务器将警告消息作为特殊离线消息存储，覆盖旧的，不推送给其他用户
5. **触发**: 服务器维护循环每 60 秒检测，用户超过宽限期未登录时：
   - 先将警告消息推送给预定收件人（在线直接发，离线存为离线消息）
   - 再执行胁迫操作（标记泄露+封禁+断开连接）
6. **防重复**: 触发后标记 `triggered=1`，防止重复触发

## 与 Python 服务端的兼容性

本 Android 客户端与 Spider Python 服务端使用相同的协议：
- 消息类型常量对齐（`SEND_MSG`/`RECV_MSG`/`LOGIN`/`REGISTER`/`COMPROMISED`/`STORE_DEADMAN_MSG` 等）
- JSON 行协议（每行一条 JSON 消息）
- 加密算法对齐（X25519 + AES-256-GCM + Ed25519）

## 注意事项

- 本版本为审查版，部分功能（群组聊天、语音通话）尚未实现
- 死人开关功能需要服务端支持 `STORE_DEADMAN_MSG` 协议（Spider 服务端 v2.0+）
- 首次使用需注册新身份，无法导入 Python 客户端的身份文件
- 胁迫 PIN 触发后本地数据将被不可逆擦除，请谨慎设置

## 许可证

MIT License
