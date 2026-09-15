# SpiderChat 编译成品目录

本目录存放各平台编译后的成品文件，与源码分离。

## 目录结构

```
releases/
├── native/          # C 语言物理层共享库
│   └── libphy.so    # Linux x86_64 无线电物理层（make 编译）
├── android/         # Android APK（需 Android SDK 34 + JDK 17 + Gradle 编译）
└── minecraft/       # Minecraft 模组 JAR（需 JDK 17 + Gradle 8.10 + NeoForge MDK 编译）
```

## 各平台构建说明

### native（已构建）
- 文件：`libphy.so`（Linux x86_64）
- 构建命令：`cd client/network/radio && make clean && make`
- 依赖：gcc、libm
- 功能：5 种调制解调（FSK/ASK/PSK/QAM/GMSK）、SDR 抽象层、自动信道协商、信道质量估计

### android（待构建）
- 目标：`app-debug.apk` / `app-release.apk`
- 构建命令：`cd android && ./gradlew assembleDebug assembleRelease`
- 环境要求：JDK 17+、Android SDK 34、Gradle 8.x
- 当前环境因仅有 JRE 11 且无 Android SDK，未能在此构建

### minecraft（待构建）
- 目标：`spiderminecraft-2.0.0.jar`
- 构建命令：`cd minecraft && ./gradlew build`
- 环境要求：JDK 17+、Gradle 8.10、NeoForge MDK
- 当前环境因仅有 JRE 11 且无 Gradle，未能在此构建
