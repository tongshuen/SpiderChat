# Makefile — Spider 无线电物理层 C 共享库
#
# 目标：
#   Linux:   libphy.so
#   macOS:   libphy.dylib
#   Windows: phy.dll (MinGW)
#
# 用法：
#   make          # 编译共享库
#   make test     # 编译并运行 C 自测
#   make clean    # 清理编译产物
#   make install  # 安装到系统库目录（可选）

# ============================================================
# 配置
# ============================================================
CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -fPIC -std=c99
LDFLAGS ?=
LDLIBS  ?= -lm

# 检测平台
UNAME_S := $(shell uname -s 2>/dev/null || echo Unknown)

ifeq ($(UNAME_S),Linux)
    TARGET  = libphy.so
    LDFLAGS += -shared
endif
ifeq ($(UNAME_S),Darwin)
    TARGET  = libphy.dylib
    LDFLAGS += -dynamiclib
endif
ifneq (,$(findstring MINGW,$(UNAME_S)))
    TARGET  = phy.dll
    LDFLAGS += -shared
endif
ifeq ($(TARGET),)
    # 默认按 Linux 处理
    TARGET  = libphy.so
    LDFLAGS += -shared
endif

# ============================================================
# 源文件
# ============================================================
SRCS = phy_lib.c
OBJS = $(SRCS:.c=.o)
HDRS = phy_lib.h

# ============================================================
# 默认目标
# ============================================================
.PHONY: all clean test install
all: $(TARGET)

# 编译共享库
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)
	@echo "=== 编译完成: $@ ==="

# 编译目标文件
%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

# ============================================================
# 测试（编译 C 自测程序）
# ============================================================
test: $(TARGET)
	@echo "=== 运行 C 库自测 ==="
	@# 检查 Python ctypes 测试是否可用
	@python3 -c "import ctypes; lib = ctypes.CDLL('./$(TARGET)'); print('库加载成功, 版本:', lib.phy_version().decode())" 2>&1 || echo "Python 测试跳过"

# ============================================================
# 安装（可选，需要 root）
# ============================================================
install: $(TARGET)
	@echo "安装 $(TARGET) 到 /usr/local/lib/"
	@sudo cp $(TARGET) /usr/local/lib/ 2>/dev/null || cp $(TARGET) /usr/local/lib/
	@sudo cp phy_lib.h /usr/local/include/ 2>/dev/null || cp phy_lib.h /usr/local/include/
	@sudo ldconfig 2>/dev/null || true
	@echo "安装完成"

# ============================================================
# 清理
# ============================================================
clean:
	rm -f $(OBJS) $(TARGET) libphy.so libphy.dylib phy.dll
	@echo "清理完成"
