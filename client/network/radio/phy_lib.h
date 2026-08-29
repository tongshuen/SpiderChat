/*
 * phy_lib.h — Spider 无线电物理层 C 共享库公共 API
 *
 * 本库将全部物理层处理下沉到 C 实现，包括：
 *   - 5 种调制/解调：FSK / ASK / PSK / QAM / GMSK
 *   - SDR 硬件抽象层（V4L2 / SoapySDR / 虚拟环回）
 *   - 自动信道协商（根据 SNR 从候选集选最快可用参数）
 *   - 信道质量估计（SNR / 频偏）
 *
 * Python 端仅通过 ctypes 调用本 API，不含任何调制/解调逻辑。
 * 若库加载失败或 SDR 打开失败，调用方必须抛出运行时异常，绝不降级。
 *
 * 线程安全：每个 PhyContext 独立，不同上下文可并行使用；
 *           同一上下文的调用应由调用方串行化。
 */
#ifndef PHY_LIB_H
#define PHY_LIB_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* ============================================================
 * 常量定义
 * ============================================================ */

/* 调制类型 */
#define PHY_MOD_FSK   0   /* 频移键控（2FSK / MFSK） */
#define PHY_MOD_ASK   1   /* 幅移键控（2ASK / MASK） */
#define PHY_MOD_PSK   2   /* 相移键控（BPSK / QPSK） */
#define PHY_MOD_QAM   3   /* 正交幅度调制（16QAM / 64QAM） */
#define PHY_MOD_GMSK  4   /* 高斯滤波最小频移键控 */

/* SDR 后端 */
#define PHY_SDR_AUTO     0   /* 自动探测（V4L2 -> SoapySDR -> 虚拟） */
#define PHY_SDR_V4L2     1   /* Linux V4L2（rtl-sdr / hackrf 经 /dev/videoX） */
#define PHY_SDR_SOAPY    2   /* SoapySDR 跨平台 */
#define PHY_SDR_VIRTUAL  3   /* 虚拟环回（仿真测试用，TX->RX 环回） */

/* 错误码（负值表示错误） */
#define PHY_OK                0
#define PHY_ERR_INVALID_PARAM  -1   /* 参数非法（如带宽超限、调制类型未知） */
#define PHY_ERR_SDR_OPEN       -2   /* SDR 设备打开失败 */
#define PHY_ERR_SDR_READ       -3   /* SDR 读取失败 */
#define PHY_ERR_SDR_WRITE      -4   /* SDR 写入失败 */
#define PHY_ERR_NO_SIGNAL      -5   /* 未检测到有效信号 */
#define PHY_ERR_BANDWIDTH      -6   /* 占用带宽超过 12.5 kHz 限制 */
#define PHY_ERR_BUFFER_TOO_SMALL -7  /* 输出缓冲区不足 */
#define PHY_ERR_TIMEOUT        -8   /* 接收超时 */
#define PHY_ERR_INTERNAL       -99  /* 内部错误 */

/* 带宽限制（Hz）：业余频段窄带信道，必须 ≤ 12.5 kHz */
#define PHY_MAX_BANDWIDTH_HZ  12500

/* 默认采样率 */
#define PHY_DEFAULT_SAMPLE_RATE  8000

/* FEC 类型 */
#define PHY_FEC_NONE      0   /* 无 FEC */
#define PHY_FEC_HAMMING74 1   /* Hamming(7,4) */
#define PHY_FEC_HAMMING_REPEAT2 2  /* Hamming(7,4) + 比特重复×2 */

/* ============================================================
 * 数据结构
 * ============================================================ */

/**
 * PhyParams — 手动模式物理层参数。
 * 所有字段均需显式设置；未使用的调制类型字段填 0。
 */
typedef struct {
    int   modulation;        /* PHY_MOD_* */
    int   baud;              /* 符号率（波特），>0 */
    int   sample_rate;       /* 采样率（Hz），默认 8000 */

    /* --- FSK 参数 --- */
    float fsk_dev0;          /* 逻辑 0 频偏（Hz，相对中心频率） */
    float fsk_dev1;          /* 逻辑 1 频偏（Hz，相对中心频率） */

    /* --- ASK 参数 --- */
    int   ask_levels;        /* 幅度电平数（2=2ASK, 4=4ASK, ...） */
    float ask_amp_high;      /* 最高幅度（0..1） */
    float ask_amp_low;       /* 最低幅度（0..1，通常 0） */

    /* --- PSK 参数 --- */
    float psk_phase0;        /* 逻辑 0 相位（度） */
    float psk_phase1;        /* 逻辑 1 相位（度，BPSK 通常 180） */

    /* --- QAM 参数 --- */
    int   qam_order;         /* 星座阶数（16 / 64 / 256） */
    float qam_rolloff;       /* 升余弦滚降系数（0..1） */

    /* --- GMSK 参数 --- */
    float gmsk_bt;           /* 带宽-时间积 BT（通常 0.3 / 0.5） */

    /* --- FEC 参数 --- */
    int   fec_type;          /* PHY_FEC_* */

    /* --- 带宽约束 --- */
    int   bandwidth_hz;      /* 占用带宽上限（Hz），必须 ≤ 12500；
                                 实际带宽超限时 phy_set_params 返回错误 */
} PhyParams;

/**
 * AutoNegotiationResult — 自动协商结果。
 * 由 phy_auto_negotiate() 填充，描述当前信道下选定的最优参数。
 */
typedef struct {
    int   modulation;           /* 选定的调制类型 PHY_MOD_* */
    int   baud;                 /* 选定的符号率 */
    float snr_db;               /* 协商时测得的 SNR（dB） */
    int   bits_per_symbol;      /* 每符号比特数 */
    int   effective_bitrate;    /* 有效比特率 = baud × bits_per_symbol */
    int   candidate_index;      /* 候选集中的索引（-1 表示无候选可用） */
    char  name[32];             /* 候选名称（如 "FSK-1200"） */
    /* 选定参数的完整副本（可直接用于 phy_set_params） */
    PhyParams params;
} AutoNegotiationResult;

/**
 * PhyContext — 不透明上下文句柄。
 * 每个独立链路创建一个上下文，包含 SDR 句柄、当前参数、
 * 协商结果、信道估计状态、虚拟环回缓冲区等。
 */
typedef struct PhyContext PhyContext;

/* ============================================================
 * 生命周期 API
 * ============================================================ */

/**
 * 打开物理层上下文并初始化 SDR 设备。
 *
 * @param sdr_backend   PHY_SDR_* 后端选择
 * @param frequency_hz  中心频率（Hz）
 * @param sample_rate   采样率（Hz），传 0 使用默认 8000
 * @return  成功返回上下文指针；失败返回 NULL（调用方应抛异常）
 */
PhyContext* phy_open(int sdr_backend, float frequency_hz, int sample_rate);

/**
 * 关闭上下文并释放所有资源（含 SDR 设备）。
 * @param ctx  上下文指针（可为 NULL）
 * @return PHY_OK
 */
int phy_close(PhyContext* ctx);

/* ============================================================
 * 自动模式 API
 * ============================================================ */

/**
 * 自动信道协商：探测当前信道 SNR，从预定义候选集中选最快可用参数。
 * 候选集涵盖全部 5 种调制、多种速率，均满足带宽 ≤ 12.5kHz。
 * 最低 SNR 下至少有 1 个候选（FSK 300 baud）可用。
 *
 * @param ctx     上下文
 * @param result  输出：协商结果
 * @return PHY_OK 或错误码
 */
int phy_auto_negotiate(PhyContext* ctx, AutoNegotiationResult* result);

/**
 * 自动模式发送：使用上次协商结果（或自动触发协商）编码并发送比特流。
 *
 * @param ctx       上下文
 * @param bits      原始比特流（字节数组，高位在前）
 * @param byte_len  字节数（>0，打包字节，每字节8比特，高位在前）
 * @return 成功返回发送的采样数；失败返回负值错误码
 */
int phy_auto_send(PhyContext* ctx, const unsigned char* bits, int byte_len);

/**
 * 自动模式接收：阻塞接收并解调，使用当前协商参数。
 *
 * @param ctx        上下文
 * @param out_buf    输出缓冲区（解调后的比特流，字节数组）
 * @param max_len    输出缓冲区最大字节数
 * @param timeout_ms 超时（毫秒），0 表示非阻塞，-1 表示无限等待
 * @return 成功返回解调得到的比特数；失败返回负值错误码
 */
int phy_auto_recv(PhyContext* ctx, unsigned char* out_buf, int max_len,
                  int timeout_ms);

/* ============================================================
 * 手动模式 API
 * ============================================================ */

/**
 * 设置手动模式参数。校验参数合法性（调制类型、带宽 ≤ 12.5kHz 等）。
 *
 * @param ctx     上下文
 * @param params  参数结构体
 * @return PHY_OK 或 PHY_ERR_*（带宽超限返回 PHY_ERR_BANDWIDTH）
 */
int phy_set_params(PhyContext* ctx, const PhyParams* params);

/**
 * 获取当前参数。
 * @param ctx     上下文
 * @param params  输出：当前参数
 * @return PHY_OK
 */
int phy_get_params(PhyContext* ctx, PhyParams* params);

/**
 * 手动模式发送：使用当前设置的参数编码并发送。
 *
 * @param ctx       上下文
 * @param bits      原始比特流
 * @param byte_len  字节数（打包字节，每字节8比特）
 * @return 成功返回发送的采样数；失败返回负值错误码
 */
int phy_manual_send(PhyContext* ctx, const unsigned char* bits, int byte_len);

/**
 * 手动模式接收：使用当前参数解调。
 *
 * @param ctx        上下文
 * @param out_buf    输出缓冲区
 * @param max_len    缓冲区最大字节数
 * @param timeout_ms 超时（毫秒）
 * @return 成功返回比特数；失败返回负值错误码
 */
int phy_manual_recv(PhyContext* ctx, unsigned char* out_buf, int max_len,
                    int timeout_ms);

/* ============================================================
 * 信道质量查询 API
 * ============================================================ */

/**
 * 获取当前估计的信噪比（dB）。
 * 基于最近一次接收/协商的信道测量。
 * @param ctx 上下文
 * @return SNR（dB），无测量时返回 -INF（-999.0f）
 */
float phy_get_snr(PhyContext* ctx);

/**
 * 获取当前估计的频率偏移（Hz）。
 * 基于接收信号的载波频率误差估计。
 * @param ctx 上下文
 * @return 频偏（Hz），无测量时返回 0
 */
float phy_get_frequency_offset(PhyContext* ctx);

/* ============================================================
 * 纯基带编码/解码 API（不操作 SDR，用于测试和上层 FEC 集成）
 * ============================================================ */

/**
 * 纯编码：比特流 -> 基带采样（8-bit unsigned，单声道）。
 * 不操作 SDR，仅做调制。
 *
 * @param params       调制参数
 * @param bits         输入比特流（打包字节，每字节8比特，高位在前）
 * @param byte_len     输入字节数
 * @param out_samples  输出采样缓冲区
 * @param max_samples  输出缓冲区最大字节数
 * @return 成功返回输出采样字节数；失败返回负值
 */
int phy_encode(const PhyParams* params, const unsigned char* bits, int byte_len,
               unsigned char* out_samples, int max_samples);

/**
 * 纯解码：基带采样 -> 比特流。
 * 不操作 SDR，仅做解调。
 *
 * @param params       调制参数
 * @param samples      输入采样
 * @param sample_len   采样字节数
 * @param out_bits     输出比特流缓冲区
 * @param max_bits     输出缓冲区最大字节数
 * @return 成功返回输出比特数；失败返回负值
 */
int phy_decode(const PhyParams* params, const unsigned char* samples, int sample_len,
               unsigned char* out_bits, int max_bits);

/**
 * 获取库版本字符串。
 */
const char* phy_version(void);

#ifdef __cplusplus
}
#endif

#endif /* PHY_LIB_H */
