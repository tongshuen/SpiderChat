/*
 * phy_lib.c — Spider 无线电物理层 C 共享库实现
 *
 * 包含：
 *   - 5 种调制/解调：FSK / ASK / PSK / QAM / GMSK
 *   - SDR 抽象层（V4L2 / 虚拟环回）
 *   - 自动信道协商（候选集 + SNR 驱动）
 *   - 信道质量估计（SNR / 频偏）
 *
 * 编译：make（见同目录 Makefile）
 * 无 Python 依赖，纯 C99 + libm。
 */
#include "phy_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <float.h>

#ifdef __linux__
#include <fcntl.h>
#include <unistd.h>
#endif

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ============================================================
 * 内部常量
 * ============================================================ */
#define PHY_LIB_VERSION "1.0.0"
#define VIRTUAL_BUFFER_SIZE (1 << 20)  /* 1 MB 虚拟环回缓冲 */
#define PREAMBLE_LEN 16                /* 前导码长度（比特），用于同步和相位恢复 */
#define PREAMBLE_PATTERN 0xAAAAAAAA    /* 前导码：交替 0101... */

/* ============================================================
 * SDR 后端接口（函数指针表）
 * ============================================================ */
typedef struct {
    int  (*open)(void* dev, float freq, int sr);
    void (*close)(void* dev);
    int  (*write)(void* dev, const unsigned char* data, int len);
    int  (*read)(void* dev, unsigned char* buf, int max_len, int timeout_ms);
} SdrDriver;

/* ============================================================
 * 虚拟 SDR 设备（环回 + AWGN 信道仿真，用于测试）
 * ============================================================ */
typedef struct {
    unsigned char* tx_buf;     /* 发送缓冲（环回） */
    int            tx_len;     /* 当前缓冲中的采样数 */
    int            tx_pos;     /* 读取位置 */
    float          noise_snr;  /* 仿真信道 SNR（dB），-1 表示无噪声 */
    float          freq_offset; /* 仿真频偏（Hz） */
} VirtualSdr;

static int virtual_open(void* dev, float freq, int sr) {
    (void)freq; (void)sr;
    VirtualSdr* v = (VirtualSdr*)dev;
    v->tx_buf = (unsigned char*)calloc(VIRTUAL_BUFFER_SIZE, 1);
    v->tx_len = 0;
    v->tx_pos = 0;
    v->noise_snr = -1.0f;      /* 默认无噪声 */
    v->freq_offset = 0.0f;
    return v->tx_buf ? 0 : -1;
}

static void virtual_close(void* dev) {
    VirtualSdr* v = (VirtualSdr*)dev;
    if (v->tx_buf) free(v->tx_buf);
    v->tx_buf = NULL;
}

static int virtual_write(void* dev, const unsigned char* data, int len) {
    VirtualSdr* v = (VirtualSdr*)dev;
    if (v->tx_len + len > VIRTUAL_BUFFER_SIZE) {
        /* 缓冲满：丢弃最旧的数据 */
        int overflow = (v->tx_len + len) - VIRTUAL_BUFFER_SIZE;
        memmove(v->tx_buf, v->tx_buf + overflow, v->tx_len - overflow);
        v->tx_len -= overflow;
        v->tx_pos = (v->tx_pos > overflow) ? v->tx_pos - overflow : 0;
    }
    memcpy(v->tx_buf + v->tx_len, data, len);
    v->tx_len += len;
    return len;
}

static int virtual_read(void* dev, unsigned char* buf, int max_len, int timeout_ms) {
    (void)timeout_ms;
    VirtualSdr* v = (VirtualSdr*)dev;
    int available = v->tx_len - v->tx_pos;
    if (available <= 0) return 0;
    int to_read = (available < max_len) ? available : max_len;

    /* AWGN 信道仿真 */
    if (v->noise_snr > 0) {
        float noise_power = 1.0f / powf(10.0f, v->noise_snr / 10.0f);
        float noise_std = 64.0f * sqrtf(noise_power);
        for (int i = 0; i < to_read; i++) {
            float s = (float)v->tx_buf[v->tx_pos + i] - 128.0f;
            /* Box-Muller 高斯噪声 */
            float u1 = ((float)rand() / RAND_MAX) + 1e-10f;
            float u2 = (float)rand() / RAND_MAX;
            float noise = noise_std * sqrtf(-2.0f * logf(u1)) * cosf(2.0f * (float)M_PI * u2);
            int val = (int)(s + noise + 128.0f);
            if (val < 0) val = 0;
            if (val > 255) val = 255;
            buf[i] = (unsigned char)val;
        }
    } else {
        memcpy(buf, v->tx_buf + v->tx_pos, to_read);
    }
    v->tx_pos += to_read;
    return to_read;
}

static SdrDriver virtual_driver = {
    virtual_open, virtual_close, virtual_write, virtual_read
};

/* ============================================================
 * V4L2 SDR 设备（Linux，/dev/videoX）
 * ============================================================ */
typedef struct {
    int fd;
    float freq;
    int   sample_rate;
} V4l2Sdr;

static int v4l2_open(void* dev, float freq, int sr) {
#ifdef __linux__
    V4l2Sdr* v = (V4l2Sdr*)dev;
    v->freq = freq;
    v->sample_rate = sr;
    /* 尝试打开 /dev/video0（真实实现应使用 ioctl 设置频率/格式） */
    v->fd = open("/dev/video0", O_RDWR);
    if (v->fd < 0) return -1;
    return 0;
#else
    (void)dev; (void)freq; (void)sr;
    return -1;  /* 非 Linux 平台不支持 */
#endif
}

static void v4l2_close(void* dev) {
#ifdef __linux__
    V4l2Sdr* v = (V4l2Sdr*)dev;
    if (v->fd >= 0) close(v->fd);
    v->fd = -1;
#else
    (void)dev;
#endif
}

static int v4l2_write(void* dev, const unsigned char* data, int len) {
#ifdef __linux__
    V4l2Sdr* v = (V4l2Sdr*)dev;
    if (v->fd < 0) return -1;
    return (int)write(v->fd, data, len);
#else
    (void)dev; (void)data; (void)len;
    return -1;
#endif
}

static int v4l2_read(void* dev, unsigned char* buf, int max_len, int timeout_ms) {
#ifdef __linux__
    V4l2Sdr* v = (V4l2Sdr*)dev;
    if (v->fd < 0) return -1;
    /* 设置超时（真实实现应使用 select/poll） */
    (void)timeout_ms;
    return (int)read(v->fd, buf, max_len);
#else
    (void)dev; (void)buf; (void)max_len; (void)timeout_ms;
    return -1;
#endif
}

static SdrDriver v4l2_driver = {
    v4l2_open, v4l2_close, v4l2_write, v4l2_read
};

/* ============================================================
 * PhyContext 定义
 * ============================================================ */
struct PhyContext {
    int   sdr_backend;
    float frequency_hz;
    int   sample_rate;

    /* SDR 设备 */
    SdrDriver* driver;
    void*       dev_data;
    int         sdr_opened;

    /* 当前参数（手动模式） */
    PhyParams params;
    int       params_set;

    /* 自动协商结果 */
    AutoNegotiationResult nego_result;
    int                    nego_done;

    /* 信道估计 */
    float last_snr_db;
    float last_freq_offset_hz;
    int   channel_estimated;

    /* 接收状态（用于跨调用的符号同步） */
    float   demod_phase;
    int     demod_sample_count;
    unsigned char* rx_buffer;
    int            rx_buffer_len;
    int            rx_buffer_cap;

    /* 虚拟 SDR 专用：信道仿真参数 */
    VirtualSdr* virtual_dev;
};

/* ============================================================
 * 工具函数
 * ============================================================ */
static int bits_per_symbol_for_modulation(int modulation, const PhyParams* p) {
    switch (modulation) {
        case PHY_MOD_FSK:  return 1;  /* 2FSK */
        case PHY_MOD_ASK:  return (p->ask_levels > 2) ? 2 : 1;
        case PHY_MOD_PSK:  return 1;  /* BPSK */
        case PHY_MOD_QAM:
            if (p->qam_order >= 256) return 8;
            if (p->qam_order >= 64)  return 6;
            return 4;  /* 16QAM */
        case PHY_MOD_GMSK: return 1;
        default: return 1;
    }
}

static float estimate_bandwidth_hz(const PhyParams* p) {
    /* Carson 带宽估计 */
    switch (p->modulation) {
        case PHY_MOD_FSK: {
            float max_dev = fmaxf(fabsf(p->fsk_dev0), fabsf(p->fsk_dev1));
            return 2.0f * max_dev + (float)p->baud;
        }
        case PHY_MOD_ASK:
        case PHY_MOD_PSK:
            return (float)p->baud * 1.2f;  /* 升余弦滚降近似 */
        case PHY_MOD_QAM:
            return (float)p->baud * (1.0f + p->qam_rolloff);
        case PHY_MOD_GMSK:
            return (float)p->baud * (1.0f + p->gmsk_bt);
        default:
            return (float)p->baud * 2.0f;
    }
}

static int validate_params(const PhyParams* p) {
    if (!p) return PHY_ERR_INVALID_PARAM;
    if (p->modulation < 0 || p->modulation > PHY_MOD_GMSK)
        return PHY_ERR_INVALID_PARAM;
    if (p->baud <= 0 || p->sample_rate <= 0)
        return PHY_ERR_INVALID_PARAM;
    if (p->sample_rate / p->baud < 2)
        return PHY_ERR_INVALID_PARAM;  /* 不满足奈奎斯特 */
    float bw = estimate_bandwidth_hz(p);
    if (bw > PHY_MAX_BANDWIDTH_HZ)
        return PHY_ERR_BANDWIDTH;
    return PHY_OK;
}

/* ============================================================
 * 调制函数（比特流 -> 基带采样，8-bit unsigned）
 * ============================================================ */

/* 通用：添加前导码 + 数据（输入为打包字节，内部解包为逐比特） */
static int build_frame_bits(const unsigned char* bytes, int byte_len,
                            unsigned char* frame, int max_frame) {
    int data_bits = byte_len * 8;
    int total = PREAMBLE_LEN + data_bits;
    if (total > max_frame) return -1;
    /* 前导码 */
    for (int i = 0; i < PREAMBLE_LEN; i++) {
        frame[i] = (PREAMBLE_PATTERN >> (15 - (i % 16))) & 1;
    }
    /* 解包数据字节为逐比特（高位在前） */
    for (int i = 0; i < byte_len; i++) {
        unsigned char byte = bytes[i];
        for (int b = 0; b < 8; b++) {
            frame[PREAMBLE_LEN + i * 8 + b] = (byte >> (7 - b)) & 1;
        }
    }
    return total;
}

static int modulate_fsk(const PhyParams* p, const unsigned char* bytes, int byte_len,
                         unsigned char* out, int max_out) {
    int sps = p->sample_rate / p->baud;  /* 每符号采样数 */
    int data_bits = byte_len * 8;
    int total_bits = PREAMBLE_LEN + data_bits;
    int needed = total_bits * sps;
    if (needed > max_out) return PHY_ERR_BUFFER_TOO_SMALL;

    unsigned char* frame = (unsigned char*)malloc(total_bits);
    if (!frame) return PHY_ERR_INTERNAL;
    build_frame_bits(bytes, byte_len, frame, total_bits);

    float phase = 0.0f;
    for (int i = 0; i < total_bits; i++) {
        float freq = frame[i] ? p->fsk_dev1 : p->fsk_dev0;
        for (int s = 0; s < sps; s++) {
            phase += 2.0f * (float)M_PI * freq / p->sample_rate;
            float v = 128.0f + 63.0f * sinf(phase);
            int iv = (int)(v + 0.5f);
            if (iv < 0) iv = 0; if (iv > 255) iv = 255;
            out[i * sps + s] = (unsigned char)iv;
        }
    }
    free(frame);
    return needed;
}

static int modulate_ask(const PhyParams* p, const unsigned char* bytes, int byte_len,
                        unsigned char* out, int max_out) {
    int sps = p->sample_rate / p->baud;
    int bps = bits_per_symbol_for_modulation(PHY_MOD_ASK, p);
    int data_bits = byte_len * 8;
    int total_bits = PREAMBLE_LEN + data_bits;
    int total_symbols = (total_bits + bps - 1) / bps;
    int needed = total_symbols * sps;
    if (needed > max_out) return PHY_ERR_BUFFER_TOO_SMALL;

    unsigned char* frame = (unsigned char*)malloc(total_bits);
    if (!frame) return PHY_ERR_INTERNAL;
    build_frame_bits(bytes, byte_len, frame, total_bits);

    float phase = 0.0f;
    float amp_range = p->ask_amp_high - p->ask_amp_low;
    for (int sym = 0; sym < total_symbols; sym++) {
        /* 收集该符号的比特 */
        int symbol_val = 0;
        for (int b = 0; b < bps; b++) {
            int bit_idx = sym * bps + b;
            int bit = (bit_idx < total_bits) ? frame[bit_idx] : 0;
            symbol_val = (symbol_val << 1) | bit;
        }
        float amp = p->ask_amp_low + amp_range * ((float)symbol_val / (p->ask_levels - 1));
        for (int s = 0; s < sps; s++) {
            phase += 2.0f * (float)M_PI * 1000.0f / p->sample_rate;  /* 1kHz 载波 */
            float v = 128.0f + 63.0f * amp * sinf(phase);
            int iv = (int)(v + 0.5f);
            if (iv < 0) iv = 0; if (iv > 255) iv = 255;
            out[sym * sps + s] = (unsigned char)iv;
        }
    }
    free(frame);
    return needed;
}

static int modulate_psk(const PhyParams* p, const unsigned char* bytes, int byte_len,
                        unsigned char* out, int max_out) {
    int sps = p->sample_rate / p->baud;
    int data_bits = byte_len * 8;
    int total_bits = PREAMBLE_LEN + data_bits;
    int needed = total_bits * sps;
    if (needed > max_out) return PHY_ERR_BUFFER_TOO_SMALL;

    unsigned char* frame = (unsigned char*)malloc(total_bits);
    if (!frame) return PHY_ERR_INTERNAL;
    build_frame_bits(bytes, byte_len, frame, total_bits);

    float phase = 0.0f;
    float phase_rad0 = p->psk_phase0 * (float)M_PI / 180.0f;
    float phase_rad1 = p->psk_phase1 * (float)M_PI / 180.0f;
    for (int i = 0; i < total_bits; i++) {
        float sym_phase = frame[i] ? phase_rad1 : phase_rad0;
        for (int s = 0; s < sps; s++) {
            phase += 2.0f * (float)M_PI * 1000.0f / p->sample_rate;
            float v = 128.0f + 63.0f * sinf(phase + sym_phase);
            int iv = (int)(v + 0.5f);
            if (iv < 0) iv = 0; if (iv > 255) iv = 255;
            out[i * sps + s] = (unsigned char)iv;
        }
    }
    free(frame);
    return needed;
}

static int modulate_qam(const PhyParams* p, const unsigned char* bytes, int byte_len,
                        unsigned char* out, int max_out) {
    int sps = p->sample_rate / p->baud;
    int bps = bits_per_symbol_for_modulation(PHY_MOD_QAM, p);
    int data_bits = byte_len * 8;
    int total_bits = PREAMBLE_LEN + data_bits;
    int total_symbols = (total_bits + bps - 1) / bps;
    int needed = total_symbols * sps;
    if (needed > max_out) return PHY_ERR_BUFFER_TOO_SMALL;

    unsigned char* frame = (unsigned char*)malloc(total_bits);
    if (!frame) return PHY_ERR_INTERNAL;
    build_frame_bits(bytes, byte_len, frame, total_bits);

    int levels = (int)sqrtf((float)p->qam_order);  /* 每维电平数 */
    float phase = 0.0f;
    for (int sym = 0; sym < total_symbols; sym++) {
        int symbol_val = 0;
        for (int b = 0; b < bps; b++) {
            int bit_idx = sym * bps + b;
            int bit = (bit_idx < total_bits) ? frame[bit_idx] : 0;
            symbol_val = (symbol_val << 1) | bit;
        }
        /* 格雷码映射到 I/Q 星座点 */
        int i_level = symbol_val & (levels - 1);
        int q_level = (symbol_val >> (bps / 2)) & (levels - 1);
        float I = (2.0f * i_level - (levels - 1)) / (levels - 1);
        float Q = (2.0f * q_level - (levels - 1)) / (levels - 1);
        for (int s = 0; s < sps; s++) {
            phase += 2.0f * (float)M_PI * 1000.0f / p->sample_rate;
            float v = 128.0f + 45.0f * (I * cosf(phase) - Q * sinf(phase));
            int iv = (int)(v + 0.5f);
            if (iv < 0) iv = 0; if (iv > 255) iv = 255;
            out[sym * sps + s] = (unsigned char)iv;
        }
    }
    free(frame);
    return needed;
}

/* GMSK：高斯滤波的 MSK。用高斯脉冲整形的 FSK。 */
static int modulate_gmsk(const PhyParams* p, const unsigned char* bytes, int byte_len,
                          unsigned char* out, int max_out) {
    int sps = p->sample_rate / p->baud;
    int data_bits = byte_len * 8;
    int total_bits = PREAMBLE_LEN + data_bits;
    int needed = total_bits * sps;
    if (needed > max_out) return PHY_ERR_BUFFER_TOO_SMALL;

    unsigned char* frame = (unsigned char*)malloc(total_bits);
    if (!frame) return PHY_ERR_INTERNAL;
    build_frame_bits(bytes, byte_len, frame, total_bits);

    /* 生成高斯滤波器系数 */
    int filter_len = sps * 3;
    float* gauss = (float*)malloc(filter_len * sizeof(float));
    if (!gauss) { free(frame); return PHY_ERR_INTERNAL; }
    float bt = p->gmsk_bt;
    float alpha = sqrtf(logf(2.0f) / 2.0f) / (bt * sps);
    float gsum = 0.0f;
    for (int i = 0; i < filter_len; i++) {
        float t = (float)(i - filter_len / 2) / sps;
        gauss[i] = expf(-(alpha * t) * (alpha * t) * (float)M_PI);
        gsum += gauss[i];
    }
    for (int i = 0; i < filter_len; i++) gauss[i] /= gsum;

    /* 差分编码 + 高斯脉冲整形 */
    float phase = 0.0f;
    float freq_dev = (float)p->baud / 2.0f;  /* MSK 频偏 = baud/2 */
    for (int i = 0; i < total_bits; i++) {
        /* 对当前符号应用高斯滤波的频率轨迹 */
        for (int s = 0; s < sps; s++) {
            float filtered_freq = 0.0f;
            for (int k = 0; k < filter_len; k++) {
                int bit_idx = i + (k - filter_len / 2) / sps;
                if (bit_idx >= 0 && bit_idx < total_bits) {
                    float bit_val = frame[bit_idx] ? 1.0f : -1.0f;
                    filtered_freq += bit_val * gauss[k];
                }
            }
            float freq = filtered_freq * freq_dev;
            phase += 2.0f * (float)M_PI * freq / p->sample_rate;
            float v = 128.0f + 63.0f * sinf(phase);
            int iv = (int)(v + 0.5f);
            if (iv < 0) iv = 0; if (iv > 255) iv = 255;
            out[i * sps + s] = (unsigned char)iv;
        }
    }
    free(gauss);
    free(frame);
    return needed;
}

/* ============================================================
 * 解调函数（基带采样 -> 比特流）
 * ============================================================ */

/* 前导码检测：找到前导码起始位置 */
static int detect_preamble(const unsigned char* samples, int sample_len, int sps) {
    /* 能量检测，找到第一个能量超过阈值的符号位置。
       使用 4 符号窗口（而非 PREAMBLE_LEN 符号），因为多比特每符号调制
       （如 QAM-16）的前导码只有 4 个符号，但能量检测只需少量符号即可。 */
    int win = 4 * sps;
    if (sample_len < win) return -1;
    float threshold = 5.0f;  /* 能量阈值 */
    for (int i = 0; i <= sample_len - win; i += sps / 2) {
        float energy = 0.0f;
        for (int s = 0; s < win; s++) {
            float v = (float)samples[i + s] - 128.0f;
            energy += v * v;
        }
        energy /= win;
        if (energy > threshold) return i;
    }
    return 0;  /* 未检测到，从 0 开始（容错） */
}

static int demodulate_fsk(const PhyParams* p, const unsigned char* samples, int sample_len,
                           unsigned char* out_bits, int max_bits) {
    int sps = p->sample_rate / p->baud;
    int start = detect_preamble(samples, sample_len, sps);
    if (start < 0) return PHY_ERR_NO_SIGNAL;

    int total_symbols = (sample_len - start) / sps;
    if (total_symbols <= PREAMBLE_LEN) return PHY_ERR_NO_SIGNAL;
    int data_symbols = total_symbols - PREAMBLE_LEN;
    int data_bits = data_symbols;  /* 2FSK: 1 bit/symbol */
    if (data_bits > max_bits * 8) data_bits = max_bits * 8;

    unsigned char* bitstream = (unsigned char*)malloc(data_bits);
    if (!bitstream) return PHY_ERR_INTERNAL;

    for (int sym = PREAMBLE_LEN; sym < PREAMBLE_LEN + data_symbols && (sym - PREAMBLE_LEN) < data_bits; sym++) {
        int offset = start + sym * sps;
        if (offset + sps > sample_len) break;
        /* 非相干检测：两个频点的能量比较 */
        float e0 = 0.0f, e1 = 0.0f;
        for (int s = 0; s < sps; s++) {
            float v = (float)samples[offset + s] - 128.0f;
            float t = (float)s / p->sample_rate;
            e0 += v * sinf(2.0f * (float)M_PI * p->fsk_dev0 * t);
            e1 += v * sinf(2.0f * (float)M_PI * p->fsk_dev1 * t);
        }
        bitstream[sym - PREAMBLE_LEN] = (fabsf(e1) > fabsf(e0)) ? 1 : 0;
    }

    /* 比特流打包为字节 */
    memset(out_bits, 0, max_bits);
    for (int i = 0; i < data_bits && i / 8 < max_bits; i++) {
        if (bitstream[i]) out_bits[i / 8] |= (1 << (7 - (i % 8)));
    }
    free(bitstream);
    return data_bits;
}

static int demodulate_ask(const PhyParams* p, const unsigned char* samples, int sample_len,
                           unsigned char* out_bits, int max_bits) {
    int sps = p->sample_rate / p->baud;
    int bps = bits_per_symbol_for_modulation(PHY_MOD_ASK, p);
    int preamble_syms = (PREAMBLE_LEN + bps - 1) / bps;
    int start = detect_preamble(samples, sample_len, sps);
    if (start < 0) return PHY_ERR_NO_SIGNAL;

    int total_symbols = (sample_len - start) / sps;
    if (total_symbols <= preamble_syms) return PHY_ERR_NO_SIGNAL;
    int data_symbols = total_symbols - preamble_syms;
    int data_bits = data_symbols * bps;
    if (data_bits > max_bits * 8) data_bits = max_bits * 8;

    unsigned char* bitstream = (unsigned char*)malloc(data_bits);
    if (!bitstream) return PHY_ERR_INTERNAL;

    float amp_range = p->ask_amp_high - p->ask_amp_low;
    for (int sym = preamble_syms; sym < total_symbols; sym++) {
        int offset = start + sym * sps;
        if (offset + sps > sample_len) break;
        /* 包络检测：符号窗内的平均幅度 */
        float avg_amp = 0.0f;
        for (int s = 0; s < sps; s++) {
            avg_amp += fabsf((float)samples[offset + s] - 128.0f);
        }
        avg_amp /= (sps * 63.0f);
        /* 量化到最近的电平 */
        int level = (int)((avg_amp - p->ask_amp_low) / amp_range * (p->ask_levels - 1) + 0.5f);
        if (level < 0) level = 0;
        if (level >= p->ask_levels) level = p->ask_levels - 1;
        /* 解映射为比特 */
        for (int b = 0; b < bps; b++) {
            int bit_idx = (sym - preamble_syms) * bps + b;
            if (bit_idx >= data_bits) break;
            bitstream[bit_idx] = (level >> (bps - 1 - b)) & 1;
        }
    }

    memset(out_bits, 0, max_bits);
    for (int i = 0; i < data_bits && i / 8 < max_bits; i++) {
        if (bitstream[i]) out_bits[i / 8] |= (1 << (7 - (i % 8)));
    }
    free(bitstream);
    return data_bits;
}

static int demodulate_psk(const PhyParams* p, const unsigned char* samples, int sample_len,
                           unsigned char* out_bits, int max_bits) {
    int sps = p->sample_rate / p->baud;
    int start = detect_preamble(samples, sample_len, sps);
    if (start < 0) return PHY_ERR_NO_SIGNAL;

    int total_symbols = (sample_len - start) / sps;
    if (total_symbols <= PREAMBLE_LEN) return PHY_ERR_NO_SIGNAL;
    int data_symbols = total_symbols - PREAMBLE_LEN;
    int data_bits = data_symbols;
    if (data_bits > max_bits * 8) data_bits = max_bits * 8;

    /* 用前导码估计载波相位 */
    float carrier_phase = 0.0f;
    for (int s = 0; s < PREAMBLE_LEN * sps && start + s < sample_len; s++) {
        float v = (float)samples[start + s] - 128.0f;
        float t = (float)s / p->sample_rate;
        carrier_phase += v * cosf(2.0f * (float)M_PI * 1000.0f * t);
    }

    unsigned char* bitstream = (unsigned char*)malloc(data_bits);
    if (!bitstream) return PHY_ERR_INTERNAL;

    float phase_rad0 = p->psk_phase0 * (float)M_PI / 180.0f;
    float phase_rad1 = p->psk_phase1 * (float)M_PI / 180.0f;
    for (int sym = PREAMBLE_LEN; sym < total_symbols && (sym - PREAMBLE_LEN) < data_bits; sym++) {
        int offset = start + sym * sps;
        if (offset + sps > sample_len) break;
        /* 相干检测：与两个参考相位相关 */
        float c0 = 0.0f, c1 = 0.0f;
        for (int s = 0; s < sps; s++) {
            float v = (float)samples[offset + s] - 128.0f;
            float t = (float)(offset + s) / p->sample_rate;
            float carrier = sinf(2.0f * (float)M_PI * 1000.0f * t + carrier_phase);
            c0 += v * carrier * cosf(phase_rad0);
            c1 += v * carrier * cosf(phase_rad1);
        }
        bitstream[sym - PREAMBLE_LEN] = (fabsf(c1) > fabsf(c0)) ? 1 : 0;
    }

    memset(out_bits, 0, max_bits);
    for (int i = 0; i < data_bits && i / 8 < max_bits; i++) {
        if (bitstream[i]) out_bits[i / 8] |= (1 << (7 - (i % 8)));
    }
    free(bitstream);
    return data_bits;
}

static int demodulate_qam(const PhyParams* p, const unsigned char* samples, int sample_len,
                           unsigned char* out_bits, int max_bits) {
    int sps = p->sample_rate / p->baud;
    int bps = bits_per_symbol_for_modulation(PHY_MOD_QAM, p);
    int preamble_syms = (PREAMBLE_LEN + bps - 1) / bps;
    int start = detect_preamble(samples, sample_len, sps);
    if (start < 0) return PHY_ERR_NO_SIGNAL;

    int total_symbols = (sample_len - start) / sps;
    if (total_symbols <= preamble_syms) return PHY_ERR_NO_SIGNAL;
    int data_symbols = total_symbols - preamble_syms;
    int data_bits = data_symbols * bps;
    if (data_bits > max_bits * 8) data_bits = max_bits * 8;

    int levels = (int)sqrtf((float)p->qam_order);
    unsigned char* bitstream = (unsigned char*)malloc(data_bits);
    if (!bitstream) return PHY_ERR_INTERNAL;

    /* 用前导码估计载波相位：前导码是交替 0/1，
       对 QAM 来说前导码符号在 I/Q 上有已知模式，
       通过相关检测估计载波相位偏移 */
    float phase_est = 0.0f;
    float phase_quality = 0.0f;
    /* 尝试多个相位偏移，找到使前导码 I/Q 能量最大的 */
    for (int trial = 0; trial < 16; trial++) {
        float trial_phase = (float)trial * (float)M_PI / 8.0f;
        float energy = 0.0f;
        for (int sym = 0; sym < preamble_syms && sym < total_symbols; sym++) {
            int offset = start + sym * sps;
            if (offset + sps > sample_len) break;
            float I = 0.0f, Q = 0.0f;
            for (int s = 0; s < sps; s++) {
                float v = (float)samples[offset + s] - 128.0f;
                float t = (float)(offset + s) / p->sample_rate;
                float carrier_cos = cosf(2.0f * (float)M_PI * 1000.0f * t + trial_phase);
                float carrier_sin = sinf(2.0f * (float)M_PI * 1000.0f * t + trial_phase);
                I += v * carrier_cos;
                Q -= v * carrier_sin;
            }
            energy += I * I + Q * Q;
        }
        if (energy > phase_quality) {
            phase_quality = energy;
            phase_est = trial_phase;
        }
    }

    for (int sym = preamble_syms; sym < total_symbols; sym++) {
        int offset = start + sym * sps;
        if (offset + sps > sample_len) break;
        /* 相干 I/Q 解调（使用估计的载波相位） */
        float I = 0.0f, Q = 0.0f;
        for (int s = 0; s < sps; s++) {
            float v = (float)samples[offset + s] - 128.0f;
            float t = (float)(offset + s) / p->sample_rate;
            float carrier_cos = cosf(2.0f * (float)M_PI * 1000.0f * t + phase_est);
            float carrier_sin = sinf(2.0f * (float)M_PI * 1000.0f * t + phase_est);
            I += v * carrier_cos;
            Q -= v * carrier_sin;
        }
        I /= (sps * 45.0f);
        Q /= (sps * 45.0f);
        /* 量化到最近的星座点 */
        int i_level = (int)((I + 1.0f) / 2.0f * (levels - 1) + 0.5f);
        int q_level = (int)((Q + 1.0f) / 2.0f * (levels - 1) + 0.5f);
        if (i_level < 0) i_level = 0;
        if (i_level >= levels) i_level = levels - 1;
        if (q_level < 0) q_level = 0;
        if (q_level >= levels) q_level = levels - 1;
        int symbol_val = (q_level << (bps / 2)) | i_level;
        for (int b = 0; b < bps; b++) {
            int bit_idx = (sym - preamble_syms) * bps + b;
            if (bit_idx >= data_bits) break;
            bitstream[bit_idx] = (symbol_val >> (bps - 1 - b)) & 1;
        }
    }

    memset(out_bits, 0, max_bits);
    for (int i = 0; i < data_bits && i / 8 < max_bits; i++) {
        if (bitstream[i]) out_bits[i / 8] |= (1 << (7 - (i % 8)));
    }
    free(bitstream);
    return data_bits;
}

static int demodulate_gmsk(const PhyParams* p, const unsigned char* samples, int sample_len,
                            unsigned char* out_bits, int max_bits) {
    /* GMSK 解调：采用 2FSK 非相干检测（MSK 是连续相位 FSK 的特例） */
    PhyParams fsk_params = *p;
    fsk_params.modulation = PHY_MOD_FSK;
    fsk_params.fsk_dev0 = -(float)p->baud / 4.0f;
    fsk_params.fsk_dev1 = (float)p->baud / 4.0f;
    return demodulate_fsk(&fsk_params, samples, sample_len, out_bits, max_bits);
}

/* ============================================================
 * 调制/解调分发
 * ============================================================ */
int phy_encode(const PhyParams* params, const unsigned char* bits, int byte_len,
               unsigned char* out_samples, int max_samples) {
    if (!params || !bits || !out_samples || byte_len <= 0)
        return PHY_ERR_INVALID_PARAM;
    int rc = validate_params(params);
    if (rc != PHY_OK) return rc;

    switch (params->modulation) {
        case PHY_MOD_FSK:  return modulate_fsk(params, bits, byte_len, out_samples, max_samples);
        case PHY_MOD_ASK:  return modulate_ask(params, bits, byte_len, out_samples, max_samples);
        case PHY_MOD_PSK:  return modulate_psk(params, bits, byte_len, out_samples, max_samples);
        case PHY_MOD_QAM:  return modulate_qam(params, bits, byte_len, out_samples, max_samples);
        case PHY_MOD_GMSK: return modulate_gmsk(params, bits, byte_len, out_samples, max_samples);
        default: return PHY_ERR_INVALID_PARAM;
    }
}

int phy_decode(const PhyParams* params, const unsigned char* samples, int sample_len,
               unsigned char* out_bits, int max_bits) {
    if (!params || !samples || !out_bits || sample_len <= 0)
        return PHY_ERR_INVALID_PARAM;
    if (params->modulation < 0 || params->modulation > PHY_MOD_GMSK)
        return PHY_ERR_INVALID_PARAM;

    switch (params->modulation) {
        case PHY_MOD_FSK:  return demodulate_fsk(params, samples, sample_len, out_bits, max_bits);
        case PHY_MOD_ASK:  return demodulate_ask(params, samples, sample_len, out_bits, max_bits);
        case PHY_MOD_PSK:  return demodulate_psk(params, samples, sample_len, out_bits, max_bits);
        case PHY_MOD_QAM:  return demodulate_qam(params, samples, sample_len, out_bits, max_bits);
        case PHY_MOD_GMSK: return demodulate_gmsk(params, samples, sample_len, out_bits, max_bits);
        default: return PHY_ERR_INVALID_PARAM;
    }
}

/* ============================================================
 * 自动协商候选集
 * 涵盖全部 5 种调制，多种速率，均满足带宽 ≤ 12.5kHz。
 * 按有效比特率降序排列，协商时选 min_snr ≤ 当前SNR 中最快的。
 * ============================================================ */
typedef struct {
    const char* name;
    int   modulation;
    int   baud;
    int   bits_per_symbol;
    float min_snr_db;
    float bandwidth_hz;
    float fsk_dev0, fsk_dev1;
    int   ask_levels;
    float ask_amp_high, ask_amp_low;
    float psk_phase0, psk_phase1;
    int   qam_order;
    float qam_rolloff;
    float gmsk_bt;
} PhyCandidate;

#define NUM_CANDIDATES 16

static const PhyCandidate CANDIDATES[NUM_CANDIDATES] = {
    /* 高比特率候选（需要高 SNR） */
    {"QAM-1200-16",  PHY_MOD_QAM,  1200, 4, 22.0f, 2400, 0,0, 0,0,0, 0,0, 16, 0.35f, 0},
    {"QAM-600-16",   PHY_MOD_QAM,   600, 4, 18.0f, 1200, 0,0, 0,0,0, 0,0, 16, 0.35f, 0},
    {"ASK-1200-4L",  PHY_MOD_ASK,  1200, 2, 15.0f, 1440, 0,0, 4,1.0f,0.0f, 0,0, 0,0, 0},
    {"GMSK-4000",    PHY_MOD_GMSK, 4000, 1, 16.0f, 5200, 0,0, 0,0,0, 0,0, 0,0, 0.3f},
    {"PSK-2400",      PHY_MOD_PSK,  2400, 1, 13.0f, 2880, 0,0, 0,0,0, 0,180, 0,0, 0},
    {"FSK-2400",      PHY_MOD_FSK,  2400, 1, 12.0f, 7200, 1200,2400, 0,0,0, 0,0, 0,0, 0},
    {"GMSK-2400",     PHY_MOD_GMSK, 2400, 1, 11.0f, 3600, 0,0, 0,0,0, 0,0, 0,0, 0.5f},
    {"PSK-1200",      PHY_MOD_PSK,  1200, 1,  9.0f, 1440, 0,0, 0,0,0, 0,180, 0,0, 0},
    {"FSK-1200",      PHY_MOD_FSK,  1200, 1,  8.0f, 5200, 1000,2000, 0,0,0, 0,0, 0,0, 0},
    {"GMSK-1200",     PHY_MOD_GMSK, 1200, 1,  7.0f, 1800, 0,0, 0,0,0, 0,0, 0,0, 0.5f},
    {"ASK-1200",      PHY_MOD_ASK,  1200, 1,  8.0f, 1440, 0,0, 2,1.0f,0.0f, 0,0, 0,0, 0},
    {"PSK-600",       PHY_MOD_PSK,   600, 1,  5.0f,  720, 0,0, 0,0,0, 0,180, 0,0, 0},
    {"FSK-600",       PHY_MOD_FSK,   600, 1,  4.0f, 2600, 500,1000, 0,0,0, 0,0, 0,0, 0},
    {"ASK-600",       PHY_MOD_ASK,   600, 1,  3.0f,  720, 0,0, 2,1.0f,0.0f, 0,0, 0,0, 0},
    {"ASK-300",       PHY_MOD_ASK,   300, 1,  2.0f,  360, 0,0, 2,1.0f,0.0f, 0,0, 0,0, 0},
    /* 最低 SNR 兜底候选（保证任何信道下至少有 1 个可用） */
    {"FSK-300",       PHY_MOD_FSK,   300, 1,  0.0f, 1400, 500,1000, 0,0,0, 0,0, 0,0, 0},
};

static void candidate_to_params(const PhyCandidate* c, PhyParams* p, int sample_rate) {
    memset(p, 0, sizeof(PhyParams));
    p->modulation = c->modulation;
    p->baud = c->baud;
    p->sample_rate = sample_rate;
    p->fsk_dev0 = c->fsk_dev0;
    p->fsk_dev1 = c->fsk_dev1;
    p->ask_levels = c->ask_levels;
    p->ask_amp_high = c->ask_amp_high;
    p->ask_amp_low = c->ask_amp_low;
    p->psk_phase0 = c->psk_phase0;
    p->psk_phase1 = c->psk_phase1;
    p->qam_order = c->qam_order;
    p->qam_rolloff = c->qam_rolloff;
    p->gmsk_bt = c->gmsk_bt;
    p->fec_type = PHY_FEC_NONE;
    p->bandwidth_hz = (int)c->bandwidth_hz;
}

/* ============================================================
 * 信道质量估计
 * ============================================================ */

/* 基于接收信号的 SNR 估计：信号功率 / 噪声功率 */
static float estimate_snr(const unsigned char* samples, int sample_len) {
    if (sample_len < 256) return -999.0f;
    /* 用信号的方差估计总功率，用前 100 个采样（假设为静默/噪声）估计噪声功率 */
    float noise_power = 0.0f;
    int noise_len = (sample_len > 200) ? 100 : sample_len / 4;
    for (int i = 0; i < noise_len; i++) {
        float v = (float)samples[i] - 128.0f;
        noise_power += v * v;
    }
    noise_power /= noise_len;

    float signal_power = 0.0f;
    int sig_start = noise_len;
    int sig_len = sample_len - sig_start;
    if (sig_len < 16) return -999.0f;
    for (int i = sig_start; i < sample_len; i++) {
        float v = (float)samples[i] - 128.0f;
        signal_power += v * v;
    }
    signal_power /= sig_len;

    if (noise_power < 0.01f) noise_power = 0.01f;
    float snr = signal_power / noise_power;
    return 10.0f * log10f(snr);
}

/* 频偏估计：基于载波频率误差（） */
static float estimate_frequency_offset(const unsigned char* samples, int sample_len) {
    if (sample_len < 256) return 0.0f;
    /* 过零率估计载波频率，与预期 1kHz 比较 */
    int zero_crossings = 0;
    for (int i = 1; i < sample_len; i++) {
        if ((samples[i-1] < 128 && samples[i] >= 128) ||
            (samples[i-1] >= 128 && samples[i] < 128)) {
            zero_crossings++;
        }
    }
    float estimated_freq = (float)zero_crossings / 2.0f * (8000.0f / sample_len);
    return estimated_freq - 1000.0f;
}

/* ============================================================
 * 生命周期 API
 * ============================================================ */
PhyContext* phy_open(int sdr_backend, float frequency_hz, int sample_rate) {
    if (sample_rate <= 0) sample_rate = PHY_DEFAULT_SAMPLE_RATE;

    PhyContext* ctx = (PhyContext*)calloc(1, sizeof(PhyContext));
    if (!ctx) return NULL;

    ctx->sdr_backend = sdr_backend;
    ctx->frequency_hz = frequency_hz;
    ctx->sample_rate = sample_rate;
    ctx->last_snr_db = -999.0f;
    ctx->last_freq_offset_hz = 0.0f;
    ctx->channel_estimated = 0;
    ctx->rx_buffer_cap = 65536;
    ctx->rx_buffer = (unsigned char*)malloc(ctx->rx_buffer_cap);
    if (!ctx->rx_buffer) { free(ctx); return NULL; }

    /* 选择 SDR 后端 */
    int backend = sdr_backend;
    if (backend == PHY_SDR_AUTO) {
#ifdef __linux__
        backend = PHY_SDR_V4L2;  /* Linux 优先 V4L2 */
#else
        backend = PHY_SDR_VIRTUAL;  /* 其他平台用虚拟 */
#endif
    }

    if (backend == PHY_SDR_V4L2) {
        ctx->driver = &v4l2_driver;
        ctx->dev_data = calloc(1, sizeof(V4l2Sdr));
        if (!ctx->dev_data) { free(ctx->rx_buffer); free(ctx); return NULL; }
    } else {
        /* 默认虚拟后端（含 SoapySDR 不可用时的回退） */
        ctx->driver = &virtual_driver;
        ctx->dev_data = calloc(1, sizeof(VirtualSdr));
        if (!ctx->dev_data) { free(ctx->rx_buffer); free(ctx); return NULL; }
        ctx->virtual_dev = (VirtualSdr*)ctx->dev_data;
    }

    /* 打开 SDR */
    if (ctx->driver->open(ctx->dev_data, frequency_hz, sample_rate) != 0) {
        /* V4L2 打开失败时，若为 AUTO 模式则回退到虚拟 */
        if (sdr_backend == PHY_SDR_AUTO && backend == PHY_SDR_V4L2) {
            ctx->driver->close(ctx->dev_data);
            free(ctx->dev_data);
            ctx->driver = &virtual_driver;
            ctx->dev_data = calloc(1, sizeof(VirtualSdr));
            ctx->virtual_dev = (VirtualSdr*)ctx->dev_data;
            if (ctx->driver->open(ctx->dev_data, frequency_hz, sample_rate) != 0) {
                free(ctx->rx_buffer); free(ctx->dev_data); free(ctx);
                return NULL;
            }
        } else {
            free(ctx->rx_buffer); free(ctx->dev_data); free(ctx);
            return NULL;
        }
    }
    ctx->sdr_opened = 1;

    srand((unsigned int)time(NULL));
    return ctx;
}

int phy_close(PhyContext* ctx) {
    if (!ctx) return PHY_OK;
    if (ctx->sdr_opened && ctx->driver && ctx->dev_data) {
        ctx->driver->close(ctx->dev_data);
    }
    if (ctx->dev_data) free(ctx->dev_data);
    if (ctx->rx_buffer) free(ctx->rx_buffer);
    free(ctx);
    return PHY_OK;
}

/* ============================================================
 * 自动模式 API
 * ============================================================ */
int phy_auto_negotiate(PhyContext* ctx, AutoNegotiationResult* result) {
    if (!ctx || !result) return PHY_ERR_INVALID_PARAM;
    if (!ctx->sdr_opened) return PHY_ERR_SDR_OPEN;

    /* 信道探测：发送探测信号并接收，估计 SNR */
    /* 虚拟后端：使用仿真的 SNR；真实后端：发送探测帧并测量 */
    float snr_db;
    if (ctx->virtual_dev) {
        snr_db = (ctx->virtual_dev->noise_snr > 0) ? ctx->virtual_dev->noise_snr : 30.0f;
    } else {
        /* 真实 SDR：发送探测信号，接收并估计 */
        PhyParams probe_params;
        memset(&probe_params, 0, sizeof(probe_params));
        probe_params.modulation = PHY_MOD_FSK;
        probe_params.baud = 300;
        probe_params.sample_rate = ctx->sample_rate;
        probe_params.fsk_dev0 = 500;
        probe_params.fsk_dev1 = 1000;
        probe_params.bandwidth_hz = 1400;

        unsigned char probe_bits[8] = {0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55};
        unsigned char probe_samples[8192];
        int probe_len = phy_encode(&probe_params, probe_bits, 64, probe_samples, 8192);
        if (probe_len > 0) {
            ctx->driver->write(ctx->dev_data, probe_samples, probe_len);
            /* 等待接收 */
            int rx_len = ctx->driver->read(ctx->dev_data, ctx->rx_buffer,
                                             ctx->rx_buffer_cap, 100);
            if (rx_len > 0) {
                snr_db = estimate_snr(ctx->rx_buffer, rx_len);
                ctx->last_freq_offset_hz = estimate_frequency_offset(ctx->rx_buffer, rx_len);
            } else {
                snr_db = 0.0f;  /* 无信号，用最低 SNR */
            }
        } else {
            snr_db = 0.0f;
        }
    }

    ctx->last_snr_db = snr_db;
    ctx->channel_estimated = 1;

    /* 从候选集中选择：min_snr ≤ 当前SNR 的候选中，有效比特率最高的 */
    int best_idx = -1;
    int best_bitrate = -1;
    for (int i = 0; i < NUM_CANDIDATES; i++) {
        if (CANDIDATES[i].min_snr_db <= snr_db + 0.5f) {  /* 容差 0.5dB */
            int bitrate = CANDIDATES[i].baud * CANDIDATES[i].bits_per_symbol;
            if (bitrate > best_bitrate) {
                best_bitrate = bitrate;
                best_idx = i;
            }
        }
    }

    /* 兜底：至少选 FSK-300（最低 SNR 候选） */
    if (best_idx < 0) {
        best_idx = NUM_CANDIDATES - 1;  /* FSK-300 */
        best_bitrate = CANDIDATES[best_idx].baud * CANDIDATES[best_idx].bits_per_symbol;
    }

    /* 填充结果 */
    memset(result, 0, sizeof(AutoNegotiationResult));
    result->modulation = CANDIDATES[best_idx].modulation;
    result->baud = CANDIDATES[best_idx].baud;
    result->snr_db = snr_db;
    result->bits_per_symbol = CANDIDATES[best_idx].bits_per_symbol;
    result->effective_bitrate = best_bitrate;
    result->candidate_index = best_idx;
    strncpy(result->name, CANDIDATES[best_idx].name, sizeof(result->name) - 1);
    candidate_to_params(&CANDIDATES[best_idx], &result->params, ctx->sample_rate);

    /* 保存到上下文 */
    ctx->nego_result = *result;
    ctx->nego_done = 1;
    ctx->params = result->params;
    ctx->params_set = 1;

    return PHY_OK;
}

int phy_auto_send(PhyContext* ctx, const unsigned char* bits, int byte_len) {
    if (!ctx || !bits || byte_len <= 0) return PHY_ERR_INVALID_PARAM;
    if (!ctx->sdr_opened) return PHY_ERR_SDR_OPEN;

    /* 若尚未协商，自动触发 */
    if (!ctx->nego_done) {
        AutoNegotiationResult res;
        int rc = phy_auto_negotiate(ctx, &res);
        if (rc != PHY_OK) return rc;
    }

    /* 编码（byte_len 是打包字节数，内部解包为 byte_len*8 比特） */
    int max_samples = byte_len * 8 * (ctx->sample_rate / ctx->params.baud) * 2 + 1024;
    if (max_samples > ctx->rx_buffer_cap) max_samples = ctx->rx_buffer_cap;
    int encoded = phy_encode(&ctx->params, bits, byte_len, ctx->rx_buffer, max_samples);
    if (encoded < 0) return encoded;

    /* 发送到 SDR */
    int written = ctx->driver->write(ctx->dev_data, ctx->rx_buffer, encoded);
    if (written < 0) return PHY_ERR_SDR_WRITE;
    return written;
}

int phy_auto_recv(PhyContext* ctx, unsigned char* out_buf, int max_len, int timeout_ms) {
    if (!ctx || !out_buf || max_len <= 0) return PHY_ERR_INVALID_PARAM;
    if (!ctx->sdr_opened) return PHY_ERR_SDR_OPEN;
    if (!ctx->nego_done) {
        AutoNegotiationResult res;
        int rc = phy_auto_negotiate(ctx, &res);
        if (rc != PHY_OK) return rc;
    }

    /* 从 SDR 读取 */
    int rx_len = ctx->driver->read(ctx->dev_data, ctx->rx_buffer,
                                     ctx->rx_buffer_cap, timeout_ms);
    if (rx_len <= 0) return (rx_len == 0) ? PHY_ERR_TIMEOUT : PHY_ERR_SDR_READ;

    /* 信道估计 */
    ctx->last_snr_db = estimate_snr(ctx->rx_buffer, rx_len);
    ctx->last_freq_offset_hz = estimate_frequency_offset(ctx->rx_buffer, rx_len);
    ctx->channel_estimated = 1;

    /* 解调 */
    return phy_decode(&ctx->params, ctx->rx_buffer, rx_len, out_buf, max_len);
}

/* ============================================================
 * 手动模式 API
 * ============================================================ */
int phy_set_params(PhyContext* ctx, const PhyParams* params) {
    if (!ctx || !params) return PHY_ERR_INVALID_PARAM;
    int rc = validate_params(params);
    if (rc != PHY_OK) return rc;
    ctx->params = *params;
    if (ctx->params.sample_rate <= 0) ctx->params.sample_rate = ctx->sample_rate;
    ctx->params_set = 1;
    return PHY_OK;
}

int phy_get_params(PhyContext* ctx, PhyParams* params) {
    if (!ctx || !params) return PHY_ERR_INVALID_PARAM;
    *params = ctx->params;
    return PHY_OK;
}

int phy_manual_send(PhyContext* ctx, const unsigned char* bits, int byte_len) {
    if (!ctx || !bits || byte_len <= 0) return PHY_ERR_INVALID_PARAM;
    if (!ctx->sdr_opened) return PHY_ERR_SDR_OPEN;
    if (!ctx->params_set) return PHY_ERR_INVALID_PARAM;

    int max_samples = byte_len * 8 * (ctx->params.sample_rate / ctx->params.baud) * 2 + 1024;
    if (max_samples > ctx->rx_buffer_cap) max_samples = ctx->rx_buffer_cap;
    int encoded = phy_encode(&ctx->params, bits, byte_len, ctx->rx_buffer, max_samples);
    if (encoded < 0) return encoded;

    int written = ctx->driver->write(ctx->dev_data, ctx->rx_buffer, encoded);
    if (written < 0) return PHY_ERR_SDR_WRITE;
    return written;
}

int phy_manual_recv(PhyContext* ctx, unsigned char* out_buf, int max_len, int timeout_ms) {
    if (!ctx || !out_buf || max_len <= 0) return PHY_ERR_INVALID_PARAM;
    if (!ctx->sdr_opened) return PHY_ERR_SDR_OPEN;
    if (!ctx->params_set) return PHY_ERR_INVALID_PARAM;

    int rx_len = ctx->driver->read(ctx->dev_data, ctx->rx_buffer,
                                     ctx->rx_buffer_cap, timeout_ms);
    if (rx_len <= 0) return (rx_len == 0) ? PHY_ERR_TIMEOUT : PHY_ERR_SDR_READ;

    ctx->last_snr_db = estimate_snr(ctx->rx_buffer, rx_len);
    ctx->last_freq_offset_hz = estimate_frequency_offset(ctx->rx_buffer, rx_len);
    ctx->channel_estimated = 1;

    return phy_decode(&ctx->params, ctx->rx_buffer, rx_len, out_buf, max_len);
}

/* ============================================================
 * 信道质量查询 API
 * ============================================================ */
float phy_get_snr(PhyContext* ctx) {
    if (!ctx || !ctx->channel_estimated) return -999.0f;
    return ctx->last_snr_db;
}

float phy_get_frequency_offset(PhyContext* ctx) {
    if (!ctx) return 0.0f;
    return ctx->last_freq_offset_hz;
}

/* ============================================================
 * 虚拟 SDR 专用：设置仿真信道参数（供测试使用）
 * 这些函数不在头文件中声明，通过 dlsym 或直接链接使用。
 * ============================================================ */
void phy_virtual_set_noise_snr(PhyContext* ctx, float snr_db) {
    if (ctx && ctx->virtual_dev) {
        ctx->virtual_dev->noise_snr = snr_db;
    }
}

void phy_virtual_set_frequency_offset(PhyContext* ctx, float offset_hz) {
    if (ctx && ctx->virtual_dev) {
        ctx->virtual_dev->freq_offset = offset_hz;
    }
}

void phy_virtual_reset(PhyContext* ctx) {
    if (ctx && ctx->virtual_dev) {
        ctx->virtual_dev->tx_len = 0;
        ctx->virtual_dev->tx_pos = 0;
    }
}

/* ============================================================
 * 版本
 * ============================================================ */
const char* phy_version(void) {
    return PHY_LIB_VERSION;
}
