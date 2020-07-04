/* include/cong/cubic.h cubic拥塞控制算法定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_CONG_CUBIC_H
#define _LIBGQUIC_CONG_CUBIC_H

#include "cong/prr.h"
#include "util/rtt.h"
#include "cong/hybrid_slow_start.h"
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

/**
 * cubic算法实现模块
 */
typedef struct gquic_cubic_s gquic_cubic_t;
struct gquic_cubic_s {

    // 连接数
    int conn_count;

    // 标记开始恢复阶段的时间
    u_int64_t epoch;

    // 在一个恢复阶段中的最大拥塞窗口
    u_int64_t last_max_cwnd;

    // 在一个恢复阶段中对端确认接收的数据大小
    u_int64_t ack_bytes_count;

    // reno拥塞窗口
    u_int64_t reno_cwnd;

    // 开始执行cubic算法时的原点拥塞窗口
    u_int64_t origin_point_cwnd;

    // 开始执行cubic算法时的原点时间
    u_int32_t origin_point_time;

    // 最后计算得到的拥塞窗口大小
    u_int64_t last_target_cwnd;
};

/**
 * cubic初始化
 *
 * @param cubic: cubic
 * 
 * @return exception
 */
gquic_exception_t gquic_cubic_init(gquic_cubic_t *const cubic);

/**
 * cubic 构造函数
 *
 * @param cubic: cubic
 * 
 * @return exception
 */
gquic_exception_t gquic_cubic_ctor(gquic_cubic_t *const cubic);

/**
 * 当QUIC探知丢包后，计算新的拥塞窗口
 *
 * @param cubic: cubic
 * @param cwnd: 当前的拥塞窗口
 *
 * @return cubic处理后的拥塞窗口
 */
u_int64_t gquic_cubic_cwnd_after_packet_loss(gquic_cubic_t *const cubic, const u_int64_t cwnd);

/**
 * 当QUIC接收到ACK frame后，计算新的拥塞窗口
 *
 * @param cubic: cubic
 * @param acked_bytes: 确认的比特数
 * @param cwnd: 当前的拥塞窗口
 * @param delay_min: ACK时延，(packet的min RTT)
 * @param event_time: 接收ACK frame时间
 *
 * @return cubic处理后的拥塞窗口
 */
u_int64_t gquic_cubic_cwnd_after_packet_ack(gquic_cubic_t *const cubic,
                                            const u_int64_t acked_bytes, const u_int64_t cwnd, const u_int64_t delay_min, const u_int64_t event_time);


/**
 * cong cubic 使用cubic算法的拥塞控制模块
 */
typedef struct gquic_cong_cubic_s gquic_cong_cubic_t;
struct gquic_cong_cubic_s {

    // 慢启动算法
    gquic_cong_bybrid_slow_start_t hybrid_slow_start;

    // PRR
    gquic_prr_t prr;
    bool disable_prr;

    // Cubic算法
    gquic_cubic_t cubic;

    const gquic_rtt_t *rtt;

    struct {
        u_int64_t lost_packets;
        u_int64_t lost_bytes;
    } stat;

    // 最大的packet号
    u_int64_t largest_sent_pn;

    // 确认的最大packet号
    u_int64_t largest_acked_pn;

    struct {
        // 丢包发生时发送的最大packet号
        u_int64_t largest_sent;

        // 丢包发生时是否处于慢启动状态
        bool in_slow_start;
    } at_loss;

    // 是否将丢包时的拥塞窗口作为慢启动门限
    bool slow_start_large_reduction;

    // 拥塞窗口
    u_int64_t cwnd;
    u_int64_t min_cwnd;
    u_int64_t max_cwnd;

    // 慢启动门限
    u_int64_t slow_start_threshold;

    // 连接数
    int conn_count;

    // 确认接收的packet数量
    u_int64_t acked_packets_count;

    // 初始拥塞窗口大小
    u_int64_t initial_cwnd;

    // 初始最大拥塞窗口大小
    u_int64_t initial_max_cwnd;
    
    // 最小慢启动退出窗口
    u_int64_t min_slow_start_exit_wnd;
};

/**
 * congestion cubic 初始化
 * 
 * @param cubic: congestion cubic
 *
 * @return exception
 */
gquic_exception_t gquic_cong_cubic_init(gquic_cong_cubic_t *const cubic);

/**
 * congestion cubic 构造
 * 
 * @param cubic: congestion cubic
 * @param rtt: RTT
 * @param initial_cwnd: 初始拥塞窗口
 * @param initial_max_cwnd: 设定的最大拥塞窗口
 * 
 * @return exception
 */
gquic_exception_t gquic_cong_cubic_ctor(gquic_cong_cubic_t *const cubic,
                                        const gquic_rtt_t *const rtt, const u_int64_t initial_cwnd, const u_int64_t initial_max_cwnd);

/**
 * 计算下次发送数据的时间间隔
 *
 * @param cubic: congestion cubic
 * @param infly_bytes: 尚未被ACK frame确认的字节数
 *
 * @return 时间间隔
 */
u_int64_t gquic_cong_cubic_time_util_send(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes);

/**
 * 发送一个packet后congestion cubic的相关处理
 *
 * @param cubic: congestion cubic
 * @param pn: packet号
 * @param bytes: packet所包含数据的大小
 * @param is_retrans: 发送的packet是否为重发
 *
 * @return exception
 */
gquic_exception_t gquic_cong_cubic_on_packet_sent(gquic_cong_cubic_t *const cubic, const u_int64_t pn, const u_int64_t bytes, bool is_retrans);

/**
 * 判断当前情况下congestion cubic是否允许发送数据
 *
 * @param cubic: congestion cubic
 * @param infly_bytes: 未确认送达的数据大小
 *
 * @return 是否允许发送数据
 */
bool gquic_cong_cubic_allowable_send(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes);

/**
 * 当QUIC接收到ACK frame后，计算新的拥塞窗口
 * 
 * @param cubic: congestion cubic
 * @param pn: packet号
 * @param acked_bytes: 确认的数据大小
 * @param infly: 未确认的数据大小
 * @param event_time: 接收到ACK frame的时间
 *
 * @return exception
 */
gquic_exception_t gquic_cong_cubic_on_packet_acked(gquic_cong_cubic_t *const cubic,
                                                   const u_int64_t pn, const u_int64_t acked_bytes, const u_int64_t infly, const u_int64_t event_time);

/**
 * 当QUIC探知到丢包后，计算新的拥塞窗口
 *
 * @param cubic: congestion cubic
 * @param pn: packet号
 * @param lost_bytes: 确认丢失的数据大小
 * @param infly: 未确认的数据大小
 *
 * @return exception
 */
gquic_exception_t gquic_cong_cubic_on_packet_lost(gquic_cong_cubic_t *const cubic,
                                                  const u_int64_t pn, const u_int64_t lost_bytes, const u_int64_t infly);

/**
 * 当前congestion cubic是否处于恢复阶段
 * 
 * @param cubic: congestion cubic
 * 
 * @return 是否处于恢复阶段
 */
static inline bool gquic_cong_cubic_in_recovery(const gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        return false;
    }

    return cubic->largest_acked_pn != (u_int64_t) -1 && cubic->largest_acked_pn <= cubic->at_loss.largest_sent;
}

/**
 * 当前congestion cubic是否处于慢启动阶段
 * 
 * @param cubic: congestion cubic
 * 
 * @return 是否处于慢启动阶段
 */
static inline bool gquic_cong_cubic_in_slow_start(const gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        return false;
    }

    // 当拥塞控制窗口如果小于慢启动门限时，则congestion cubic处于慢启动阶段
    return cubic->cwnd < cubic->slow_start_threshold;
}

/**
 * congestion cubic尝试退出慢启动阶段
 *
 * @param cubic: congestion cubic
 *
 * @return exception
 */
static inline gquic_exception_t gquic_cong_cubic_try_exit_slow_start(gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }

    // 如果当前congestion cubic处于慢启动状态
    // 并且在慢启动阶段判断当前状态应选择退出慢启动状态
    // 则将慢启动门限设置为当前拥塞窗口
    if (gquic_cong_cubic_in_slow_start(cubic)
        && gquic_hybrid_slow_start_should_exit(&cubic->hybrid_slow_start, cubic->rtt->latest, cubic->rtt->min, cubic->cwnd / 1460)) {
        cubic->slow_start_threshold = cubic->cwnd;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#endif
