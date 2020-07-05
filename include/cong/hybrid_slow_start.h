/* include/cong/hybrid_slow_start.h 慢启动模块定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_CONG_HYBIRD_SLOW_START_H
#define _LIBGQUIC_CONG_HYBIRD_SLOW_START_H

#include <sys/types.h>
#include <stdbool.h>
#include "exception.h"

/**
 * 慢启动实现模块
 */
typedef struct gquic_cong_hybrid_slow_start_s gquic_cong_bybrid_slow_start_t;
struct gquic_cong_hybrid_slow_start_s {

    // 开始慢启动阶段时的packet号
    u_int64_t end_pn;

    // 记录最后发送的packet号, 当慢启动开始时，将end_pn置为该值
    u_int64_t last_sent_pn;

    // 当前是否处于慢启动阶段
    bool started;

    // 慢启动阶段最小RTT时间
    u_int64_t current_min_rtt;

    // RTT样本数量
    u_int32_t rtt_sample_count;

    // 慢启动阶段是否已探知该阶段的窗口大小
    bool hystart_found;
};

/**
 * 慢启动模块初始化
 *
 * @param slowstart: slowstart
 * 
 * @return exception
 */
gquic_exception_t gquic_cong_hybrid_slow_start_init(gquic_cong_bybrid_slow_start_t *const slowstart);

/**
 * 判断当前状态下是否应退出慢启动阶段
 *
 * @param slowstart: slowstart
 * @param last_rtt: 最新的RTT取样
 * @param min_rtt: 最小的RTT取样
 * @param cwnd: 当前拥塞窗口
 *
 * @return 是否应退出慢启动阶段
 */
bool gquic_hybrid_slow_start_should_exit(gquic_cong_bybrid_slow_start_t *const slowstart,
                                         const u_int64_t last_rtt, const u_int64_t min_rtt, const u_int64_t cwnd);

#endif
