/* src/cong/hybrid_slow_start.c 慢启动模块实现
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "cong/hybrid_slow_start.h"
#include "exception.h"
#include <stddef.h>

/**
 * 开始慢启动阶段
 * 
 * @param slowstart: slowstart
 * @param last_sent: 开始慢启动阶段时发送的packet号
 *
 * @return exception
 */
static gquic_exception_t gquic_hybrid_slow_start_start_recv_round(gquic_cong_bybrid_slow_start_t *const slowstart, const u_int64_t last_sent);

gquic_exception_t gquic_cong_hybrid_slow_start_init(gquic_cong_bybrid_slow_start_t *const slowstart) {
    if (slowstart == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    slowstart->current_min_rtt = 0;
    slowstart->end_pn = 0;
    slowstart->hystart_found = false;
    slowstart->last_sent_pn = 0;
    slowstart->rtt_sample_count = 0;
    slowstart->started = false;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

static gquic_exception_t gquic_hybrid_slow_start_start_recv_round(gquic_cong_bybrid_slow_start_t *const slowstart, const u_int64_t last_sent) {
    if (slowstart == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    slowstart->end_pn = last_sent;
    slowstart->current_min_rtt = 0;
    slowstart->rtt_sample_count = 0;
    slowstart->started = true;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

bool gquic_hybrid_slow_start_should_exit(gquic_cong_bybrid_slow_start_t *const slowstart,
                                         const u_int64_t last_rtt, const u_int64_t min_rtt, const u_int64_t cwnd) {
    u_int64_t min_rtt_increase_threshold = 0;
    if (slowstart == NULL) {
        return false;
    }

    // 因此如果 started == false，则应启动慢启动阶段
    if (!slowstart->started) {
        gquic_hybrid_slow_start_start_recv_round(slowstart, slowstart->last_sent_pn);
    }

    // hystart_found == true 则意味着慢启动阶段已经结束
    if (slowstart->hystart_found) {
        return true;
    }

    slowstart->rtt_sample_count++;
    if (slowstart->rtt_sample_count <= 8) {
        if (slowstart->current_min_rtt == 0 || slowstart->current_min_rtt > last_rtt) {
            slowstart->current_min_rtt = last_rtt;
        }
    }
    if (slowstart->rtt_sample_count == 8) {
        min_rtt_increase_threshold = min_rtt >> 3;
        min_rtt_increase_threshold = min_rtt_increase_threshold < 16000 ? min_rtt_increase_threshold : 16000;
        min_rtt_increase_threshold = min_rtt_increase_threshold < 4000 ? 4000 : min_rtt_increase_threshold;

        if (slowstart->current_min_rtt > (min_rtt + min_rtt_increase_threshold)) {
            slowstart->hystart_found = true;
        }
    }
    return cwnd >= 16 && slowstart->hystart_found;
}
