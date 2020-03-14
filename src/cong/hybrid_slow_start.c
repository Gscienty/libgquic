#include "cong/hybrid_slow_start.h"
#include "exception.h"
#include <stddef.h>

int gquic_cong_hybrid_slow_start_init(gquic_cong_bybrid_slow_start_t *const slowstart) {
    if (slowstart == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    slowstart->current_min_rtt = 0;
    slowstart->end_pn = 0;
    slowstart->hystart_found = 0;
    slowstart->last_sent_pn = 0;
    slowstart->rtt_sample_count = 0;
    slowstart->started = 0;

    return GQUIC_SUCCESS;
}

int gquic_hybrid_slow_start_start_recv_round(gquic_cong_bybrid_slow_start_t *const slowstart, const u_int64_t last_sent) {
    if (slowstart == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    slowstart->end_pn = last_sent;
    slowstart->current_min_rtt = 0;
    slowstart->rtt_sample_count = 0;
    slowstart->started = 1;
    return GQUIC_SUCCESS;
}

int gquic_hybrid_slow_start_should_exit(gquic_cong_bybrid_slow_start_t *const slowstart,
                                        const u_int64_t last_rtt,
                                        const u_int64_t min_rtt,
                                        const u_int64_t cwnd) {
    u_int64_t min_rtt_increase_threshold = 0;
    if (slowstart == NULL) {
        return 0;
    }
    if (!slowstart->started) {
        gquic_hybrid_slow_start_start_recv_round(slowstart, slowstart->last_sent_pn);
    }
    if (slowstart->hystart_found) {
        return 1;
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
            slowstart->hystart_found = 1;
        }
    }
    return cwnd >= 16 && slowstart->hystart_found;
}
