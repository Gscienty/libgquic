#ifndef _LIBGQUIC_CONG_CUBIC_H
#define _LIBGQUIC_CONG_CUBIC_H

#include "util/prr.h"
#include "util/rtt.h"
#include "util/cubic.h"
#include "cong/hybrid_slow_start.h"
#include <stddef.h>

typedef struct gquic_cong_cubic_s gquic_cong_cubic_t;
struct gquic_cong_cubic_s {
    gquic_cong_bybrid_slow_start_t hybrid_slow_start;
    gquic_prr_t prr;
    const gquic_rtt_t *rtt;
    gquic_cubic_t cubic;
    struct {
        u_int64_t lost_packets;
        u_int64_t lost_bytes;
    } stat;
    int disable_prr;
    u_int64_t largest_sent_pn;
    u_int64_t largest_acked_pn;
    u_int64_t largest_sent_last_cut;
    int last_cut_slow_start_exited;
    int slow_start_large_reduction;
    u_int64_t cwnd;
    u_int64_t min_cwnd;
    u_int64_t max_cwnd;
    u_int64_t slow_start_threshold;
    int conn_count;
    u_int64_t acked_packets_count;
    u_int64_t initial_cwnd;
    u_int64_t initial_max_cwnd;
    u_int64_t min_slow_start_exit_wnd;
};

int gquic_cong_cubic_init(gquic_cong_cubic_t *const cubic);
u_int64_t gquic_cong_cubic_time_util_send(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes);
int gquic_cong_cubic_on_packet_sent(gquic_cong_cubic_t *const cubic,
                                    const u_int64_t pn,
                                    const u_int64_t bytes,
                                    int is_retrans);
int gquic_cong_cubic_allowable_send(gquic_cong_cubic_t *const cubic,
                                    const u_int64_t infly_bytes);
int gquic_cong_cubic_on_packet_acked(gquic_cong_cubic_t *const cubic,
                                     const u_int64_t pn,
                                     const u_int64_t acked_bytes,
                                     const u_int64_t infly,
                                     const u_int64_t event_time);
int gquic_cong_cubic_on_packet_lost(gquic_cong_cubic_t *const cubic,
                                    const u_int64_t pn,
                                    const u_int64_t lost_bytes,
                                    const u_int64_t infly);

static inline int gquic_cong_cubic_in_recovery(const gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    return cubic->largest_acked_pn != (u_int64_t) -1
        && cubic->largest_acked_pn <= cubic->largest_sent_last_cut;
}

static inline int gquic_cong_cubic_in_slow_start(const gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    return cubic->cwnd < cubic->slow_start_threshold;
}

static inline int gquic_cong_cubic_try_exit_slow_start(gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    if (gquic_cong_cubic_in_slow_start(cubic)
        && gquic_hybrid_slow_start_should_exit(&cubic->hybrid_slow_start,
                                               cubic->rtt->latest,
                                               cubic->rtt->min,
                                               cubic->cwnd / 1460)) {
        gquic_cong_cubic_try_exit_slow_start(cubic);
    }
    return 0;
}

#endif
