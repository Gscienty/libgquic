#include "cong/cubic.h"
#include "exception.h"

static int gquic_cong_cubic_try_increase_cwnd(gquic_cong_cubic_t *const, const u_int64_t, const u_int64_t, const u_int64_t);
static int gquic_cong_cubic_is_cwnd_limited(gquic_cong_cubic_t *const, const u_int64_t);

int gquic_cong_cubic_init(gquic_cong_cubic_t *const cubic) {
    if (cubic == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_cong_hybrid_slow_start_init(&cubic->hybrid_slow_start);
    gquic_prr_init(&cubic->prr);
    cubic->rtt = NULL;
    gquic_cubic_init(&cubic->cubic);
    cubic->stat.lost_bytes = 0;
    cubic->stat.lost_packets = 0;
    cubic->disable_prr = 0;
    cubic->largest_sent_pn = -1;
    cubic->largest_acked_pn = -1;
    cubic->largest_sent_last_cut = -1;
    cubic->last_cut_slow_start_exited = 0;
    cubic->slow_start_large_reduction = 0;
    cubic->cwnd = 0;
    cubic->min_cwnd = 2 * 1460;
    cubic->max_cwnd = 0;
    cubic->slow_start_threshold = 0;
    cubic->conn_count = 0;
    cubic->acked_packets_count = 0;
    cubic->initial_cwnd = 0;
    cubic->initial_max_cwnd = 0;
    cubic->min_slow_start_exit_wnd = 0;

    return GQUIC_SUCCESS;
}

int gquic_cong_cubic_ctor(gquic_cong_cubic_t *const cubic, const gquic_rtt_t *const rtt, const u_int64_t initial_cwnd, const u_int64_t initial_max_cwnd) {
    if (cubic == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    cubic->initial_cwnd = initial_cwnd;
    cubic->initial_max_cwnd = initial_max_cwnd;
    cubic->cwnd = initial_cwnd;
    cubic->min_cwnd = 1460 * 2;
    cubic->slow_start_threshold = initial_cwnd;
    cubic->max_cwnd = initial_cwnd;
    cubic->conn_count = 1;
    cubic->rtt = rtt;
    gquic_cubic_ctor(&cubic->cubic);

    return GQUIC_SUCCESS;
}

u_int64_t gquic_cong_cubic_time_util_send(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes) {
    if (cubic == NULL) {
        return 0;
    }
    if (!cubic->disable_prr && gquic_cong_cubic_in_recovery(cubic)) {
        if (gquic_prr_allowable_send(&cubic->prr, cubic->cwnd, infly_bytes, cubic->slow_start_threshold)) {
            return 0;
        }
    }
    return cubic->rtt->smooth * 1460 / (2 * cubic->cwnd);
}

int gquic_cong_cubic_on_packet_sent(gquic_cong_cubic_t *const cubic,
                                    const u_int64_t pn,
                                    const u_int64_t bytes,
                                    int is_retrans) {
    if (cubic == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (!is_retrans) {
        return GQUIC_SUCCESS;
    }
    if (gquic_cong_cubic_in_recovery(cubic)) {
        cubic->prr.sent_bytes += bytes;
    }
    cubic->largest_sent_pn = pn;
    cubic->hybrid_slow_start.last_sent_pn = pn;
    return GQUIC_SUCCESS;
}

int gquic_cong_cubic_allowable_send(gquic_cong_cubic_t *const cubic,
                                    const u_int64_t infly_bytes) {
    if (cubic == NULL) {
        return 0;
    }
    if (!cubic->disable_prr && gquic_cong_cubic_in_recovery(cubic)) {
        return gquic_prr_allowable_send(&cubic->prr, cubic->cwnd, infly_bytes, cubic->slow_start_threshold);
    }
    return infly_bytes < cubic->cwnd;
}

int gquic_cong_cubic_on_packet_acked(gquic_cong_cubic_t *const cubic,
                                     const u_int64_t pn,
                                     const u_int64_t acked_bytes,
                                     const u_int64_t infly,
                                     const u_int64_t event_time) {
    if (cubic == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    cubic->largest_acked_pn = pn > cubic->largest_acked_pn ? pn : cubic->largest_acked_pn;
    if (gquic_cong_cubic_in_recovery(cubic)) {
        if (!cubic->disable_prr) {
            cubic->prr.delivered_bytes += acked_bytes;
            cubic->prr.ack_count++;
        }
        return GQUIC_SUCCESS;
    }
    gquic_cong_cubic_try_increase_cwnd(cubic, acked_bytes, infly, event_time);
    if (gquic_cong_cubic_in_slow_start(cubic)) {
        if (cubic->hybrid_slow_start.end_pn < pn) {
            cubic->hybrid_slow_start.started = 0;
        }
    }
    return GQUIC_SUCCESS;
}

static int gquic_cong_cubic_try_increase_cwnd(gquic_cong_cubic_t *const cubic,
                                              const u_int64_t ack_bytes,
                                              const u_int64_t infly,
                                              const u_int64_t event_time) {
    if (cubic == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (!gquic_cong_cubic_is_cwnd_limited(cubic, infly)) {
        cubic->cubic.epoch = 0;
        return GQUIC_SUCCESS;
    }
    if (cubic->cwnd >= cubic->max_cwnd) {
        return GQUIC_SUCCESS;
    }
    if (gquic_cong_cubic_in_slow_start(cubic)) {
        cubic->cwnd += 1460;
        return GQUIC_SUCCESS;
    }
    cubic->cwnd = gquic_cubic_cwnd_after_packet_ack(&cubic->cubic, ack_bytes, cubic->cwnd, cubic->rtt->min, event_time);
    cubic->cwnd = cubic->cwnd < cubic->max_cwnd ? cubic->cwnd : cubic->max_cwnd;
    return GQUIC_SUCCESS;
}

static int gquic_cong_cubic_is_cwnd_limited(gquic_cong_cubic_t *const cubic, const u_int64_t infly_bytes) {
    u_int64_t avail_bytes = 0;
    if (cubic == NULL) {
        return 0;
    }
    if (infly_bytes >= cubic->cwnd) {
        return 1;
    }
    avail_bytes = cubic->cwnd - infly_bytes;
    return (gquic_cong_cubic_in_slow_start(cubic)
            && infly_bytes > cubic->cwnd /2)
        || avail_bytes <= 3 * 1460;
}

int gquic_cong_cubic_on_packet_lost(gquic_cong_cubic_t *const cubic,
                                    const u_int64_t pn,
                                    const u_int64_t lost_bytes,
                                    const u_int64_t infly) {
    if (cubic == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (pn <= cubic->largest_sent_last_cut) {
        if (cubic->last_cut_slow_start_exited) {
            cubic->stat.lost_packets++;
            cubic->stat.lost_bytes += lost_bytes;
            if (cubic->slow_start_large_reduction) {
                cubic->cwnd = cubic->cwnd - lost_bytes;
                cubic->cwnd = cubic->cwnd > cubic->min_slow_start_exit_wnd ? cubic->cwnd : cubic->min_slow_start_exit_wnd;
                cubic->slow_start_threshold = cubic->cwnd;
            }
        }
        return GQUIC_SUCCESS;
    }
    cubic->last_cut_slow_start_exited = gquic_cong_cubic_in_slow_start(cubic);
    if (gquic_cong_cubic_in_slow_start(cubic)) {
        cubic->stat.lost_packets++;
    }
    if (!cubic->disable_prr) {
        gquic_prr_packet_lost(&cubic->prr, infly);
    }
    if (cubic->slow_start_large_reduction && gquic_cong_cubic_in_slow_start(cubic)) {
        if (cubic->cwnd >= 2 * cubic->initial_cwnd) {
            cubic->min_slow_start_exit_wnd = cubic->cwnd / 2;
        }
        cubic->cwnd -= 1460;
    }
    else {
        cubic->cwnd = gquic_cubic_cwnd_after_packet_loss(&cubic->cubic, cubic->cwnd);
    }
    if (cubic->cwnd < cubic->min_cwnd) {
        cubic->cwnd = cubic->min_cwnd;
    }
    cubic->slow_start_threshold = cubic->cwnd;
    cubic->largest_sent_last_cut = cubic->largest_sent_pn;
    cubic->acked_packets_count = 0;

    return GQUIC_SUCCESS;
}
