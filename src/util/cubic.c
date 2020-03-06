#include "util/cubic.h"
#include <stddef.h>
#include <math.h>

static float gquic_cubic_beta(const gquic_cubic_t *const);
static float gquic_cubic_alpha(const gquic_cubic_t *const);
static float gquic_cubic_bata_last_max(const gquic_cubic_t *const);

int gquic_cubic_init(gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        return -1;
    }
    cubic->conn_count = 1;
    cubic->epoch = 0;
    cubic->last_max_cwnd = 0;
    cubic->ack_bytes_count = 0;
    cubic->est_cwnd = 0;
    cubic->origin_point_cwnd = 0;
    cubic->origin_point_time = 0;
    cubic->last_target_cwnd = 0;

    return 0;
}

static float gquic_cubic_beta(const gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    return (cubic->conn_count - 1 + 0.7) / cubic->conn_count;
}

static float gquic_cubic_alpha(const gquic_cubic_t *const cubic) {
    float b = 0;
    if (cubic == NULL) {
        return 0;
    }
    b = gquic_cubic_beta(cubic);
    return 3 * cubic->conn_count * cubic->conn_count * (1 - b) / (1 + b);
}

static float gquic_cubic_bata_last_max(const gquic_cubic_t *const cubic) {
    if (cubic == NULL) {
        return 0;
    }
    return (cubic->conn_count - 1 + 0.85) / cubic->conn_count;
}

u_int64_t gquic_cubic_cwnd_after_packet_loss(gquic_cubic_t *const cubic, const u_int64_t cwnd) {
    if (cubic == NULL) {
        return 0;
    }
    if (cwnd + 1460 < cubic->last_max_cwnd) {
        cubic->last_max_cwnd = gquic_cubic_bata_last_max(cubic) * cwnd;
    }
    else {
        cubic->last_max_cwnd = cwnd;
    }
    cubic->epoch = 0;
    return cwnd * gquic_cubic_beta(cubic);
}

u_int64_t gquic_cubic_cwnd_after_packet_ack(gquic_cubic_t *const cubic,
                                            const u_int64_t acked_bytes,
                                            const u_int64_t cwnd,
                                            const u_int64_t delay_min,
                                            const u_int64_t event_time) {
    u_int64_t elapsed_time = 0;
    int64_t offset = 0;
    u_int64_t delta_cwnd = 0;
    u_int64_t ret = 0;
    if (cubic == NULL) {
        return 0;
    }
    cubic->ack_bytes_count += acked_bytes;
    if (cubic->epoch == 0) {
        cubic->epoch = event_time;
        cubic->ack_bytes_count = acked_bytes;
        cubic->est_cwnd = cwnd;
        if (cubic->last_max_cwnd <= cwnd) {
            cubic->origin_point_time = 0;
            cubic->origin_point_cwnd = cwnd;
        }
        else {
            cubic->origin_point_time = cbrt((1L << 40) / 410 / 1460 * (cubic->last_max_cwnd - cwnd));
            cubic->origin_point_cwnd = cubic->last_max_cwnd;
        }
    }
    elapsed_time = ((event_time + delay_min - cubic->epoch) << 10) / 1000;
    offset = cubic->origin_point_time - elapsed_time;
    if (offset < 0) {
        offset = -offset;
    }
    delta_cwnd = ((410 * offset * offset * offset) * 1460) >> 40;
    if (elapsed_time > cubic->origin_point_time) {
        ret = cubic->origin_point_cwnd + delta_cwnd;
    }
    else {
        ret = cubic->origin_point_cwnd - delta_cwnd;
    }
    ret = ret < cwnd + cubic->ack_bytes_count / 2 ? ret : cwnd + cubic->ack_bytes_count / 2;

    cubic->est_cwnd += cubic->ack_bytes_count * gquic_cubic_alpha(cubic) * 1460 / cubic->est_cwnd;
    cubic->ack_bytes_count = 0;
    cubic->last_target_cwnd = ret;

    if (ret < cubic->est_cwnd) {
        ret = cubic->est_cwnd;
    }

    return ret;
}
