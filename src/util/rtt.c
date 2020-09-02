/* include/util/rtt.h RTT
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "util/rtt.h"
#include "exception.h"
#include <math.h>
#include <unistd.h>

gquic_exception_t gquic_rtt_init(gquic_rtt_t *rtt) {
    if (rtt == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    rtt->latest = 0;
    rtt->max_delay = 0;
    rtt->mean_dev = 0;
    rtt->min = 0;
    rtt->smooth = 0;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_rtt_update(gquic_rtt_t *rtt, const u_int64_t send, const u_int64_t ack) {
    if (rtt == NULL || send <= 0) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (rtt->min == 0 || rtt->min > send) {
        rtt->min = send;
    }
    u_int64_t sample = send;
    if (sample - rtt->min >= ack) {
        sample -= ack;
    }
    rtt->latest = sample;
    if (rtt->smooth == 0) {
        rtt->smooth = sample;
        rtt->mean_dev = sample / 2;
    }
    else {
        rtt->mean_dev = 0.75 * rtt->mean_dev + 0.25 * fabs((double) (rtt->smooth - sample));
        rtt->smooth = 0.875 * rtt->smooth + 0.125 * sample;
    }

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

#define __MAX(a, b) ((a) > (b) ? (a) : (b))

u_int64_t gquic_time_pto(const gquic_rtt_t *const rtt, const int inc_max_ack_delay) {
    u_int64_t pto = 0;
    if (rtt == NULL) {
        return 0;
    }
    if (rtt->smooth == 0) {
        return 2 * 100 * 1000;
    }
    pto = rtt->smooth + __MAX(4 * rtt->mean_dev, 1000);
    if (inc_max_ack_delay) {
        pto += rtt->max_delay;
    }

    return pto;
}
