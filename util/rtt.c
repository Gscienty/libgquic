#include "util/rtt.h"
#include <math.h>
#include <unistd.h>

int gquic_rtt_init(gquic_rtt_t *rtt) {
    rtt->latest = 0;
    rtt->max_delay = 0;
    rtt->mean_dev = 0;
    rtt->min = 0;
    rtt->smooth = 0;
    return 0;
}

int gquic_rtt_update(gquic_rtt_t *rtt, const suseconds_t send, const suseconds_t ack) {
    if (send <= 0) {
        return -1;
    }
    if (rtt->min == 0 || rtt->min > send) {
        rtt->min = send;
    }
    suseconds_t sample = send;
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
    return 0;
}

suseconds_t gquic_time_since(const struct timeval *time) {
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) {
        return -1;
    }
    return (now.tv_sec - time->tv_sec) * 1000000 + now.tv_usec - time->tv_usec;
}

#define __MAX(a, b) ((a) > (b) ? (a) : (b))

suseconds_t gquic_time_pto(const gquic_rtt_t *const rtt, int inc_max_ack_delay) {
    suseconds_t pto = 0;
    if (rtt == NULL) {
        return -1;
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
