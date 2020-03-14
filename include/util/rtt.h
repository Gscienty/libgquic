#ifndef _LIBGQUIC_UTIL_RTT_H
#define _LIBGQUIC_UTIL_RTT_H

#include <sys/time.h>
#include <sys/types.h>

typedef struct gquic_rtt_s gquic_rtt_t;
struct gquic_rtt_s {
    u_int64_t min;
    u_int64_t latest;
    u_int64_t smooth;
    u_int64_t mean_dev;

    u_int64_t max_delay;
};

int gquic_rtt_init(gquic_rtt_t *rtt);
int gquic_rtt_update(gquic_rtt_t *const rtt, const u_int64_t send, const u_int64_t ack);
u_int64_t gquic_time_pto(const gquic_rtt_t *const rtt, const int inc_max_ack_delay);

#endif
