#ifndef _LIBGQUIC_UTIL_RTT_H
#define _LIBGQUIC_UTIL_RTT_H

#include <sys/time.h>
#include <sys/types.h>

typedef struct gquic_rtt_s gquic_rtt_t;
struct gquic_rtt_s {
    suseconds_t min;
    suseconds_t latest;
    suseconds_t smooth;
    suseconds_t mean_dev;

    suseconds_t max_delay;
};

int gquic_rtt_init(gquic_rtt_t *rtt);

int gquic_rtt_update(gquic_rtt_t *rtt, const suseconds_t send, const suseconds_t ack);

suseconds_t gquic_time_since(const struct timeval *time);

#endif
