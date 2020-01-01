#ifndef _LIBGQUIC_EVENT_EVENT_H
#define _LIBGQUIC_EVENT_EVENT_H

#include "util/list.h"
#include <sys/types.h>

#define GQUIC_EVENT_PACKET_SENT 0x01
#define GQUIC_EVENT_PACKET_RECEIVED 0x02
#define GQUIC_EVENT_PACKET_LOST 0x04

typedef struct gquic_event_s gquic_event_t;
struct gquic_event_s {
    u_int64_t time;
    u_int8_t type;
    struct {
        u_int64_t min_rtt;
        u_int64_t smooth_rtt;
        u_int64_t latest_rtt;
        u_int64_t infly_bytes;
        u_int64_t cwnd;
        int in_slow_start;
        int in_recovery;
    } state;
    u_int8_t enc_lv;
    u_int64_t pn;
    u_int64_t p_size;
    const gquic_list_t *frames;
};

#endif
