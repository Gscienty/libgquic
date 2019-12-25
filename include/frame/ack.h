#ifndef _LIBGQUIC_FRAME_ACK_H
#define _LIBGQUIC_FRAME_ACK_H

#include "util/varint.h"
#include "util/list.h"

typedef struct gquic_frame_ack_ecn_s gquic_frame_ack_ecn_t;
struct gquic_frame_ack_ecn_s {
    u_int64_t ect[2];
    u_int64_t ecn_ce;
};

typedef struct gquic_frame_ack_s gquic_frame_ack_t;
struct gquic_frame_ack_s {
    u_int64_t largest_ack;
    u_int64_t delay;
    u_int64_t count;
    u_int64_t first_range;

    gquic_list_t range;

    gquic_frame_ack_ecn_t ecn;
};

typedef struct gquic_frame_ack_range_s gquic_frame_range_t;
struct gquic_frame_ack_range_s {
    u_int64_t gap;
    u_int64_t range;
};

gquic_frame_ack_t *gquic_frame_ack_alloc();

#endif
