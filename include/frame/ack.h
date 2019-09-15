#ifndef _LIBGQUIC_FRAME_ACK_H
#define _LIBGQUIC_FRAME_ACK_H

#include "util/varint.h"
#include "util/list.h"

typedef struct gquic_frame_ack_ecn_s gquic_frame_ack_ecn_t;
struct gquic_frame_ack_ecn_s {
    gquic_util_varint_t ect[2];
    gquic_util_varint_t ecn_ce;
};

typedef struct gquic_frame_ack_s gquic_frame_ack_t;
struct gquic_frame_ack_s {
    gquic_util_varint_t largest_ack;
    gquic_util_varint_t delay;
    gquic_util_varint_t count;
    gquic_util_varint_t first_range;

    gquic_list_t range;

    gquic_frame_ack_ecn_t ecn;
};

typedef struct gquic_frame_ack_range_s gquic_frame_range_t;
struct gquic_frame_ack_range_s {
    gquic_util_varint_t gap;
    gquic_util_varint_t range;
};

gquic_frame_ack_t *gquic_frame_ack_alloc();

#endif
