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

    gquic_list_t ranges;

    gquic_frame_ack_ecn_t ecn;
};

typedef struct gquic_frame_ack_range_s gquic_frame_ack_range_t;
struct gquic_frame_ack_range_s {
    u_int64_t gap;
    u_int64_t range;
};

int gquic_frame_ack_range_init(gquic_frame_ack_range_t *const range);

typedef struct gquic_frame_ack_block_s gquic_frame_ack_block_t;
struct gquic_frame_ack_block_s {
    u_int64_t smallest;
    u_int64_t largest;
};

gquic_frame_ack_t *gquic_frame_ack_alloc();
int gquic_frame_ack_acks_packet(const gquic_list_t *const blocks, const u_int64_t pn);
int gquic_frame_ack_ranges_to_blocks(gquic_list_t *const blocks, const gquic_frame_ack_t *const spec);
int gquic_frame_ack_ranges_from_blocks(gquic_frame_ack_t *const spec, const gquic_list_t *const blocks);

int gquic_frames_has_frame_ack(gquic_list_t *const frames);

#endif
