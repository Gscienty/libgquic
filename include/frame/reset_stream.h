#ifndef _LIBGQUIC_FRAME_RESET_STREAM_H
#define _LIBGQUIC_FRAME_RESET_STREAM_H

#include "util/varint.h"
#include "streams/type.h"

typedef struct gquic_frame_reset_stream_s gquic_frame_reset_stream_t;
struct gquic_frame_reset_stream_s {
    u_int64_t id;
    u_int64_t errcode;
    u_int64_t final_size;
};

int gquic_frame_reset_stream_alloc(gquic_frame_reset_stream_t **const frame_storage);

#endif
