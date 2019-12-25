#ifndef _LIBGQUIC_FRAME_STREAM_H
#define _LIBGQUIC_FRAME_STREAM_H

#include "util/varint.h"
#include "streams/type.h"

typedef struct gquic_frame_stream_s gquic_frame_stream_t;
struct gquic_frame_stream_s {
    u_int64_t id;
    u_int64_t off;
    u_int64_t len;
    void *data;
};

gquic_frame_stream_t *gquic_frame_stream_alloc();

#endif
