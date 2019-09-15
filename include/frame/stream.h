#ifndef _LIBGQUIC_FRAME_STREAM_H
#define _LIBGQUIC_FRAME_STREAM_H

#include "util/varint.h"
#include "streams/type.h"

typedef struct gquic_frame_stream_s gquic_frame_stream_t;
struct gquic_frame_stream_s {
    gquic_stream_id_t id;
    gquic_util_varint_t off;
    gquic_util_varint_t len;
    void *data;
};

gquic_frame_stream_t *gquic_frame_stream_alloc();

#endif
