#ifndef _LIBGQUIC_FRAME_MAX_STREAM_DATA_H
#define _LIBGQUIC_FRAME_MAX_STREAM_DATA_H

#include "util/varint.h"
#include "streams/type.h"

typedef struct gquic_frame_max_stream_data_s gquic_frame_max_stream_data_t;
struct gquic_frame_max_stream_data_s {
    u_int64_t id;
    u_int64_t max;
};

gquic_frame_max_stream_data_t *gquic_frame_max_stream_data_alloc();

#endif
