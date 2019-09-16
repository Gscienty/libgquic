#ifndef _LIBGQUIC_FRAME_MAX_STREAMS_H
#define _LIBGQUIC_FRAME_MAX_STREAMS_H

#include "util/varint.h"

typedef struct gquic_frame_max_streams_s gquic_frame_max_streams_t;
struct gquic_frame_max_streams_s {
    gquic_varint_t max;
};

gquic_frame_max_streams_t *gquic_frame_max_streams_alloc();

#endif
