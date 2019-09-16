#ifndef _LIBGQUIC_FRAME_STREAMS_BLOCKED_H
#define _LIBGQUIC_FRAME_STREAMS_BLOCKED_H

#include "util/varint.h"

typedef struct gquic_frame_streams_blocked_s gquic_frame_streams_blocked_t;
struct gquic_frame_streams_blocked_s {
    gquic_varint_t limit;
};

gquic_frame_streams_blocked_t *gquic_frame_streams_blocked_alloc();

#endif
