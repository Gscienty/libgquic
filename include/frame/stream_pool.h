#ifndef _LIBGQUIC_FRAME_STREAM_POOL_H
#define _LIBGQUIC_FRAME_STREAM_POOL_H

#include "frame/stream.h"

int gquic_stream_frame_pool_init();
int gquic_stream_frame_pool_put(gquic_frame_stream_t *const stream);
int gquic_stream_frame_pool_get(gquic_frame_stream_t **const stream);

#endif
