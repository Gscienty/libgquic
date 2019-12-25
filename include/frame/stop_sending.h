#ifndef _LIBGQUIC_FRAME_STOP_SENDING_H
#define _LIBGQUIC_FRAME_STOP_SENDING_H

#include "util/varint.h"
#include "streams/type.h"

typedef struct gquic_frame_stop_sending_s gquic_frame_stop_sending_t;
struct gquic_frame_stop_sending_s {
    u_int64_t id;
    u_int64_t errcode;
};

gquic_frame_stop_sending_t *gquic_frame_stop_sending_alloc();

#endif
