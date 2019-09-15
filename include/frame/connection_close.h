#ifndef _LIBGQUIC_FRAME_CONNECTION_CLOSE_H
#define _LIBGQUIC_FRAME_CONNECTION_CLOSE_H

#include "util/varint.h"

typedef struct gquic_frame_connection_close_s gquic_frame_connecion_close_t;
struct gquic_frame_connection_close_s {
    gquic_util_varint_t errcode;
    gquic_util_varint_t type;
    gquic_util_varint_t phase_len;
    char *phase;
};

gquic_frame_connecion_close_t *gquic_frame_connection_close_alloc();

#endif
