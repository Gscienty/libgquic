#ifndef _LIBGQUIC_FRAME_RETIRE_CONNECTION_ID_H
#define _LIBGQUIC_FRAME_RETIRE_CONNECTION_ID_H

#include "util/varint.h"

typedef struct gquic_frame_retire_connection_id_s gquic_frame_retire_connection_id_t;
struct gquic_frame_retire_connection_id_s {
    gquic_util_varint_t seq;
};

gquic_frame_retire_connection_id_t *gquic_frame_retire_connection_id_alloc();

#endif
