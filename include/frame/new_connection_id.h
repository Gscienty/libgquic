#ifndef _LIBGQUIC_FRAME_NEW_CONNECTION_ID_H
#define _LIBGQUIC_FRAME_NEW_CONNECTION_ID_H

#include "util/varint.h"

typedef struct gquic_frame_new_connection_id_s gquic_frame_new_connection_id_t;
struct gquic_frame_new_connection_id_s {
    u_int64_t seq;
    u_int64_t prior;
    unsigned char len;
    unsigned char conn_id[20];
    unsigned char token[16];
};

int gquic_frame_new_connection_id_alloc(gquic_frame_new_connection_id_t **const frame_storage);

#endif
