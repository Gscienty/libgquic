#ifndef _LIBGQUIC_FRAME_DATA_BLOCKED_H
#define _LIBGQUIC_FRAME_DATA_BLOCKED_H

#include "util/varint.h"

typedef struct gquic_frame_data_blocked_s gquic_frame_data_blocked_t;
struct gquic_frame_data_blocked_s {
    u_int64_t limit;
};

int gquic_frame_data_blocked_alloc(gquic_frame_data_blocked_t **const frame_storage);

#endif
