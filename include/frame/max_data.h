#ifndef _LIBGQUIC_FRAME_MAX_DATA_H
#define _LIBGQUIC_FRAME_MAX_DATA_H

#include "util/varint.h"

typedef struct gquic_frame_max_data_s gquic_frame_max_data_t;
struct gquic_frame_max_data_s {
    u_int64_t max;
};

gquic_frame_max_data_t *gquic_frame_max_data_alloc();

#endif
