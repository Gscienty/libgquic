#ifndef _LIBGQUIC_FRAME_PATH_RESPONSE_H
#define _LIBGQUIC_FRAME_PATH_RESPONSE_H

#include <sys/types.h>

typedef struct gquic_frame_path_response_s gquic_frame_path_response_t;
struct gquic_frame_path_response_s {
    u_int8_t data[8];
};

int gquic_frame_path_response_alloc(gquic_frame_path_response_t **const frame_storage);

#endif
