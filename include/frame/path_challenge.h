#ifndef _LIBGQUIC_FRAME_PATH_CHALLENGE_H
#define _LIBGQUIC_FRAME_PATH_CHALLENGE_H

#include <sys/types.h>

typedef struct gquic_frame_path_challenge_s gquic_frame_path_challenge_t;
struct gquic_frame_path_challenge_s {
    u_int8_t data[8];
};

gquic_frame_path_challenge_t *gquic_frame_path_challenge_alloc();

#endif
