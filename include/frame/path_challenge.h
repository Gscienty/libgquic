#ifndef _LIBGQUIC_FRAME_PATH_CHALLENGE_H
#define _LIBGQUIC_FRAME_PATH_CHALLENGE_H

typedef struct gquic_frame_path_challenge_s gquic_frame_path_challenge_t;
struct gquic_frame_path_challenge_s {
    unsigned char data[8];
};

gquic_frame_path_challenge_t *gquic_frame_path_challenge_alloc();

#endif
