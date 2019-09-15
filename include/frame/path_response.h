#ifndef _LIBGQUIC_FRAME_PATH_RESPONSE_H
#define _LIBGQUIC_FRAME_PATH_RESPONSE_H

typedef struct gquic_frame_path_response_s gquic_frame_path_response_t;
struct gquic_frame_path_response_s {
    unsigned char data[8];
};

gquic_frame_path_response_t *gquic_frame_path_response_alloc();

#endif
