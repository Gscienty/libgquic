#ifndef _LIBGQUIC_FRAME_NEW_TOKEN_H
#define _LIBGQUIC_FRAME_NEW_TOKEN_H

#include "util/varint.h"

typedef struct gquic_frame_new_token_s gquic_frame_new_token_t;
struct gquic_frame_new_token_s {
    gquic_varint_t len;
    void *token;
};

gquic_frame_new_token_t *gquic_frame_new_token_alloc();

#endif
