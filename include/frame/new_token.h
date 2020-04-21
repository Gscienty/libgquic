#ifndef _LIBGQUIC_FRAME_NEW_TOKEN_H
#define _LIBGQUIC_FRAME_NEW_TOKEN_H

#include "util/varint.h"

typedef struct gquic_frame_new_token_s gquic_frame_new_token_t;
struct gquic_frame_new_token_s {
    u_int64_t len;
    void *token;
};

int gquic_frame_new_token_alloc(gquic_frame_new_token_t **const frame_storage);

#endif
