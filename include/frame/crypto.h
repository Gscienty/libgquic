#ifndef _LIBGQUIC_FRAME_CRYPTO_H
#define _LIBGQUIC_FRAME_CRYPTO_H

#include "util/varint.h"

typedef struct gquic_frame_crypto_s gquic_frame_crypto_t;
struct gquic_frame_crypto_s {
    u_int64_t off;
    u_int64_t len;

    void *data;
};

int gquic_frame_crypto_alloc(gquic_frame_crypto_t **const frame_storage);

#endif
