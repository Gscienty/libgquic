#ifndef _LIBGQUIC_FRAME_CRYPTO_H
#define _LIBGQUIC_FRAME_CRYPTO_H

#include "util/varint.h"

typedef struct gquic_frame_crypto_s gquic_frame_crypto_t;
struct gquic_frame_crypto_s {
    gquic_util_varint_t off;
    gquic_util_varint_t len;

    void *data;
};

gquic_frame_crypto_t *gquic_frame_crypto_alloc(size_t size);

#endif
