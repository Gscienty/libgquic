/* include/frame/crypto.h CRYPTO frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_CRYPTO_H
#define _LIBGQUIC_FRAME_CRYPTO_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_crypto_s gquic_frame_crypto_t;
struct gquic_frame_crypto_s {
    u_int64_t off;
    u_int64_t len;

    void *data;
};

/**
 * 生成CRYPTO frame
 * 
 * @return frame_storage: CRYPTO frame
 * @return: exception
 */
gquic_exception_t gquic_frame_crypto_alloc(gquic_frame_crypto_t **const frame_storage);

#endif
