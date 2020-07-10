/* include/frame/new_token.h NEW_TOKEN frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_NEW_TOKEN_H
#define _LIBGQUIC_FRAME_NEW_TOKEN_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_new_token_s gquic_frame_new_token_t;
struct gquic_frame_new_token_s {
    u_int64_t len;
    void *token;
};

/**
 * 生成NEW_TOKEN frame
 * 
 * @return frame_storage: NEW_TOKEN frame
 * @return: exception
 */
gquic_exception_t gquic_frame_new_token_alloc(gquic_frame_new_token_t **const frame_storage);

#endif
