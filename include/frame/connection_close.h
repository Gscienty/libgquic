/* include/frame/connection_close.h CONNECTION_CLOSE frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_CONNECTION_CLOSE_H
#define _LIBGQUIC_FRAME_CONNECTION_CLOSE_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_connection_close_s gquic_frame_connection_close_t;
struct gquic_frame_connection_close_s {
    u_int64_t errcode;
    u_int64_t type;
    u_int64_t phase_len;
    char *phase;
};

/**
 * 生成CONNECTION_CLOSE frame
 * 
 * @return frame_storage: CONNECTION_CLOSE frame
 * @return: exception
 */
gquic_exception_t gquic_frame_connection_close_alloc(gquic_frame_connection_close_t **const frame_storage);

#endif
