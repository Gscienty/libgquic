/* include/frame/reset_stream.h RESET_STREAM frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_RESET_STREAM_H
#define _LIBGQUIC_FRAME_RESET_STREAM_H

#include "util/varint.h"
#include "streams/type.h"
#include "exception.h"

typedef struct gquic_frame_reset_stream_s gquic_frame_reset_stream_t;
struct gquic_frame_reset_stream_s {
    u_int64_t id;
    u_int64_t errcode;
    u_int64_t final_size;
};

/**
 * 生成RESET_STREAM frame
 * 
 * @return frame_storage: RESET_STREAM frame
 * @return: exception
 */
gquic_exception_t gquic_frame_reset_stream_alloc(gquic_frame_reset_stream_t **const frame_storage);

#endif
