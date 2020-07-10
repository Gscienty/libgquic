/* include/frame/max_stream_data.h MAX_STREAM_DATA frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_MAX_STREAM_DATA_H
#define _LIBGQUIC_FRAME_MAX_STREAM_DATA_H

#include "exception.h"

#include "util/varint.h"
#include "streams/type.h"

typedef struct gquic_frame_max_stream_data_s gquic_frame_max_stream_data_t;
struct gquic_frame_max_stream_data_s {
    u_int64_t id;
    u_int64_t max;
};

/**
 * 生成MAX_STREAM_DATA frame
 * 
 * @return frame_storage: MAX_STREAM_DATA frame
 * @return: exception
 */
gquic_exception_t gquic_frame_max_stream_data_alloc(gquic_frame_max_stream_data_t **const frame_storage);

#endif
