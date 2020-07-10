/* include/frame/streams_blocked.h STREAMS_BLOCKED frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_STREAMS_BLOCKED_H
#define _LIBGQUIC_FRAME_STREAMS_BLOCKED_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_streams_blocked_s gquic_frame_streams_blocked_t;
struct gquic_frame_streams_blocked_s {
    u_int64_t limit;
};

/**
 * 生成STREAMS_BLOCKED frame
 * 
 * @return frame_storage: STREAM_BLOCKED frame
 * @return: exception
 */
gquic_exception_t gquic_frame_streams_blocked_alloc(gquic_frame_streams_blocked_t **const frame_storage);

#endif
