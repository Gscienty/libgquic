/* include/frame/max_streams.h MAX_STREAMS frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_MAX_STREAMS_H
#define _LIBGQUIC_FRAME_MAX_STREAMS_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_max_streams_s gquic_frame_max_streams_t;
struct gquic_frame_max_streams_s {
    u_int64_t max;
};

/**
 * 生成MAX_STREAMS frame
 * 
 * @return frame_storage: MAX_STREAMS frame
 * @return: exception
 */
gquic_exception_t gquic_frame_max_streams_alloc(gquic_frame_max_streams_t **const frame_storage);

#endif
