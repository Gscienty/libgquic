/* include/frame/data_blocked.h DATA_BLOCKED frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_DATA_BLOCKED_H
#define _LIBGQUIC_FRAME_DATA_BLOCKED_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_data_blocked_s gquic_frame_data_blocked_t;
struct gquic_frame_data_blocked_s {
    u_int64_t limit;
};

/**
 * 生成DATA_BLOCKED frame
 * 
 * @return frame_storage: DATA_BLOCKED frame
 * @return: exception
 */
gquic_exception_t gquic_frame_data_blocked_alloc(gquic_frame_data_blocked_t **const frame_storage);

#endif
