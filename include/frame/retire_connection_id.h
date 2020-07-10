/* include/frame/retire_connection_id.h RETIRE_CONNECTION_ID frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_RETIRE_CONNECTION_ID_H
#define _LIBGQUIC_FRAME_RETIRE_CONNECTION_ID_H

#include "util/varint.h"
#include "exception.h"

typedef struct gquic_frame_retire_connection_id_s gquic_frame_retire_connection_id_t;
struct gquic_frame_retire_connection_id_s {
    u_int64_t seq;
};

/**
 * 生成RETIRE_CONNECTION_ID frame
 * 
 * @return frame_storage: RETIRE_CONNECTION_ID frame
 * @return: exception
 */
gquic_exception_t gquic_frame_retire_connection_id_alloc(gquic_frame_retire_connection_id_t **const frame_storage);

#endif
