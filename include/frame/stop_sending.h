/* include/frame/stop_sending.h STOP_SENDING frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_STOP_SENDING_H
#define _LIBGQUIC_FRAME_STOP_SENDING_H

#include "util/varint.h"
#include "streams/type.h"
#include "exception.h"

typedef struct gquic_frame_stop_sending_s gquic_frame_stop_sending_t;
struct gquic_frame_stop_sending_s {
    u_int64_t id;
    u_int64_t errcode;
};

/**
 * 生成STOP_SENDING frame
 * 
 * @return frame_storage: STOP_SENDING frame
 * @return: exception
 */
gquic_exception_t gquic_frame_stop_sending_alloc(gquic_frame_stop_sending_t **const frame_storage);

#endif
