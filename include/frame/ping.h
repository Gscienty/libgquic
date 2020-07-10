/* include/frame/ping.h PING frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_PING_H
#define _LIBGQUIC_FRAME_PING_H

#include "exception.h"

typedef struct gquic_frame_ping_s gquic_frame_ping_t;
struct gquic_frame_ping_s { };

/**
 * 生成PING frame
 * 
 * @return frame_storage: PING frame
 * @return: exception
 */
gquic_exception_t gquic_frame_ping_alloc(gquic_frame_ping_t **const frame_storage);

#endif
