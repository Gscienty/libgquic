/* include/frame/path_response.h PATH_RESPONSE frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_PATH_RESPONSE_H
#define _LIBGQUIC_FRAME_PATH_RESPONSE_H

#include "exception.h"
#include <sys/types.h>

typedef struct gquic_frame_path_response_s gquic_frame_path_response_t;
struct gquic_frame_path_response_s {
    u_int8_t data[8];
};

/**
 * 生成PATH_RESPONSE frame
 * 
 * @return frame_storage: PATH_RESPONSE frame
 * @return: exception
 */
gquic_exception_t gquic_frame_path_response_alloc(gquic_frame_path_response_t **const frame_storage);

#endif
