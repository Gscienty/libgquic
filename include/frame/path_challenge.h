/* include/frame/path_challenge.h PATH_CHALLENGE frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_PATH_CHALLENGE_H
#define _LIBGQUIC_FRAME_PATH_CHALLENGE_H

#include "exception.h"
#include <sys/types.h>

typedef struct gquic_frame_path_challenge_s gquic_frame_path_challenge_t;
struct gquic_frame_path_challenge_s {
    u_int8_t data[8];
};

/**
 * 生成PATH_CHALLENGE frame
 * 
 * @return frame_storage: PATH_CHALLENGE frame
 * @return: exception
 */
gquic_exception_t gquic_frame_path_challenge_alloc(gquic_frame_path_challenge_t **const frame_storage);

#endif
