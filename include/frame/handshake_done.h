/* include/frame/handshake_done.h HANDSHAKE_DONE frame 定义
 * 该frame用于Server向Client通知握手阶段完毕，告知Client可以摒弃Handshake 密钥
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_HANDSAHKE_DONE_H
#define _LIBGQUIC_FRAME_HANDSAHKE_DONE_H

#include "exception.h"

typedef struct gquic_frame_handshake_done_s gquic_frame_handshake_done_t;
struct gquic_frame_handshake_done_s { };

/**
 * 生成HANDSHAKE_DONE frame
 * 
 * @return frame_storage: HANDSHAKE_DONE frame
 * @return: exception
 */
gquic_exception_t gquic_frame_handshake_done_alloc(gquic_frame_handshake_done_t **const frame_storage);

#endif
