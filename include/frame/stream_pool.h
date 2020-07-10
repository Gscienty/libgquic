/* include/frame/stream_pool.h STREAM frame池定义
 * 由于stream会频繁的申请和释放，因此设置STREAM frame池可优化性能
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_STREAM_POOL_H
#define _LIBGQUIC_FRAME_STREAM_POOL_H

#include "frame/stream.h"
#include "exception.h"

/**
 * 初始化STREAM frame池
 *
 * @return: exception
 */
gquic_exception_t gquic_stream_frame_pool_init();

/**
 * 向池中返还STREAM frame
 * 
 * @param stream: 返还的STREAM frame
 * 
 * @return: exception
 */
gquic_exception_t gquic_stream_frame_pool_put(gquic_frame_stream_t *const stream);

/**
 * 从池中获取STREAM frame
 * 
 * @return stream: 取出的STREAM frame
 * @return: exception
 */
gquic_exception_t gquic_stream_frame_pool_get(gquic_frame_stream_t **const stream);

#endif
