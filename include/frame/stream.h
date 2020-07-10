/* include/frame/stream.h STREAM frame 定义
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FRAME_STREAM_H
#define _LIBGQUIC_FRAME_STREAM_H

#include "frame/meta.h"
#include "streams/type.h"
#include "util/str.h"
#include "exception.h"
#include <stdbool.h>

typedef struct gquic_frame_stream_s gquic_frame_stream_t;
struct gquic_frame_stream_s {
    u_int64_t id;
    u_int64_t off;
    gquic_str_t data;
};

/**
 * 生成STREAM frame
 * 
 * @return frame_storage: STREAM frame
 * @return: exception
 */
gquic_exception_t gquic_frame_stream_alloc(gquic_frame_stream_t **const frame_storage);

/**
 * 获取STREAM frame数据容量
 *
 * @param size: 携带frame头部的总数据大小
 * @param frame: STREAM frame
 * 
 * @return: 数据容量
 */
u_int64_t gquic_frame_stream_data_capacity(const u_int64_t size, const gquic_frame_stream_t *const frame);

/**
 * 切割STREAM frame
 * 
 * @param frame: 原始frame
 * @param size: 切割的数据大小
 *
 * @return new_frame: 新切割出的STREAM frame
 * @return: 是否切割
 */
bool gquic_frame_stream_split(gquic_frame_stream_t **new_frame, gquic_frame_stream_t *const frame, const u_int64_t size);

/**
 * 设置STREAM frame FIN字段
 *
 * @param frame: STREAM frame
 * 
 * @return: exception
 */
static inline gquic_exception_t gquic_frame_stream_set_fin(gquic_frame_stream_t *const frame) {
    if (frame == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    GQUIC_FRAME_META(frame).type |= 0x01;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

/**
 * 获取STREAM frame FIN字段
 *
 * @param frame: STREAM frame
 * 
 * @return: FIN字段是否置1
 */
static inline bool gquic_frame_stream_get_fin(gquic_frame_stream_t *const frame) {
    if (frame == NULL) {
        return true;
    }

    return (GQUIC_FRAME_META(frame).type & 0x01) != 0x00;
}

#endif
