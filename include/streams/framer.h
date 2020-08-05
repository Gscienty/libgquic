/* include/stream/framer.h 数据帧发送队列
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAMS_FRAMER_H
#define _LIBGQUIC_STREAMS_FRAMER_H

#include "streams/stream_map.h"
#include "util/list.h"
#include "util/rbtree.h"
#include <pthread.h>

/**
 * 数据帧发送队列
 */
typedef struct gquic_framer_s gquic_framer_t;
struct gquic_framer_s {

    // 数据流管理模块
    gquic_stream_map_t *stream_getter;

    // 处于活动状态的数据流集合
    gquic_rbtree_t *active_streams_root; /* u_int64_t: u_int8_t */

    // STREAM frame队列
    pthread_mutex_t stream_mtx;
    gquic_list_t stream_queue; /* u_int64_t */

    // 控制frame队列
    pthread_mutex_t ctrl_mtx;
    gquic_list_t ctrl_frames; /* void * */

    // STREAM frame队列中的数据帧个数
    int stream_queue_count;
};

/**
 * 初始化数据帧发送队列
 *
 * @param framer: 数据帧发送队列
 *
 * @return: exception
 */
gquic_exception_t gquic_framer_init(gquic_framer_t *const framer);

/**
 * 构造数据帧发送队列
 *
 * @param framer: 数据帧发送队列
 * @param stream_getter: 数据流管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_framer_ctor(gquic_framer_t *const framer, gquic_stream_map_t *const stream_getter);

/**
 * 发送一个控制数据帧
 *
 * @param framer: 数据帧发送队列
 * @param frame: 控制数据帧
 *
 * @return: exception
 */
gquic_exception_t gquic_framer_queue_ctrl_frame(gquic_framer_t *const framer, void *const frame);

/**
 * 从数据帧发送队列中取出若干控制数据帧到frames队列中
 *
 * @param frames: 待填充的数据帧队列
 * @param length: 填充的数据帧所占据的长度
 * @param framer: 发送数据帧队列
 * @param max_len: 最大数据帧容量
 *
 * @return: exception
 */
gquic_exception_t gquic_framer_append_ctrl_frame(gquic_list_t *const frames, u_int64_t *const length, gquic_framer_t *const framer, const u_int64_t max_len);

/**
 * 添加一个活动的数据流
 *
 * @param framer: 发送数据帧
 * @param id: 数据流id
 *
 * @return: exception
 */
gquic_exception_t gquic_framer_add_active_stream(gquic_framer_t *const framer, const u_int64_t id);

/**
 * 从数据帧发送队列中取出若干数据流数据帧到frames队列中
 *
 * @param frames: 待填充的数据帧队列
 * @param length: 填充的数据帧所占据的长度
 * @param framer: 发送数据帧队列
 * @param max_len: 最大数据帧容量
 *
 * @return: exception
 */
gquic_exception_t gquic_framer_append_stream_frames(gquic_list_t *const frames, u_int64_t *const length, gquic_framer_t *const framer, const u_int64_t max_len);

#endif
