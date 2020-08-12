/* include/stream/inbidi_stream_map.h 用于输出操作的单向数据流管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAMS_OUTUNI_STREAM_MAP_H
#define _LIBGQUIC_STREAMS_OUTUNI_STREAM_MAP_H

#include "streams/stream.h"
#include "util/rbtree.h"
#include "coglobal.h"
#include <pthread.h>

/**
 * 用于输出的双向数据流管理模块
 */
typedef struct gquic_outuni_stream_map_s gquic_outuni_stream_map_t;
struct gquic_outuni_stream_map_s {
    pthread_mutex_t mtx;

    // <stream id, stream> 字典
    gquic_rbtree_t *streams; /* u_int64_t: gquic_stream_t */
    // 打开输出双向数据流队列
    gquic_rbtree_t *open_queue; /* u_int64_t: liteco_channel_t * */

    // 在队列中最小的 stream id
    u_int64_t lowest_in_queue;
    // 在队列中最大的 stream id
    u_int64_t highest_in_queue;

    // 同时有效的最大数据流个数
    u_int64_t max_stream;

    // 下一个打开的数据流 stream id
    u_int64_t next_stream;

    // 发送队列是否处于堵塞状态
    bool block_sent;

    // 构造数据流回调函数
    struct {
        void *self;
        int (*cb) (gquic_stream_t *const, void *const, const u_int64_t);
    } stream_ctor;

    // 发送 STREAMS_BLOCKED frame 的回调函数
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_stream_id_blocked;

    bool closed;
    gquic_exception_t closed_reason;
};

#define GQUIC_OUTUNI_STREAM_MAP_STREAM_CTOR(stream, map, n) ((map)->stream_ctor.cb((stream), (map)->stream_ctor.self, n))
#define GQUIC_OUTUNI_STREAM_MAP_QUEUE_STREAM_ID_BLOCKED(frame, map) ((map)->queue_stream_id_blocked.cb((frame), (map)->queue_stream_id_blocked.self))

/**
 * 初始化数据流管理模块
 *
 * @param str_map: 数据流管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_init(gquic_outuni_stream_map_t *const str_map);

/**
 * 构造数据流管理模块
 *
 * @param str_map: 数据流管理模块
 * @param new_stream_self: 构造数据流回调函数self参数
 * @param new_stream_cb: 构造数据流回调函数
 * @param max_stream_count: 最大数据流限制
 * @param queue_stream_id_blocked_self: 发送STREAMS_BLOCKED frame回调函数self参数
 * @param queue_stream_id_blocked_cb: 发送STREAMS_BLOCKED frame回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_ctor(gquic_outuni_stream_map_t *const str_map,
                                               void *const stream_ctor_self,
                                               gquic_exception_t (*stream_ctor_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                               void *const queue_stream_id_blocked_self,
                                               gquic_exception_t (*queue_stream_id_blocked_cb) (void *const, void *const));

/**
 * 打开一个数据流
 *
 * @param str_map: 数据流管理模块
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_open_stream(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map);

/**
 * 打开一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param done_chan: 完成打开数据流后的通知通道
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_open_stream_sync(gquic_stream_t **const str,
                                                           gquic_outuni_stream_map_t *const str_map, liteco_channel_t *const done_chan);

/**
 * 获取一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param num: stream id
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_get_stream(gquic_stream_t **const str, gquic_outuni_stream_map_t *const str_map, const u_int64_t num);

/**
 * 释放一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param num: stream id
 *
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_release_stream(gquic_outuni_stream_map_t *const str_map, const u_int64_t num);

/**
 * 设置最大 stream id
 *
 * @param str_map: 数据流管理模块
 * @param num: stream id
 *
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_set_max_stream(gquic_outuni_stream_map_t *const str_map, const u_int64_t num);

/**
 * 关闭数据流管理模块
 *
 * @param str_map: 数据流管理模块
 * @param reason: 关闭数据流的原因
 *
 * @return: exception
 */
gquic_exception_t gquic_outuni_stream_map_close(gquic_outuni_stream_map_t *const str_map, const gquic_exception_t err);

#endif
