/* include/stream/inbidi_stream_map.h 用于读操作的双向数据流管理模块
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_STREAMS_INBIDI_STREAM_MAP_H
#define _LIBGQUIC_STREAMS_INBIDI_STREAM_MAP_H

#include "streams/stream.h"
#include "util/rbtree.h"
#include "coglobal.h"
#include <pthread.h>

/**
 * 用于读取的双向数据流管理模块
 */
typedef struct gquic_inbidi_stream_map_s gquic_inbidi_stream_map_t;
struct gquic_inbidi_stream_map_s {
    pthread_mutex_t mtx;

    // 接收一个新数据流信号通道
    liteco_channel_t new_stream_chan;

    // <stream id, stream> 字典
    gquic_rbtree_t *streams; /* u_int64_t: gquic_stream_t * */
    // 字典内元素个数
    u_int64_t streams_count;
    // 待删除的数据流
    gquic_rbtree_t *del_streams; /* u_int64_t; u_int8_t */
    
    // 下一个被接受的数据流 stream id
    u_int64_t next_stream_accept;

    // 下一个打开的数据流 stream id
    u_int64_t next_stream_open;

    // 同时有效的最大数据流个数
    u_int64_t max_stream;
    // 字典中存在的最大数据流个数
    u_int64_t max_stream_count;

    // 数据流构造回调函数
    struct {
        void *self;
        int (*cb) (gquic_stream_t *const, void *const, const u_int64_t);
    } stream_ctor;

    // 发送 MAX_STREAM_ID frame 的回调函数
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } queue_max_stream_id;

    bool closed;
    gquic_exception_t closed_reason;
};

#define GQUIC_INBIDI_STREAM_MAP_CTOR_STREAM(stream, map, n) ((map)->stream_ctor.cb(stream, (map)->stream_ctor.self, n))
#define GQUIC_INBIDI_STREAM_MAP_QUEUE_MAX_STREAM_ID(map, stream) ((map)->queue_max_stream_id.cb((map)->queue_max_stream_id.self, stream))

/**
 * 初始化数据流管理模块
 *
 * @param str_map: 数据流管理模块
 *
 * @return: exception
 */
gquic_exception_t gquic_inbidi_stream_map_init(gquic_inbidi_stream_map_t *const str_map);

/**
 * 构造数据流管理模块
 *
 * @param str_map: 数据流管理模块
 * @param new_stream_self: 构造数据流回调函数self参数
 * @param new_stream_cb: 构造数据流回调函数
 * @param max_stream_count: 最大数据流限制
 * @param queue_max_stream_id_self: 发送MAX_STREAM_ID frame回调函数self参数
 * @param queue_max_stream_id_cb: 发送MAX_STREAM_ID frame回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_inbidi_stream_map_ctor(gquic_inbidi_stream_map_t *const str_map,
                                               void *const new_stream_self,
                                               gquic_exception_t (*new_stream_cb) (gquic_stream_t *const, void *const, const u_int64_t),
                                               u_int64_t max_stream_count,
                                               void *const queue_max_stream_id_self,
                                               gquic_exception_t (*queue_max_stream_id_cb) (void *const, void *const));

/**
 * 接受一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param done_chan: done信号通道
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_inbidi_stream_map_accept_stream(gquic_stream_t **const str,
                                                        gquic_inbidi_stream_map_t *const str_map, liteco_channel_t *const done_chan);

/**
 * 获取或打开一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param done_chan: done信号通道
 *
 * @return str: 数据流
 * @return: exception
 */
gquic_exception_t gquic_inbidi_stream_map_get_or_open_stream(gquic_stream_t **const str,
                                                             gquic_inbidi_stream_map_t *const str_map, const u_int64_t pn);

/**
 * 释放一个数据流
 *
 * @param str_map: 数据流管理模块
 * @param num: stream id
 *
 * @return: exception
 */
gquic_exception_t gquic_inbidi_stream_map_release_stream(gquic_inbidi_stream_map_t *const str_map, const u_int64_t num);

/**
 * 关闭数据流管理模块
 *
 * @param str_map: 数据流管理模块
 * @param reason: 关闭数据流的原因
 *
 * @return: exception
 *
 */
gquic_exception_t gquic_inbidi_stream_map_close(gquic_inbidi_stream_map_t *const str_map, const int reason);

#endif
