/* include/flowcontrol/wnd_update_queue.h 接收窗口更新通知队列声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#ifndef _LIBGQUIC_FLOWCONTROL_WND_UPDATE_QUEUE_H
#define _LIBGQUIC_FLOWCONTROL_WND_UPDATE_QUEUE_H

#include "util/rbtree.h"
#include "streams/stream_map.h"
#include "flowcontrol/conn_flow_ctrl.h"
#include <pthread.h>
#include <stdbool.h>

/**
 * 接收窗口更新通知队列
 */
typedef struct gquic_wnd_update_queue_s gquic_wnd_update_queue_t;
struct gquic_wnd_update_queue_s {

    pthread_mutex_t mtx;

    // stream 集合
    gquic_rbtree_t *queue; /* u_int64_t: u_int8_t(useless) */

    // 接收窗口更新是否关联连接标记
    bool queue_conn;

    // stream 管理器
    gquic_stream_map_t *stream_getter;

    // 连接流量控制模块
    gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl;

    // 接收窗口变更回调函数(发送控制frame)
    // param: frame
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } cb; 
};

#define GQUIC_WND_UPDATE_QUEUE_CB(queue, frame) \
    ((queue)->cb.cb((queue)->cb.self, (frame)))

/**
 * 接收窗口更新通知队列初始化
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_wnd_update_queue_init(gquic_wnd_update_queue_t *const queue);

/**
 * 构造接收窗口更新通知队列
 *
 * @param queue: queue
 * @param stream_getter: stream 集合
 * @param conn_flow_ctrl: 连接流量控制模块
 * @param cb_self: 接收窗口变更回调函数self参数
 * @param cb_cb: 接收窗口变更回调函数
 *
 * @return: exception
 */
gquic_exception_t gquic_wnd_update_queue_ctor(gquic_wnd_update_queue_t *const queue,
                                              gquic_stream_map_t *const stream_getter,
                                              gquic_flowcontrol_conn_flow_ctrl_t *const conn_flow_ctrl,
                                              void *const cb_self,
                                              int (*cb_cb) (void *const, void *const));

/**
 * 析构通知队列
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_wnd_update_queue_dtor(gquic_wnd_update_queue_t *const queue);

/**
 * 向通知队列中添加一个新的stream
 *
 * @param queue: queue
 * @param stream_id: stream id
 * 
 * @return: exception
 */
gquic_exception_t gquic_wnd_update_queue_add_stream(gquic_wnd_update_queue_t *const queue, const u_int64_t stream_id);

/**
 * 告知通知队列，将接收窗口更新通知到连接流量控制模块
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_wnd_update_queue_add_conn(gquic_wnd_update_queue_t *const queue);

/**
 * 通知接收窗口变更
 *
 * @param queue: queue
 * 
 * @return: exception
 */
gquic_exception_t gquic_wnd_update_queue_queue_all(gquic_wnd_update_queue_t *const queue);

#endif
