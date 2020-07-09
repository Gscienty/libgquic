/* src/flowcontrol/wnd_update_queue.c 接收窗口更新通知队列声明
 *
 * Copyright (c) 2019-2020 Gscienty <gaoxiaochuan@hotmail.com>
 *
 * Distributed under the MIT software license, see the accompanying
 * file LICENSE or https://www.opensource.org/licenses/mit-license.php .
 */

#include "flowcontrol/wnd_update_queue.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "frame/max_stream_data.h"
#include "frame/max_data.h"
#include "exception.h"

gquic_exception_t gquic_wnd_update_queue_init(gquic_wnd_update_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_init(&queue->mtx, NULL);
    gquic_rbtree_root_init(&queue->queue);
    queue->queue_conn = 0;
    queue->stream_getter = NULL;
    queue->conn_flow_ctrl = NULL;
    queue->cb.cb = NULL;
    queue->cb.self = NULL;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_wnd_update_queue_ctor(gquic_wnd_update_queue_t *const queue,
                                              gquic_stream_map_t *const stream_getter,
                                              gquic_flowcontrol_conn_flow_ctrl_t *const conn_flow_ctrl,
                                              void *const cb_self,
                                              int (*cb_cb) (void *const, void *const)) {
    if (queue == NULL || stream_getter == NULL || conn_flow_ctrl == NULL || cb_self == NULL || cb_cb == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    queue->stream_getter = stream_getter;
    queue->conn_flow_ctrl = conn_flow_ctrl;
    queue->cb.cb = cb_cb;
    queue->cb.self = cb_self;

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_wnd_update_queue_dtor(gquic_wnd_update_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_destroy(&queue->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_wnd_update_queue_add_stream(gquic_wnd_update_queue_t *const queue, const u_int64_t stream_id) {
    gquic_rbtree_t *rbt = NULL;
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(u_int64_t), sizeof(u_int8_t)))) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_ALLOCATION_FAILED);
    }
    pthread_mutex_lock(&queue->mtx);
    *(u_int64_t *) GQUIC_RBTREE_KEY(rbt) = stream_id;
    gquic_rbtree_insert(&queue->queue, rbt);
    pthread_mutex_unlock(&queue->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_wnd_update_queue_add_conn(gquic_wnd_update_queue_t *const queue) {
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    pthread_mutex_lock(&queue->mtx);
    queue->queue_conn = 1;
    pthread_mutex_unlock(&queue->mtx);

    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
}

gquic_exception_t gquic_wnd_update_queue_queue_all(gquic_wnd_update_queue_t *const queue) {
    int exception = 0;
    gquic_frame_max_data_t *max_data_frame = NULL;
    gquic_frame_max_stream_data_t *max_stream_data_frame = NULL;
    gquic_rbtree_t *rbt = NULL;
    gquic_stream_t *str = NULL;
    gquic_list_t del;
    u_int64_t *id = NULL;
    u_int64_t offset = 0;
    if (queue == NULL) {
        GQUIC_PROCESS_DONE(GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED);
    }
    gquic_list_head_init(&del);

    pthread_mutex_lock(&queue->mtx);
    if (queue->queue_conn) {
        if (GQUIC_ASSERT_CAUSE(exception, gquic_frame_max_data_alloc(&max_data_frame))) {
            goto failure;
        }
        max_data_frame->max = gquic_flowcontrol_conn_flow_ctrl_get_wnd_update(queue->conn_flow_ctrl);
        GQUIC_WND_UPDATE_QUEUE_CB(queue, max_data_frame);
        queue->queue_conn = 0;
    }
    GQUIC_RBTREE_EACHOR_BEGIN(rbt, queue->queue)
        if (GQUIC_ASSERT_CAUSE(exception,
                               gquic_stream_map_get_or_open_recv_stream(&str, queue->stream_getter, *(u_int64_t *) GQUIC_RBTREE_KEY(rbt)))
            || str == NULL) {
            continue;
        }
        if ((offset = gquic_flowcontrol_stream_flow_ctrl_get_wnd_update(str->recv.flow_ctrl)) == 0) {
            continue;
        }
        if (GQUIC_ASSERT_CAUSE(exception, gquic_frame_max_stream_data_alloc(&max_stream_data_frame))) {
            goto failure;
        }
        max_stream_data_frame->id = *(u_int64_t *) GQUIC_RBTREE_KEY(rbt);
        max_stream_data_frame->max = offset;
        GQUIC_WND_UPDATE_QUEUE_CB(queue, max_stream_data_frame);
        if (GQUIC_ASSERT_CAUSE(exception, gquic_list_alloc((void **) &id, sizeof(u_int64_t)))) {
            goto failure;
        }
        *id = *(u_int64_t *) GQUIC_RBTREE_KEY(rbt);
        gquic_list_insert_before(&del, id);
    GQUIC_RBTREE_EACHOR_END(rbt)
    
    while (!gquic_list_head_empty(&del)) {
        if (gquic_rbtree_find((const gquic_rbtree_t **) &rbt, queue->queue, GQUIC_LIST_FIRST(&del), sizeof(u_int64_t)) == 0) {
            gquic_rbtree_remove(&queue->queue, &rbt);
            gquic_rbtree_release(rbt, NULL);
        }
        gquic_list_release(GQUIC_LIST_FIRST(&del));
    }

    pthread_mutex_unlock(&queue->mtx);
    GQUIC_PROCESS_DONE(GQUIC_SUCCESS);
failure:
    pthread_mutex_unlock(&queue->mtx);
    while (!gquic_list_head_empty(&del)) {
        gquic_list_release(GQUIC_LIST_FIRST(&del));
    }
    GQUIC_PROCESS_DONE(exception);
}
