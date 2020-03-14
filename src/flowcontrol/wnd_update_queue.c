#include "flowcontrol/wnd_update_queue.h"
#include "flowcontrol/stream_flow_ctrl.h"
#include "frame/max_stream_data.h"
#include "frame/max_data.h"
#include "exception.h"

int gquic_wnd_update_queue_init(gquic_wnd_update_queue_t *const queue) {
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_init(&queue->mtx, 0, 1);
    gquic_rbtree_root_init(&queue->queue);
    queue->queue_conn = 0;
    queue->stream_getter = NULL;
    queue->conn_flow_ctrl = NULL;
    queue->cb.cb = NULL;
    queue->cb.self = NULL;

    return GQUIC_SUCCESS;
}

int gquic_wnd_update_queue_ctor(gquic_wnd_update_queue_t *const queue,
                                gquic_stream_map_t *const stream_getter,
                                gquic_flowcontrol_conn_flow_ctrl_t *const conn_flow_ctrl,
                                void *const cb_self,
                                int (*cb_cb) (void *const, void *const)) {
    if (queue == NULL || stream_getter == NULL || conn_flow_ctrl == NULL || cb_self == NULL || cb_cb == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    queue->stream_getter = stream_getter;
    queue->conn_flow_ctrl = conn_flow_ctrl;
    queue->cb.cb = cb_cb;
    queue->cb.self = cb_self;

    return GQUIC_SUCCESS;
}

int gquic_wnd_update_queue_add_stream(gquic_wnd_update_queue_t *const queue, const u_int64_t stream_id) {
    gquic_rbtree_t *rbt = NULL;
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    if (GQUIC_ASSERT(gquic_rbtree_alloc(&rbt, sizeof(u_int64_t), sizeof(u_int8_t)))) {
        return GQUIC_EXCEPTION_ALLOCATION_FAILED;
    }
    sem_wait(&queue->mtx);
    *(u_int64_t *) GQUIC_RBTREE_KEY(rbt) = stream_id;
    gquic_rbtree_insert(&queue->queue, rbt);
    sem_post(&queue->mtx);

    return GQUIC_SUCCESS;
}

int gquic_wnd_update_queue_add_conn(gquic_wnd_update_queue_t *const queue) {
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    sem_wait(&queue->mtx);
    queue->queue_conn = 1;
    sem_post(&queue->mtx);

    return GQUIC_SUCCESS;
}

int gquic_wnd_update_queue_queue_all(gquic_wnd_update_queue_t *const queue) {
    int exception = 0;
    gquic_frame_max_data_t *max_data_frame = NULL;
    gquic_frame_max_stream_data_t *max_stream_data_frame = NULL;
    gquic_rbtree_t *rbt = NULL;
    gquic_stream_t *str = NULL;
    gquic_list_t del;
    u_int64_t *id = NULL;
    u_int64_t offset = 0;
    if (queue == NULL) {
        return GQUIC_EXCEPTION_PARAMETER_UNEXCEPTED;
    }
    gquic_list_head_init(&del);
    sem_wait(&queue->mtx);
    if (queue->queue_conn) {
        if ((max_data_frame = gquic_frame_max_data_alloc()) == NULL) {
            exception = GQUIC_EXCEPTION_ALLOCATION_FAILED;
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
        if ((max_stream_data_frame = gquic_frame_max_stream_data_alloc()) == NULL) {
            exception = GQUIC_EXCEPTION_ALLOCATION_FAILED;
            goto failure;
        }
        max_stream_data_frame->id = *(u_int64_t *) GQUIC_RBTREE_KEY(rbt);
        max_stream_data_frame->max = offset;
        GQUIC_WND_UPDATE_QUEUE_CB(queue, max_stream_data_frame);
        if ((id = gquic_list_alloc(sizeof(u_int64_t))) == NULL) {
            exception = GQUIC_EXCEPTION_ALLOCATION_FAILED;
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

    sem_post(&queue->mtx);
    return GQUIC_SUCCESS;
failure:
    sem_post(&queue->mtx);

    while (!gquic_list_head_empty(&del)) {
        gquic_list_release(GQUIC_LIST_FIRST(&del));
    }
    return exception;
}
