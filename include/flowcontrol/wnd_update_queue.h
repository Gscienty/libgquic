#ifndef _LIBGQUIC_FLOWCONTROL_WND_UPDATE_QUEUE_H
#define _LIBGQUIC_FLOWCONTROL_WND_UPDATE_QUEUE_H

#include <semaphore.h>
#include "util/rbtree.h"
#include "streams/stream_map.h"
#include "flowcontrol/conn_flow_ctrl.h"

typedef struct gquic_wnd_update_queue_s gquic_wnd_update_queue_t;
struct gquic_wnd_update_queue_s {
    sem_t mtx;

    gquic_rbtree_t *queue; /* u_int64_t: u_int8_t(useless) */
    int queue_conn;

    gquic_stream_map_t *stream_getter;
    gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl;
    struct {
        void *self;
        int (*cb) (void *const, void *const);
    } cb; 
};

#define GQUIC_WND_UPDATE_QUEUE_CB(queue, frame) \
    ((queue)->cb.cb((queue)->cb.self, (frame)))

int gquic_wnd_update_queue_init(gquic_wnd_update_queue_t *const queue);
int gquic_wnd_update_queue_ctor(gquic_wnd_update_queue_t *const queue,
                                gquic_stream_map_t *const stream_getter,
                                gquic_flowcontrol_conn_flow_ctrl_t *const conn_flow_ctrl,
                                void *const cb_self,
                                int (*cb_cb) (void *const, void *const));
int gquic_wnd_update_queue_add_stream(gquic_wnd_update_queue_t *const queue, const u_int64_t stream_id);
int gquic_wnd_update_queue_add_conn(gquic_wnd_update_queue_t *const queue);
int gquic_wnd_update_queue_queue_all(gquic_wnd_update_queue_t *const queue);

#endif
