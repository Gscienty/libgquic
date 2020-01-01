#include "flowcontrol/stream_flow_ctrl.h"

static inline int gquic_flowcontrol_stream_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const);

int gquic_flowcontrol_stream_flow_ctrl_init(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        return -1;
    }
    gquic_flowcontrol_base_init(&ctrl->base);
    ctrl->stream_id = 0;
    ctrl->queue_wnd_update.cb = NULL;
    ctrl->queue_wnd_update.self = NULL;
    ctrl->conn_flow_ctrl = NULL;
    ctrl->recv_final_off = 0;

    return 0;
}
int gquic_flowcontrol_stream_flow_ctrl_ctor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                            const u_int64_t stream_id,
                                            gquic_flowcontrol_conn_flow_ctrl_t *conn_flow_ctrl,
                                            const u_int64_t rwnd,
                                            const u_int64_t max_rwnd,
                                            const u_int64_t initial_swnd,
                                            void *const queue_wnd_update_self,
                                            int (*queue_wnd_update_cb) (void *const, const u_int64_t),
                                            gquic_rtt_t *const rtt) {
    if (ctrl == NULL) {
        return -1;
    }
    ctrl->stream_id = stream_id;
    ctrl->conn_flow_ctrl = conn_flow_ctrl;
    ctrl->queue_wnd_update.cb = queue_wnd_update_cb;
    ctrl->queue_wnd_update.self = queue_wnd_update_self;
    ctrl->base.rtt = rtt;
    ctrl->base.rwnd = rwnd;
    ctrl->base.rwnd_size = rwnd;
    ctrl->base.max_rwnd_size = max_rwnd;
    ctrl->base.swnd = initial_swnd;
    return 0;
}

int gquic_flowcontrol_stream_flow_ctrl_dtor(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    if (ctrl == NULL) {
        return -1;
    }
    gquic_flowcontrol_base_dtor(&ctrl->base);
    return 0;
}

int gquic_flowcontrol_stream_flow_ctrl_update_highest_recv(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                           const u_int64_t off,
                                                           int final) {
    int ret = 0;
    u_int64_t increment = 0;
    if (ctrl == NULL) {
        return -1;
    }
    sem_wait(&ctrl->base.mtx);
    if (ctrl->recv_final_off) {
        if (final && off != ctrl->base.highest_recv) {
            ret = -2;
            goto failure;
        }
        if (off > ctrl->base.highest_recv) {
            ret = -3;
            goto failure;
        }
    }
    if (final) {
        ctrl->recv_final_off = 1;
    }
    if (off == ctrl->base.highest_recv) {
        goto finished;
    }
    if (off <= ctrl->base.highest_recv) {
        if (final) {
            ret = -4;
            goto failure;
        }
        goto finished;
    }
    increment = off - ctrl->base.highest_recv;
    ctrl->base.highest_recv = off;
    if (ctrl->base.highest_recv > ctrl->base.rwnd) {
        ret = -5;
        goto failure;
    }
    if (gquic_flowcontrol_conn_flow_ctrl_increment_highest_recv(ctrl->conn_flow_ctrl, increment) != 0) {
        ret = -6;
        goto failure;
    }
finished:
    sem_post(&ctrl->base.mtx);
    return 0;
failure:
    sem_post(&ctrl->base.mtx);
    return ret;
}

int gquic_flowcontrol_stream_flow_ctrl_read_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                      const u_int64_t n) {
    if (ctrl == NULL) {
        return -1;
    }
    gquic_flowcontrol_base_read_add_bytes(&ctrl->base, n);
    gquic_flowcontrol_stream_flow_ctrl_try_queue_wnd_update(ctrl);
    gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(ctrl->conn_flow_ctrl, n);
    return 0;
}

static inline int gquic_flowcontrol_stream_flow_ctrl_try_queue_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    int has_wnd_update = 0;
    if (ctrl == NULL) {
        return -1;
    }
    sem_wait(&ctrl->base.mtx);
    has_wnd_update = !ctrl->recv_final_off && gquic_flowcontrol_base_has_wnd_update(&ctrl->base);
    sem_post(&ctrl->base.mtx);
    if (has_wnd_update) {
        GQUIC_FLOWCONTROL_STREAM_FLOW_CTRL_QUEUE_WND_UPDATE(ctrl);
    }

    return 0;
}

int gquic_flowcontrol_stream_flow_ctrl_abandon(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    u_int64_t unread = 0;
    if (ctrl == NULL) {
        return -1;
    }
    unread = ctrl->base.highest_recv - ctrl->base.read_bytes;
    if (unread > 0) {
        gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(ctrl->conn_flow_ctrl, unread);
    }
    return 0;
}

int gquic_flowcontrol_stream_flow_ctrl_sent_add_bytes(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl,
                                                      const u_int64_t n) {
    if (ctrl == NULL) {
        return -1;
    }
    gquic_flowcontrol_base_read_add_bytes(&ctrl->base, n);
    gquic_flowcontrol_conn_flow_ctrl_read_add_bytes(ctrl->conn_flow_ctrl, n);
    return 0;
}

u_int64_t gquic_flowcontrol_stream_flow_ctrl_swnd_size(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    u_int64_t self_swnd_size = 0;
    u_int64_t conn_swnd_size = 0;
    if (ctrl == NULL) {
        return 0;
    }
    self_swnd_size = gquic_flowcontrol_base_swnd_size(&ctrl->base);
    conn_swnd_size = gquic_flowcontrol_conn_flow_ctrl_swnd_size(ctrl->conn_flow_ctrl);
    return self_swnd_size < conn_swnd_size ? self_swnd_size : conn_swnd_size;
}

u_int64_t gquic_flowcontrol_stream_flow_ctrl_get_wnd_update(gquic_flowcontrol_stream_flow_ctrl_t *const ctrl) {
    u_int64_t old_wnd_size = 0;
    u_int64_t off = 0;
    if (ctrl == NULL) {
        return 0;
    }
    sem_wait(&ctrl->base.mtx);
    if (ctrl->recv_final_off) {
        sem_post(&ctrl->base.mtx);
        return 0;
    }
    old_wnd_size = ctrl->base.rwnd_size;
    off = gquic_flowcontrol_base_get_wnd_update(&ctrl->base);
    if (ctrl->base.rwnd_size > old_wnd_size) {
        gquic_flowcontrol_conn_flow_ctrl_ensure_min_wnd_size(ctrl->conn_flow_ctrl, ctrl->base.rwnd_size * 1.5);
    }
    sem_post(&ctrl->base.mtx);
    return off;
}
